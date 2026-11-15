import { randomUUID } from 'node:crypto';
import { constants } from 'node:fs';
import { access, chmod, mkdir, rm } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { AppPaths } from '../config.js';
import { MASTER_START_TIMEOUT_MS } from '../config.js';
import { McpOpsError, errorMessage } from '../errors.js';
import { LocalPathPolicy } from '../local-path-policy.js';
import { promptSecret } from '../password-prompt.js';
import type { ProcessResult } from '../process-runner.js';
import { runProcess } from '../process-runner.js';
import type { ProfileStore } from '../profile-store.js';
import type { ExecRequest, ExecResult, SessionMetadata, SshProfile } from '../types.js';
import { AskpassBroker } from './askpass-broker.js';
import { OpenSshFileOperations } from './openssh-file-operations.js';
import { buildRemoteCommand } from './shell.js';
import { Ssh2ConnectionFactory } from './ssh2-connection.js';
import type { Ssh2Transport } from './ssh2-transport.js';

interface SessionRecord {
  id: string;
  name: string;
  profile: SshProfile;
  target: string;
  controlPath: string;
  credentialGroup: string;
  status: 'connected' | 'disconnected' | 'closing';
  connectedAt: string;
  lastError?: string;
  activeOperations: number;
  masterPid?: number;
  transport?: Ssh2Transport;
}

export class SessionManager {
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly broker: AskpassBroker;
  private readonly localPathPolicy: LocalPathPolicy;
  private readonly processRuntimeDir: string;
  private readonly brokerAllPrompts: boolean;
  private readyPromise?: Promise<void>;
  private askpassClientPath?: string;
  private heartbeat?: NodeJS.Timeout;
  private readonly ssh2: Ssh2ConnectionFactory;

  constructor(
    private readonly paths: AppPaths,
    private readonly profiles: ProfileStore,
    secretPrompt: typeof promptSecret = promptSecret,
    private readonly backend: 'openssh' | 'ssh2' = process.platform === 'win32' ? 'ssh2' : 'openssh',
  ) {
    this.processRuntimeDir = join(paths.runtimeDir, `agent-${process.pid}-${randomUUID().slice(0, 8)}`);
    this.localPathPolicy = new LocalPathPolicy(paths.localRoots);
    this.brokerAllPrompts = true;
    this.broker = new AskpassBroker(join(this.processRuntimeDir, 'askpass.sock'), secretPrompt);
    this.ssh2 = new Ssh2ConnectionFactory(paths, profiles, secretPrompt);
  }

  async createSession(profile: SshProfile, name?: string, inheritedCredentialGroup?: string, signal?: AbortSignal) {
    validateProfile(profile);
    await this.ensureReady();
    const token = randomUUID();
    const sessionName = name ?? profile.ssh_alias ?? `${profile.username}@${profile.host}`;
    const id = formatPublicSessionId(sessionName, profile, token);
    const target = profile.ssh_alias ?? profile.host;
    const controlPath = join(this.processRuntimeDir, `cm-${token.slice(0, 12)}`);
    const credentialGroup = inheritedCredentialGroup ?? `user:${profile.username}`;
    if (this.backend === 'ssh2') {
      const transport = await this.ssh2.connect(profile, connectionOptions(profile), signal);
      const record: SessionRecord = {
        id, name: sessionName, profile: { ...profile }, target, controlPath: '', credentialGroup,
        transport, status: 'connected', connectedAt: new Date().toISOString(), activeOperations: 0,
      };
      transport.client.once('close', () => {
        record.status = 'disconnected';
        record.lastError = 'SSH transport closed.';
      });
      this.sessions.set(id, record);
      return this.describe(record);
    }
    const sharedCredential = this.broker.hasCredentialReferences(credentialGroup);
    const releaseCredentialOnFailure = !inheritedCredentialGroup && !sharedCredential;
    const contextId = this.broker.createContext(credentialGroup, profile.host, profile.port);
    const args = this.masterArgs(profile, target, controlPath);
    let result: ProcessResult;
    try {
      result = await runProcess('ssh', args, {
        env: this.askpassEnvironment(contextId),
        signal,
        timeout_ms: MASTER_START_TIMEOUT_MS,
        max_output_bytes: 1_048_576,
      });
    } catch (error) {
      await rm(controlPath, { force: true });
      if (releaseCredentialOnFailure) this.broker.releaseCredential(credentialGroup);
      if (error instanceof Error && error.name === 'AbortError') throw new McpOpsError('REQUEST_CANCELLED', error.message);
      throw new McpOpsError('OPENSSH_START_FAILED', `Cannot start the system ssh client: ${errorMessage(error)}`);
    } finally {
      this.broker.releaseContext(contextId);
    }

    const pending = this.broker.takePendingForContext(contextId);
    const promptError = this.broker.takeErrorForContext(contextId);
    if (result.exit_code !== 0 || result.timed_out) {
      await rm(controlPath, { force: true });
      if (/Permission denied|Authentication failed/i.test(result.stderr.toString('utf8'))) {
        this.broker.invalidateCredential(credentialGroup);
      }
      if (releaseCredentialOnFailure) this.broker.releaseCredential(credentialGroup);
      if (pending) {
        throw new McpOpsError('HOST_KEY_UNKNOWN', `${pending.host}:${pending.port} is not trusted. Key type: ${pending.key_type}. Fingerprint: ${pending.fingerprint}. Show this fingerprint to the operator and call ssh_trust_host only after explicit confirmation.`);
      }
      if (promptError instanceof Error) throw promptError;
      throw connectionError(profile, result);
    }

    const check = await this.checkMaster(profile, target, controlPath);
    if (!check.connected) {
      await rm(controlPath, { force: true });
      if (releaseCredentialOnFailure) this.broker.releaseCredential(credentialGroup);
      throw new McpOpsError('CONTROL_MASTER_FAILED', `OpenSSH exited successfully but no ControlMaster is available: ${check.error ?? 'unknown error'}`);
    }

    this.broker.retainCredential(credentialGroup);
    const record: SessionRecord = {
      id,
      name: sessionName,
      profile: { ...profile },
      target,
      controlPath,
      credentialGroup,
      status: 'connected',
      connectedAt: new Date().toISOString(),
      activeOperations: 0,
      masterPid: check.pid,
    };
    this.sessions.set(id, record);
    this.ensureHeartbeat();
    return this.describe(record);
  }

  async cloneSession(sessionId: string, name?: string, signal?: AbortSignal) {
    const source = this.requireConnected(sessionId);
    return this.createSession(source.profile, name ?? `${source.name}-clone`, source.credentialGroup, signal);
  }

  listSessions() {
    return [...this.sessions.values()]
      .map((session) => this.describe(session))
      .sort((left, right) => left.connected_at.localeCompare(right.connected_at));
  }

  sessionInfo(sessionId: string) {
    return this.describe(this.requireSession(sessionId));
  }

  trustHost(host: string, port: number, fingerprint: string) {
    if (this.backend === 'ssh2') return this.ssh2.trustHost(host, port, fingerprint);
    return this.broker.trustPending(host, port, fingerprint);
  }

  async closeSession(sessionId: string) {
    const session = this.requireSession(sessionId);
    session.status = 'closing';
    if (session.transport) {
      session.transport.close();
      this.sessions.delete(sessionId);
      return { session: this.sessionMetadata(session), session_id: sessionId, closed: true, graceful: true };
    }
    const result = await runProcess('ssh', [
      '-F', this.paths.sshConfigFile,
      '-S', session.controlPath,
      '-O', 'exit',
      ...connectionOptions(session.profile),
      session.target,
    ], {
      timeout_ms: 5_000,
      max_output_bytes: 65_536,
    }).catch(() => undefined);
    await rm(session.controlPath, { force: true });
    const metadata = this.sessionMetadata(session);
    this.sessions.delete(sessionId);
    this.broker.releaseCredential(session.credentialGroup);
    return {
      session: metadata,
      session_id: sessionId,
      closed: true,
      graceful: result?.exit_code === 0,
    };
  }

  async closeAll(): Promise<void> {
    if (this.heartbeat) clearInterval(this.heartbeat);
    this.heartbeat = undefined;
    await Promise.all([...this.sessions.keys()].map((id) => this.closeSession(id).catch(() => undefined)));
    await this.broker.close();
    await rm(this.processRuntimeDir, { recursive: true, force: true });
  }

  async exec(sessionId: string, request: ExecRequest): Promise<ExecResult> {
    const session = this.requireConnected(sessionId);
    const command = buildRemoteCommand(request.command, request.cwd, request.env);
    return this.withOperation(session, async () => {
      const result = await this.execRaw(session, command, request.timeout_ms, request.max_output_bytes);
      return {
        session: this.sessionMetadata(session),
        exit_code: result.exit_code,
        signal: result.signal,
        stdout: result.stdout.toString('utf8'),
        stderr: result.stderr.toString('utf8'),
        timed_out: result.timed_out,
        output_truncated: result.output_truncated,
        duration_ms: result.duration_ms,
      };
    });
  }

  async stat(sessionId: string, path: string, followSymlinks: boolean) {
    return this.withFiles(sessionId, (files) => files.stat(path, followSymlinks));
  }

  async listDirectory(sessionId: string, path: string, maxEntries: number) {
    return this.withFiles(sessionId, (files) => files.listDirectory(path, maxEntries));
  }

  async readRemoteFile(
    sessionId: string,
    path: string,
    offset: number,
    length: number | undefined,
    maxBytes: number,
    encoding: 'utf8' | 'base64',
  ) {
    return this.withFiles(sessionId, (files) => files.readFile(path, offset, length, maxBytes, encoding));
  }

  async uploadFile(
    sessionId: string,
    localPath: string,
    remotePath: string,
    overwrite: boolean,
    preserveMode: boolean,
    expectedLocalSha256?: string,
    expectedDestinationSha256?: string,
  ) {
    return this.withFiles(sessionId, (files) => files.uploadFile(
      localPath,
      remotePath,
      overwrite,
      preserveMode,
      expectedLocalSha256,
      expectedDestinationSha256,
    ));
  }

  async downloadFile(
    sessionId: string,
    remotePath: string,
    localPath: string,
    overwrite: boolean,
    preserveMode: boolean,
    expectedRemoteSha256?: string,
  ) {
    return this.withFiles(sessionId, (files) => files.downloadFile(
      remotePath,
      localPath,
      overwrite,
      preserveMode,
      expectedRemoteSha256,
    ));
  }

  async applyPatch(sessionId: string, path: string, patch: string, expectedSha256: string, createBackup: boolean) {
    return this.withFiles(sessionId, (files) => files.applyPatch(path, patch, expectedSha256, createBackup));
  }

  private async withFiles<T extends object>(
    sessionId: string,
    operation: (files: OpenSshFileOperations) => Promise<T>,
  ): Promise<T & { session: SessionMetadata }> {
    const session = this.requireConnected(sessionId);
    return this.withOperation(session, async () => {
      const result = await operation(new OpenSshFileOperations(session.transport ?? {
        execRaw: (command, timeoutMs, maxOutputBytes) => this.execRaw(session, command, timeoutMs, maxOutputBytes),
        sftp: (batch, timeoutMs, maxOutputBytes) => this.runSftp(session, batch, timeoutMs, maxOutputBytes),
      }, this.localPathPolicy, this.paths.maxTransferBytes));
      return { session: this.sessionMetadata(session), ...result };
    });
  }

  private async execRaw(session: SessionRecord, command: string, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    if (session.transport) return session.transport.execRaw(command, timeoutMs, maxOutputBytes);
    await this.assertMaster(session);
    const result = await runProcess('ssh', [
      '-F', this.paths.sshConfigFile,
      '-S', session.controlPath,
      '-o', 'ControlMaster=no',
      '-o', 'BatchMode=yes',
      '-T',
      ...connectionOptions(session.profile),
      session.target,
      command,
    ], {
      timeout_ms: timeoutMs,
      max_output_bytes: maxOutputBytes,
    });
    if (result.exit_code === 255 && /Control socket connect|master is not running|mux_client/i.test(result.stderr.toString('utf8'))) {
      session.status = 'disconnected';
      session.lastError = result.stderr.toString('utf8').trim();
      throw new McpOpsError('SESSION_DISCONNECTED', `ControlMaster for session ${session.id} is no longer available.`);
    }
    return result;
  }

  private async runSftp(session: SessionRecord, batch: string, timeoutMs: number, maxOutputBytes: number): Promise<ProcessResult> {
    await this.assertMaster(session);
    const result = await runProcess('sftp', [
      '-q',
      '-b', '-',
      '-F', this.paths.sshConfigFile,
      '-o', `ControlPath=${session.controlPath}`,
      '-o', 'ControlMaster=no',
      '-o', 'BatchMode=yes',
      ...connectionOptions(session.profile),
      session.target,
    ], {
      input: batch,
      timeout_ms: timeoutMs,
      max_output_bytes: maxOutputBytes,
    });
    if (result.exit_code === 255 && /Control socket connect|master is not running|mux_client/i.test(result.stderr.toString('utf8'))) {
      session.status = 'disconnected';
      session.lastError = result.stderr.toString('utf8').trim();
      throw new McpOpsError('SESSION_DISCONNECTED', `ControlMaster for session ${session.id} is no longer available.`);
    }
    return result;
  }

  private async assertMaster(session: SessionRecord): Promise<void> {
    const check = await this.checkMaster(session.profile, session.target, session.controlPath);
    if (check.connected) {
      session.masterPid = check.pid;
      return;
    }
    session.status = 'disconnected';
    session.lastError = check.error;
    throw new McpOpsError('SESSION_DISCONNECTED', `ControlMaster for session ${session.id} is not running: ${check.error ?? 'unknown error'}`);
  }

  private async checkMaster(profile: SshProfile, target: string, controlPath: string): Promise<{ connected: boolean; pid?: number; error?: string }> {
    const result = await runProcess('ssh', [
      '-F', this.paths.sshConfigFile,
      '-S', controlPath,
      '-O', 'check',
      ...connectionOptions(profile),
      target,
    ], {
      timeout_ms: 5_000,
      max_output_bytes: 65_536,
    }).catch((error) => ({
      exit_code: null,
      signal: null,
      stdout: Buffer.alloc(0),
      stderr: Buffer.from(String(error)),
      timed_out: false,
      output_truncated: false,
      duration_ms: 0,
    }));
    const output = `${result.stdout.toString('utf8')}\n${result.stderr.toString('utf8')}`;
    const pid = Number(output.match(/Master running \(pid=(\d+)\)/)?.[1]);
    return {
      connected: result.exit_code === 0 && !result.timed_out,
      pid: Number.isSafeInteger(pid) && pid > 0 ? pid : undefined,
      error: result.exit_code === 0 ? undefined : result.stderr.toString('utf8').trim(),
    };
  }

  private masterArgs(profile: SshProfile, target: string, controlPath: string): string[] {
    return [
      '-F', this.paths.sshConfigFile,
      '-S', controlPath,
      '-o', 'ControlMaster=auto',
      '-o', `ControlPath=${controlPath}`,
      '-o', 'ControlPersist=300',
      '-o', 'BatchMode=no',
      '-o', 'NumberOfPasswordPrompts=1',
      '-o', 'ExitOnForwardFailure=yes',
      '-o', `ConnectTimeout=${Math.max(1, Math.ceil(profile.connect_timeout_ms / 1_000))}`,
      ...connectionOptions(profile),
      target,
      'true',
    ];
  }

  private askpassEnvironment(contextId: string): NodeJS.ProcessEnv {
    return {
      ...process.env,
      SSH_ASKPASS: this.askpassClientPath!,
      MCP_SSH_OPS_ASKPASS_CLIENT: this.askpassClientPath!,
      MCP_SSH_OPS_NATIVE_ASKPASS: process.env.SSH_ASKPASS,
      SSH_ASKPASS_REQUIRE: 'force',
      MCP_SSH_OPS_ASKPASS_SOCKET: this.broker.socketPath,
      MCP_SSH_OPS_ASKPASS_CONTEXT: contextId,
      ...(this.brokerAllPrompts ? { MCP_SSH_OPS_ASKPASS_MODE: 'broker' } : {}),
    };
  }

  private async ensureReady(): Promise<void> {
    this.readyPromise ??= (async () => {
      await this.profiles.ensure();
      if (this.backend === 'ssh2') return;
      await mkdir(this.processRuntimeDir, { recursive: true, mode: 0o700 });
      await chmod(this.processRuntimeDir, 0o700);
      this.askpassClientPath = await resolveAskpassClientPath();
      await chmod(this.askpassClientPath, 0o700);
      await this.broker.start();
    })();
    return this.readyPromise;
  }

  private ensureHeartbeat(): void {
    if (this.heartbeat) return;
    this.heartbeat = setInterval(() => void this.refreshMasters(), 60_000);
    this.heartbeat.unref();
  }

  private async refreshMasters(): Promise<void> {
    await Promise.all([...this.sessions.values()].map(async (session) => {
      if (session.status !== 'connected') return;
      const check = await this.checkMaster(session.profile, session.target, session.controlPath);
      if (check.connected) {
        session.masterPid = check.pid;
      } else {
        session.status = 'disconnected';
        session.lastError = check.error;
      }
    }));
  }

  private async withOperation<T>(session: SessionRecord, operation: () => Promise<T>): Promise<T> {
    session.activeOperations += 1;
    try {
      return await operation();
    } finally {
      session.activeOperations -= 1;
    }
  }

  private requireSession(sessionId: string): SessionRecord {
    const session = this.sessions.get(sessionId);
    if (!session) throw new McpOpsError('SESSION_NOT_FOUND', `No SSH session exists with ID ${sessionId}. Call ssh_list_sessions to see active IDs.`);
    return session;
  }

  private requireConnected(sessionId: string): SessionRecord {
    const session = this.requireSession(sessionId);
    if (session.status !== 'connected') throw new McpOpsError('SESSION_DISCONNECTED', `SSH session ${sessionId} is ${session.status}. Create a new session from its OpenSSH Host profile.`);
    return session;
  }

  private sessionMetadata(session: SessionRecord): SessionMetadata {
    return {
      session_id: session.id,
      name: session.name,
      ssh_alias: session.profile.ssh_alias ?? null,
      target: `${session.profile.username}@${session.profile.host}:${session.profile.port}`,
      host: session.profile.host,
      port: session.profile.port,
      username: session.profile.username,
      proxy_jump: session.profile.proxy_jump ?? null,
    };
  }

  private describe(session: SessionRecord) {
    return {
      ...this.sessionMetadata(session),
      status: session.status,
      auth_method: session.profile.auth_method,
      connected_at: session.connectedAt,
      active_operations: session.activeOperations,
      master_pid: session.masterPid ?? null,
      backend: session.transport ? 'ssh2' : 'openssh',
      last_error: session.lastError ?? null,
    };
  }
}

function formatPublicSessionId(name: string, profile: SshProfile, token: string): string {
  const label = sanitizeSessionLabel(name);
  const target = `${profile.username}@${profile.host}:${profile.port}`;
  const route = profile.ssh_alias ? `${sanitizeSessionLabel(profile.ssh_alias)} -> ${target}` : target;
  return `${label} | ${route} | ${token.slice(0, 8)}`;
}

function sanitizeSessionLabel(value: string): string {
  const sanitized = value.replace(/[|\r\n\0]+/g, ' ').replace(/\s+/g, ' ').trim();
  return (sanitized || 'session').slice(0, 80);
}

function connectionOptions(profile: SshProfile): string[] {
  const options: string[] = [];
  if (!profile.ssh_alias) {
    options.push(
      '-o', `HostName=${profile.host}`,
      '-o', `User=${profile.username}`,
      '-o', `Port=${profile.port}`,
      '-o', `ProxyJump=${profile.proxy_jump ?? 'none'}`,
    );
    pushAuthenticationOptions(options, profile);
    return options;
  }
  if (profile.override_username) options.push('-o', `User=${profile.username}`);
  if (profile.override_port) options.push('-o', `Port=${profile.port}`);
  if (profile.override_proxy_jump) options.push('-o', `ProxyJump=${profile.proxy_jump ?? 'none'}`);
  if (profile.override_auth) pushAuthenticationOptions(options, profile);
  return options;
}

function pushAuthenticationOptions(options: string[], profile: SshProfile): void {
  if (profile.auth_method === 'password') {
    options.push('-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no');
  } else if (profile.auth_method === 'key') {
    options.push('-o', `IdentityFile=${profile.private_key_path}`, '-o', 'IdentitiesOnly=yes', '-o', 'PreferredAuthentications=publickey');
  } else {
    options.push('-o', 'PreferredAuthentications=publickey');
  }
}

function validateProfile(profile: SshProfile): void {
  if (!profile.host || /\s/.test(profile.host)) throw new McpOpsError('INVALID_HOST', 'SSH host must be a non-empty value without whitespace.');
  if (!profile.username || /\s/.test(profile.username)) throw new McpOpsError('INVALID_USERNAME', 'SSH username must be a non-empty value without whitespace.');
  if (profile.port < 1 || profile.port > 65_535) throw new McpOpsError('INVALID_PORT', 'SSH port must be between 1 and 65535.');
  if (profile.auth_method === 'key' && !profile.private_key_path) throw new McpOpsError('PRIVATE_KEY_REQUIRED', 'private_key_path is required for key authentication.');
}

function connectionError(profile: SshProfile, result: ProcessResult): McpOpsError {
  const stderr = result.stderr.toString('utf8').trim();
  if (/REMOTE HOST IDENTIFICATION HAS CHANGED|Offending .*known_hosts|Host key for .* has changed/i.test(stderr)) {
    return new McpOpsError('HOST_KEY_CHANGED', `OpenSSH rejected a changed host key for ${profile.host}. Inspect ${stderr}`);
  }
  if (/Permission denied|Authentication failed/i.test(stderr)) {
    return new McpOpsError('SSH_AUTH_FAILED', `Authentication failed for ${profile.username}@${profile.host}: ${stderr}`);
  }
  if (result.timed_out) return new McpOpsError('SSH_CONNECTION_TIMEOUT', `Connection to ${profile.host} timed out.`);
  return new McpOpsError('SSH_CONNECTION_FAILED', `Cannot connect to ${profile.username}@${profile.host}:${profile.port}: ${stderr || `ssh exited with ${result.exit_code}`}`);
}

async function resolveAskpassClientPath(): Promise<string> {
  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(moduleDirectory, '..', 'askpass-client.js'),
    join(moduleDirectory, '..', '..', 'dist', 'askpass-client.js'),
  ];
  for (const candidate of candidates) {
    try {
      await access(candidate, constants.F_OK);
      return candidate;
    } catch {
      continue;
    }
  }
  throw new McpOpsError('ASKPASS_CLIENT_MISSING', 'dist/askpass-client.js is missing. Run npm run build before starting MCP Ops.');
}
