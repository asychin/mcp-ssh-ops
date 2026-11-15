import { Duplex } from 'node:stream';
import type { AnyAuthMethod, AuthenticationType, ClientChannel, ConnectConfig, NextAuthHandler } from 'ssh2';
import type { AppPaths } from '../config.js';
import { ASKPASS_TIMEOUT_MS } from '../config.js';
import { McpOpsError } from '../errors.js';
import { promptSecret } from '../password-prompt.js';
import type { ProfileStore } from '../profile-store.js';
import type { SshProfile } from '../types.js';
import { HostKeyStore } from './host-keys.js';
import { SecretCache } from './secret-cache.js';
import { configPaths, disabled, expandPath, option, ssh2Algorithms, validateSsh2Options } from './ssh2-config.js';
import { Ssh2Transport } from './ssh2-transport.js';

export class Ssh2ConnectionFactory {
  private readonly secrets: SecretCache;
  private readonly pending = new Map<string, { store: HostKeyStore; lookupHost: string }>();

  constructor(private readonly paths: AppPaths, private readonly profiles: ProfileStore, prompt: typeof promptSecret) {
    this.secrets = new SecretCache(prompt);
  }

  async connect(profile: SshProfile, overrides: string[], signal?: AbortSignal): Promise<Ssh2Transport> {
    const opened: Ssh2Transport[] = [];
    try {
      return await this.connectHop(profile, overrides, opened, new Set(), signal);
    } catch (error) {
      for (const transport of opened.reverse()) transport.close();
      throw error;
    }
  }

  async trustHost(host: string, port: number, fingerprint: string) {
    const key = pendingId(host, port, fingerprint);
    const pending = this.pending.get(key);
    if (!pending) throw new McpOpsError('HOST_KEY_NOT_PENDING', 'No matching host key is pending. Connect first and confirm the exact fingerprint.');
    await pending.store.trustPending(pending.lookupHost, port, fingerprint);
    this.pending.delete(key);
    return { status: 'approved' as const, host, port, fingerprint };
  }

  private async connectHop(
    profile: SshProfile, overrides: string[], opened: Ssh2Transport[], ancestors: Set<string>, signal?: AbortSignal, upstream?: Ssh2Transport,
  ): Promise<Ssh2Transport> {
    if (signal?.aborted) throw cancelled();
    const alias = profile.ssh_alias ?? profile.host;
    if (ancestors.has(alias) || ancestors.size >= 16 || opened.length >= 16) throw new McpOpsError('PROXY_JUMP_CYCLE', 'ProxyJump is cyclic or exceeds 16 hops.');
    const chain = new Set([...ancestors, alias]);
    const values = await this.profiles.resolveOptions(alias, [...overrides, ...(upstream ? ['-o', 'ProxyJump=none'] : [])]);
    const defaults = await this.profiles.resolveOptions(alias, [], true);
    validateSsh2Options(values, defaults);
    if (profile.auth_method === 'key') {
      throw new McpOpsError('SSH_CONFIG_UNSUPPORTED', 'Windows ssh2 never reads private key files. Load the key with ssh-add, then use agent authentication without IdentitiesOnly.');
    }
    const algorithms = ssh2Algorithms(values);
    const host = option(values, 'hostname') ?? profile.host;
    const port = Number(option(values, 'port') ?? profile.port);
    const username = option(values, 'user') ?? profile.username;
    const userHosts = configPaths(values, 'userknownhostsfile', host, port, username);
    const globalHosts = configPaths(values, 'globalknownhostsfile', host, port, username);
    const store = new HostKeyStore(userHosts[0] ?? this.paths.knownHostsFile, [...userHosts, ...globalHosts]);
    await store.refresh();
    let parent = upstream;
    const jumps = option(values, 'proxyjump');
    if (jumps && jumps !== 'none') {
      for (const jump of jumps.split(',')) {
        const hop = parseJump(jump);
        const resolved = await this.profiles.resolve(hop.host);
        const jumpOptions = [
          ...(hop.username ? ['-o', `User=${hop.username}`] : []),
          ...(hop.port ? ['-o', `Port=${hop.port}`] : []),
        ];
        parent = await this.connectHop({ ...resolved, username: hop.username ?? resolved.username, port: hop.port ?? resolved.port }, jumpOptions, opened, chain, signal, parent);
      }
    }
    let socket: ClientChannel | undefined;
    if (parent) {
      socket = await new Promise<ClientChannel>((resolve, reject) => {
        const timer = setTimeout(() => { parent!.close(); reject(new McpOpsError('PROXY_JUMP_TIMEOUT', 'ProxyJump channel timed out.')); }, profile.connect_timeout_ms);
        const abort = () => { clearTimeout(timer); parent!.close(); reject(cancelled()); };
        signal?.addEventListener('abort', abort, { once: true });
        parent!.client.forwardOut('127.0.0.1', 0, host, port, (error, stream) => {
          clearTimeout(timer);
          signal?.removeEventListener('abort', abort);
          if (signal?.aborted) { stream?.destroy(); reject(cancelled()); }
          else if (error) reject(error);
          else resolve(stream);
        });
      });
    }
    if (signal?.aborted) throw cancelled();
    const group = `user:${username}`;
    this.secrets.retain(group);
    const transport = new Ssh2Transport(this.paths.maxTransferBytes, () => this.secrets.release(group), parent);
    opened.push(transport);
    const lookupHost = option(values, 'hostkeyalias') ?? host;
    let promptError: unknown;
    let hostError: McpOpsError | undefined;
    const agentOption = option(values, 'identityagent');
    const agent = agentOption === 'none' ? undefined
      : !agentOption || agentOption === 'SSH_AUTH_SOCK' ? process.env.SSH_AUTH_SOCK ?? (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : undefined)
        : expandPath(agentOption.replace(/^\$SSH_AUTH_SOCK$/, process.env.SSH_AUTH_SOCK ?? ''), host, port, username);
    const methods = (option(values, 'preferredauthentications') ?? 'publickey,keyboard-interactive,password').split(',');
    const attempts = new Set<string>();
    const interactive = option(values, 'batchmode') !== 'yes' && option(values, 'numberofpasswordprompts') !== '0';
    const config: ConnectConfig = {
      host, port, username, sock: socket ? deferredChannel(socket) : undefined, algorithms, tryKeyboard: true, readyTimeout: profile.connect_timeout_ms + ASKPASS_TIMEOUT_MS,
      keepaliveInterval: Number(option(values, 'serveraliveinterval') ?? 30) * 1_000,
      keepaliveCountMax: Number(option(values, 'serveralivecountmax') ?? 3),
      hostVerifier: (key: Buffer) => {
        const verification = store.rememberUnknown(lookupHost, port, key);
        if (verification.status === 'trusted') return true;
        if (verification.status === 'unknown') {
          if (!userHosts.length) {
            hostError = new McpOpsError('SSH_CONFIG_UNSUPPORTED', 'No writable UserKnownHostsFile is configured. Refusing to trust a host outside the configured trust store.');
          } else {
            this.pending.set(pendingId(host, port, verification.fingerprint), { store, lookupHost });
            hostError = new McpOpsError('HOST_KEY_UNKNOWN', `${host}:${port} is not trusted. Key type: ${verification.key_type}. Fingerprint: ${verification.fingerprint}. Ask the operator to verify it before ssh_trust_host.`);
          }
        } else {
          hostError = new McpOpsError('HOST_KEY_CHANGED', `Host key for ${host}:${port} is ${verification.status}. Investigate the configured known_hosts manually.`);
        }
        return false;
      },
      authHandler: (remaining, _partial, callback) => {
        if (!remaining) return callback({ type: 'none', username });
        const method = methods.find((candidate) => remaining.some((allowed) => allowed === candidate) && !attempts.has(candidate)
          && (candidate !== 'publickey' || Boolean(agent) && !disabled(values, 'pubkeyauthentication'))
          && (candidate !== 'password' || interactive && !disabled(values, 'passwordauthentication'))
          && (candidate !== 'keyboard-interactive' || interactive && !disabled(values, 'kbdinteractiveauthentication'))
          && ['publickey', 'password', 'keyboard-interactive'].includes(candidate));
        if (!method || signal?.aborted) return stopAuthentication(callback);
        attempts.add(method);
        if (method === 'publickey') return callback({ type: 'agent', username, agent: agent! });
        if (method === 'keyboard-interactive') return callback('keyboard-interactive');
        void this.secrets.get(group, 'password', `${username}@${host}'s password:`).then(
          (password) => { if (transport.isClosed || signal?.aborted) return; callback({ type: 'password', username, password }); },
          (error) => { promptError = error; if (!transport.isClosed) stopAuthentication(callback); },
        );
      },
    };
    return new Promise<Ssh2Transport>((resolve, reject) => {
      let settled = false;
      const finish = (error?: unknown) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener('abort', abort);
        if (error) {
          if ((error as { level?: string }).level === 'client-authentication') this.secrets.invalidate(group);
          transport.close();
          reject(hostError ?? promptError ?? error);
        } else { transport.connected = true; resolve(transport); }
      };
      const abort = () => finish(cancelled());
      signal?.addEventListener('abort', abort, { once: true });
      transport.client.once('ready', () => finish());
      transport.client.on('error', (error: Error & { level?: string }) => {
        if (error.level !== 'agent') finish(error);
      });
      transport.client.once('close', () => finish(new McpOpsError('SSH_CONNECTION_FAILED', `SSH connection to ${username}@${host}:${port} closed before authentication${parent ? ' over ProxyJump' : ''}.`)));
      transport.client.on('keyboard-interactive', (_name, _instructions, _language, prompts, respond) => {
        void (async () => {
          const answers: string[] = [];
          for (const prompt of prompts) {
            const password = !prompt.echo && /^password\s*:/i.test(prompt.prompt.trim());
            answers.push(await this.secrets.get(group, password ? 'password' : prompt.prompt, `${username}@${host}: ${prompt.prompt}`, password));
          }
          if (!settled && !signal?.aborted) respond(answers);
        })().catch((error) => { promptError = error; finish(error); });
      });
      try { transport.client.connect(config); }
      catch (error) { finish(error); }
    });
  }
}

function deferredChannel(channel: ClientChannel): Duplex {
  const socket = new Duplex({
    read() { channel.resume(); },
    write(chunk: Buffer, encoding, callback) {
      // ssh2's fallback ChaCha cipher shares nonce scratch space across clients.
      // Defer parent writes until the child has finished encrypting its packet.
      queueMicrotask(() => {
        if (channel.destroyed) callback(new Error('ProxyJump channel is closed.'));
        else channel.write(chunk, encoding, callback);
      });
    },
    final(callback) { channel.end(callback); },
    destroy(error, callback) { channel.destroy(); callback(error); },
  });
  channel.on('data', (chunk: Buffer) => { if (!socket.push(chunk)) channel.pause(); });
  channel.once('end', () => socket.push(null));
  channel.once('error', (error: Error) => socket.destroy(error));
  channel.once('close', () => socket.destroy());
  return socket;
}

function pendingId(host: string, port: number, fingerprint: string): string {
  return `${host.toLowerCase()}\0${port}\0${fingerprint}`;
}

function cancelled(): McpOpsError {
  return new McpOpsError('REQUEST_CANCELLED', 'SSH connection cancelled by the MCP client.');
}

function stopAuthentication(callback: NextAuthHandler): void {
  // ssh2 documents false as exhaustion; @types/ssh2 omits it.
  (callback as (method: AuthenticationType | AnyAuthMethod | false) => void)(false);
}

export function parseJump(jump: string): { host: string; username?: string; port?: number } {
  const match = jump.match(/^(?:([^@\s]+)@)?(\[[^\]]+\]|[^:\s]+)(?::(\d+))?$/);
  if (!match?.[2]) throw new McpOpsError('PROXY_JUMP_INVALID', `Unsupported ProxyJump target: ${jump}.`);
  const port = match[3] ? Number(match[3]) : undefined;
  if (port !== undefined && (port < 1 || port > 65_535)) throw new McpOpsError('PROXY_JUMP_INVALID', 'Invalid ProxyJump port.');
  return { username: match[1], host: match[2].replace(/^\[|\]$/g, ''), port };
}
