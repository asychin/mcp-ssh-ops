import { McpServer } from '@modelcontextprotocol/server';
import * as z from 'zod/v4';
import {
  DEFAULT_COMMAND_TIMEOUT_MS,
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_OUTPUT_LIMIT_BYTES,
  DEFAULT_READ_LIMIT_BYTES,
  MAX_COMMAND_TIMEOUT_MS,
  MAX_OUTPUT_LIMIT_BYTES,
  MAX_READ_LIMIT_BYTES,
} from './config.js';
import { McpOpsError } from './errors.js';
import { ProfileStore } from './profile-store.js';
import type { SshProfile } from './types.js';
import { SessionManager } from './ssh/session-manager.js';

const profileName = z.string().min(1).max(64).regex(/^[A-Za-z0-9._-]+$/).describe('Profile name containing letters, digits, dot, underscore, or hyphen');
const sessionId = z.string().min(1).max(512).describe('Human-readable session ID containing session name, SSH alias, resolved user@host:port, and a unique token');
const remotePath = z.string().min(1).max(4096).describe('Absolute or remote-shell-relative path on the SSH server');
const localPath = z.string().min(1).max(4096).describe('Local path under an allowed MCP SSH Ops local root');
const sha256Hash = z.string().regex(/^(?:sha256:)?[a-fA-F0-9]{64}$/);
const authMethod = z.enum(['agent', 'key', 'password']);
const directProfileFields = {
  host: z.string().min(1).max(255).regex(/^\S+$/),
  port: z.number().int().min(1).max(65_535).default(22),
  username: z.string().min(1).max(128).regex(/^\S+$/),
  auth_method: authMethod.default('agent'),
  private_key_path: z.string().min(1).max(4096).optional(),
  proxy_jump: z.string().min(1).max(4096).regex(/^\S+$/).optional(),
  connect_timeout_ms: z.number().int().min(1_000).max(120_000).default(DEFAULT_CONNECT_TIMEOUT_MS),
};

export interface ServerDependencies {
  profiles: ProfileStore;
  sessions: SessionManager;
}

export function createMcpServer(dependencies: ServerDependencies): McpServer {
  const { profiles, sessions } = dependencies;
  const server = new McpServer({ name: 'mcp-ssh-ops', version: '0.3.2' });

  server.registerTool(
    'ssh_save_profile',
    {
      description: 'Save or replace a Host block in the user native ~/.ssh/config. Supports ProxyJump; passwords and key passphrases are never stored.',
      inputSchema: z.object({ name: profileName, ...directProfileFields }),
    },
    async ({ name, ...profile }) => jsonResult(await profiles.save(name, profile)),
  );

  server.registerTool(
    'ssh_list_profiles',
    {
      description: 'List literal Host aliases from the user ~/.ssh/config and Include files, resolved natively with ssh -G. Live ControlMaster sessions remain isolated to this MCP process.',
      inputSchema: z.object({}),
    },
    async () => jsonResult({ profiles: await profiles.list() }),
  );

  server.registerTool(
    'ssh_create_session',
    {
      description: 'Create an isolated native OpenSSH ControlMaster. host without username must match a literal Host in ~/.ssh/config. host with username still resolves all OpenSSH settings via ssh -G, then overrides only explicitly supplied fields. Also accepts profile_name. Passwords are never tool arguments.',
      inputSchema: z.object({
        profile_name: profileName.optional(),
        session_name: z.string().min(1).max(128).optional(),
        host: directProfileFields.host.optional(),
        port: z.number().int().min(1).max(65_535).optional(),
        username: directProfileFields.username.optional(),
        auth_method: authMethod.optional(),
        private_key_path: directProfileFields.private_key_path,
        proxy_jump: directProfileFields.proxy_jump,
        connect_timeout_ms: z.number().int().min(1_000).max(120_000).optional(),
      }),
    },
    async (input, context) => {
      let profile: SshProfile;
      if (input.profile_name) {
        const directValues = [input.host, input.username, input.port, input.auth_method, input.private_key_path, input.proxy_jump, input.connect_timeout_ms];
        if (directValues.some((value) => value !== undefined)) {
          throw new McpOpsError('AMBIGUOUS_SESSION_CONFIG', 'Use profile_name by itself, or provide host with optional explicit overrides.');
        }
        profile = await profiles.get(input.profile_name);
      } else if (input.host && !input.username) {
        const overrides = [input.port, input.auth_method, input.private_key_path, input.proxy_jump, input.connect_timeout_ms];
        if (overrides.some((value) => value !== undefined)) {
          throw new McpOpsError('USERNAME_REQUIRED_FOR_OVERRIDES', 'A host without username uses its ~/.ssh/config Host block unchanged. Provide username when overriding connection fields.');
        }
        profile = await profiles.get(input.host);
      } else if (input.host && input.username) {
        const resolved = await profiles.resolve(input.host);
        const authMethod = input.private_key_path ? 'key' : input.auth_method ?? resolved.auth_method;
        const validated = profiles.validateProfile({
          host: resolved.host,
          port: input.port ?? resolved.port,
          username: input.username,
          auth_method: authMethod,
          private_key_path: authMethod === 'key' ? input.private_key_path ?? resolved.private_key_path : undefined,
          proxy_jump: input.proxy_jump ?? resolved.proxy_jump,
          connect_timeout_ms: input.connect_timeout_ms ?? resolved.connect_timeout_ms,
        });
        profile = {
          ...validated,
          ssh_alias: input.host,
          override_username: true,
          override_port: input.port !== undefined,
          override_auth: input.auth_method !== undefined || input.private_key_path !== undefined,
          override_proxy_jump: input.proxy_jump !== undefined,
        };
      } else {
        throw new McpOpsError('SESSION_CONFIG_REQUIRED', 'Provide profile_name or host. A host without username must exist as a literal Host alias in ~/.ssh/config.');
      }
      return jsonResult(await sessions.createSession(profile, input.session_name, undefined, context.mcpReq.signal));
    },
  );

  server.registerTool(
    'ssh_trust_host',
    {
      description: 'Approve an OpenSSH host-key prompt rejected by ssh_create_session. Call only after the operator verifies the exact host, port, and SHA-256 fingerprint. The next connection lets OpenSSH write it to the user configured known_hosts; changed keys remain blocked.',
      inputSchema: z.object({
        host: z.string().min(1).max(255).regex(/^\S+$/),
        port: z.number().int().min(1).max(65_535).default(22),
        fingerprint: z.string().regex(/^SHA256:[A-Za-z0-9+/]+$/),
      }),
    },
    async ({ host, port, fingerprint }) => jsonResult(sessions.trustHost(host, port, fingerprint)),
  );

  server.registerTool(
    'ssh_list_sessions',
    {
      description: 'List SSH sessions owned by this agent process. Sessions from other chats or agents are not visible.',
      inputSchema: z.object({}),
    },
    async () => jsonResult({ sessions: sessions.listSessions() }),
  );

  server.registerTool(
    'ssh_session_info',
    {
      description: 'Show the current status and non-secret metadata for one SSH session.',
      inputSchema: z.object({ session_id: sessionId }),
    },
    async ({ session_id }) => jsonResult(sessions.sessionInfo(session_id)),
  );

  server.registerTool(
    'ssh_clone_session',
    {
      description: 'Create an independent OpenSSH ControlMaster with the same target settings. Agent/key authentication is automatic; password/passphrase is reused from this MCP process RAM for the same user and prompt while another session keeps that credential scope active.',
      inputSchema: z.object({
        session_id: sessionId,
        session_name: z.string().min(1).max(128).optional(),
      }),
    },
    async ({ session_id, session_name }, context) => jsonResult(await sessions.cloneSession(session_id, session_name, context.mcpReq.signal)),
  );

  server.registerTool(
    'ssh_close_session',
    {
      description: 'Close and forget one SSH session owned by this agent process.',
      inputSchema: z.object({ session_id: sessionId }),
    },
    async ({ session_id }) => jsonResult(await sessions.closeSession(session_id)),
  );

  server.registerTool(
    'ssh_exec',
    {
      description: 'Execute a non-interactive command over an existing persistent SSH connection. No PTY is allocated and stdin is closed. The human-readable session_id is visible in Arguments; output includes explicit session name/alias/target plus exit code, stdout, stderr, timeout, and truncation metadata.',
      inputSchema: z.object({
        session_id: sessionId,
        command: z.string().min(1).max(131_072),
        cwd: z.string().min(1).max(4096).optional(),
        env: z.record(z.string(), z.string().max(32_768)).optional(),
        timeout_ms: z.number().int().min(100).max(MAX_COMMAND_TIMEOUT_MS).default(DEFAULT_COMMAND_TIMEOUT_MS),
        max_output_bytes: z.number().int().min(1_024).max(MAX_OUTPUT_LIMIT_BYTES).default(DEFAULT_OUTPUT_LIMIT_BYTES),
      }),
    },
    async ({ session_id, ...request }) => {
      if (request.env && Object.keys(request.env).length > 64) {
        throw new McpOpsError('TOO_MANY_ENV_VARS', 'At most 64 environment variables may be supplied.');
      }
      return jsonResult(await sessions.exec(session_id, request));
    },
  );

  server.registerTool(
    'ssh_stat',
    {
      description: 'Read remote file metadata through SFTP without downloading file contents.',
      inputSchema: z.object({
        session_id: sessionId,
        path: remotePath,
        follow_symlinks: z.boolean().default(false),
      }),
    },
    async ({ session_id, path, follow_symlinks }) => jsonResult(await sessions.stat(session_id, path, follow_symlinks)),
  );

  server.registerTool(
    'ssh_list_directory',
    {
      description: 'List a remote directory through SFTP with a bounded number of entries.',
      inputSchema: z.object({
        session_id: sessionId,
        path: remotePath,
        max_entries: z.number().int().min(1).max(1_000).default(200),
      }),
    },
    async ({ session_id, path, max_entries }) => jsonResult(await sessions.listDirectory(session_id, path, max_entries)),
  );

  server.registerTool(
    'ssh_read_file',
    {
      description: 'Read a bounded range from a remote file through SFTP. UTF-8 and base64 output are supported. A full-file read returns the SHA-256 required by ssh_apply_patch.',
      inputSchema: z.object({
        session_id: sessionId,
        path: remotePath,
        offset: z.number().int().min(0).default(0),
        length: z.number().int().min(0).max(MAX_READ_LIMIT_BYTES).optional(),
        max_bytes: z.number().int().min(1).max(MAX_READ_LIMIT_BYTES).default(DEFAULT_READ_LIMIT_BYTES),
        encoding: z.enum(['utf8', 'base64']).default('utf8'),
      }),
    },
    async ({ session_id, path, offset, length, max_bytes, encoding }) => jsonResult(
      await sessions.readRemoteFile(session_id, path, offset, length, max_bytes, encoding),
    ),
  );

  server.registerTool(
    'ssh_upload_file',
    {
      description: 'Upload one regular local file to the remote server through the existing ControlMaster SFTP channel. Local path must be inside an allowed root. Refuses overwrite by default; overwrite=true creates a remote backup. Verifies SHA-256 before and after transfer.',
      inputSchema: z.object({
        session_id: sessionId,
        local_path: localPath,
        remote_path: remotePath,
        overwrite: z.boolean().default(false),
        preserve_mode: z.boolean().default(true),
        expected_local_sha256: sha256Hash.optional(),
        expected_destination_sha256: sha256Hash.optional(),
      }),
    },
    async ({ session_id, local_path, remote_path, overwrite, preserve_mode, expected_local_sha256, expected_destination_sha256 }) => jsonResult(
      await sessions.uploadFile(
        session_id,
        local_path,
        remote_path,
        overwrite,
        preserve_mode,
        expected_local_sha256,
        expected_destination_sha256,
      ),
    ),
  );

  server.registerTool(
    'ssh_download_file',
    {
      description: 'Download one regular remote file through the existing ControlMaster SFTP channel. Local destination must be inside an allowed root. Refuses overwrite by default; overwrite=true creates a local backup. Verifies SHA-256 before and after transfer.',
      inputSchema: z.object({
        session_id: sessionId,
        remote_path: remotePath,
        local_path: localPath,
        overwrite: z.boolean().default(false),
        preserve_mode: z.boolean().default(true),
        expected_remote_sha256: sha256Hash.optional(),
      }),
    },
    async ({ session_id, remote_path, local_path, overwrite, preserve_mode, expected_remote_sha256 }) => jsonResult(
      await sessions.downloadFile(
        session_id,
        remote_path,
        local_path,
        overwrite,
        preserve_mode,
        expected_remote_sha256,
      ),
    ),
  );

  server.registerTool(
    'ssh_apply_patch',
    {
      description: 'Safely edit a UTF-8 remote file using a unified diff. Requires the SHA-256 from a full ssh_read_file result, rejects concurrent changes, writes a same-directory temporary file, preserves mode, optionally creates a backup, and atomically renames when supported.',
      inputSchema: z.object({
        session_id: sessionId,
        path: remotePath,
        patch: z.string().min(1).max(5_242_880),
        expected_sha256: sha256Hash,
        create_backup: z.boolean().default(true),
      }),
    },
    async ({ session_id, path, patch, expected_sha256, create_backup }) => jsonResult(
      await sessions.applyPatch(session_id, path, patch, expected_sha256, create_backup),
    ),
  );

  return server;
}

function jsonResult(value: unknown) {
  return { content: [{ type: 'text' as const, text: JSON.stringify(value, null, 2) }] };
}
