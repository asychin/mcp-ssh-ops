export const AUTH_METHODS = ['agent', 'key', 'password'] as const;

export type AuthMethod = (typeof AUTH_METHODS)[number];

export interface SshProfile {
  host: string;
  port: number;
  username: string;
  auth_method: AuthMethod;
  private_key_path?: string;
  proxy_jump?: string;
  connect_timeout_ms: number;
  ssh_alias?: string;
  override_username?: boolean;
  override_port?: boolean;
  override_auth?: boolean;
  override_proxy_jump?: boolean;
}

export interface NamedSshProfile extends SshProfile {
  name: string;
}

export interface ExecRequest {
  command: string;
  cwd?: string;
  env?: Record<string, string>;
  timeout_ms: number;
  max_output_bytes: number;
}

export interface SessionMetadata {
  session_id: string;
  name: string;
  ssh_alias: string | null;
  target: string;
  host: string;
  port: number;
  username: string;
  proxy_jump: string | null;
}

export interface ExecResult {
  session: SessionMetadata;
  exit_code: number | null;
  signal: string | null;
  stdout: string;
  stderr: string;
  timed_out: boolean;
  output_truncated: boolean;
  duration_ms: number;
}
