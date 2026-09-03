import { homedir, tmpdir, userInfo } from 'node:os';
import { delimiter, join, resolve } from 'node:path';

export interface AppPaths {
  sshDir: string;
  sshConfigFile: string;
  knownHostsFile: string;
  keysDir: string;
  runtimeDir: string;
  localRoots: string[];
  maxTransferBytes: number;
  legacyConfigDir: string;
  legacyProfilesFile: string;
  legacyKnownHostsFile: string;
}

export function getAppPaths(env: NodeJS.ProcessEnv = process.env): AppPaths {
  const home = env.HOME ?? homedir();
  const sshDir = resolve(env.MCP_SSH_OPS_SSH_DIR ?? join(home, '.ssh'));
  const legacyConfigDir = resolve(env.MCP_SSH_OPS_CONFIG_DIR ?? join(home, '.config', 'mcp-ops'));
  const runtimeBase = env.XDG_RUNTIME_DIR
    ? resolve(env.XDG_RUNTIME_DIR)
    : join('/tmp', `mcp-ssh-ops-${userInfo().uid}`);
  const localRoots = env.MCP_SSH_OPS_LOCAL_ROOTS
    ? env.MCP_SSH_OPS_LOCAL_ROOTS.split(delimiter).filter(Boolean).map((path) => resolve(path))
    : [resolve(process.cwd()), resolve(tmpdir())];
  const configuredTransferLimit = Number(env.MCP_SSH_OPS_MAX_TRANSFER_BYTES);
  return {
    sshDir,
    sshConfigFile: resolve(env.MCP_SSH_OPS_SSH_CONFIG ?? join(sshDir, 'config')),
    knownHostsFile: resolve(env.MCP_SSH_OPS_KNOWN_HOSTS ?? join(sshDir, 'known_hosts')),
    keysDir: sshDir,
    runtimeDir: join(runtimeBase, 'mcp-ssh-ops'),
    localRoots: [...new Set(localRoots)],
    maxTransferBytes: Number.isSafeInteger(configuredTransferLimit) && configuredTransferLimit > 0
      ? configuredTransferLimit
      : DEFAULT_TRANSFER_LIMIT_BYTES,
    legacyConfigDir,
    legacyProfilesFile: join(legacyConfigDir, 'profiles.json'),
    legacyKnownHostsFile: join(legacyConfigDir, 'known_hosts'),
  };
}

export const DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
export const DEFAULT_COMMAND_TIMEOUT_MS = 30_000;
export const MAX_COMMAND_TIMEOUT_MS = 600_000;
export const DEFAULT_OUTPUT_LIMIT_BYTES = 1_048_576;
export const MAX_OUTPUT_LIMIT_BYTES = 5_242_880;
export const DEFAULT_READ_LIMIT_BYTES = 1_048_576;
export const MAX_READ_LIMIT_BYTES = 2_097_152;
export const MAX_EDIT_FILE_BYTES = 2_097_152;
export const DEFAULT_TRANSFER_LIMIT_BYTES = 104_857_600;
export const ASKPASS_TIMEOUT_MS = 120_000;
export const MASTER_START_TIMEOUT_MS = 180_000;
