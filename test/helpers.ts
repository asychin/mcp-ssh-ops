import { join } from 'node:path';
import type { AppPaths } from '../src/config.js';

export function testPaths(directory: string): AppPaths {
  const sshDir = join(directory, '.ssh', 'mcp-ssh-ops');
  const legacyConfigDir = join(directory, '.config', 'mcp-ops');
  return {
    sshDir,
    sshConfigFile: join(sshDir, 'config'),
    knownHostsFile: join(sshDir, 'known_hosts'),
    keysDir: join(sshDir, 'keys'),
    runtimeDir: join(directory, 'runtime'),
    localRoots: [directory, '/tmp'],
    maxTransferBytes: 104_857_600,
    legacyConfigDir,
    legacyProfilesFile: join(legacyConfigDir, 'profiles.json'),
    legacyKnownHostsFile: join(legacyConfigDir, 'known_hosts'),
  };
}
