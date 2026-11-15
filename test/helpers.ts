import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { generateKeyPairSync } from 'node:crypto';
import type { AppPaths } from '../src/config.js';

export function testKeyPair() {
  // ssh2's Ed25519 generator incorrectly strips leading zero public-key bytes.
  const { privateKey } = generateKeyPairSync('ec', {
    namedCurve: 'prime256v1', privateKeyEncoding: { type: 'sec1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { private: privateKey };
}

export function testPaths(directory: string): AppPaths {
  const sshDir = join(directory, '.ssh', 'mcp-ssh-ops');
  const legacyConfigDir = join(directory, '.config', 'mcp-ops');
  return {
    sshDir,
    sshConfigFile: join(sshDir, 'config'),
    knownHostsFile: join(sshDir, 'known_hosts'),
    keysDir: join(sshDir, 'keys'),
    runtimeDir: join(directory, 'runtime'),
    localRoots: [directory, tmpdir()],
    maxTransferBytes: 104_857_600,
    legacyConfigDir,
    legacyProfilesFile: join(legacyConfigDir, 'profiles.json'),
    legacyKnownHostsFile: join(legacyConfigDir, 'known_hosts'),
  };
}
