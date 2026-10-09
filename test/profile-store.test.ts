import assert from 'node:assert/strict';
import { chmod, mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { ProfileStore } from '../src/profile-store.js';
import { testPaths } from './helpers.js';

test('stores profiles as native OpenSSH Host blocks without secrets', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-profiles-'));
  try {
    const paths = testPaths(directory);
    const store = new ProfileStore(paths);
    const saved = await store.save('prod-web', {
      host: 'prod.example.test',
      username: 'deployer',
      auth_method: 'agent',
      proxy_jump: 'bastion',
      password: 'must-not-be-stored',
    } as never);
    assert.equal(saved.port, 22);
    assert.equal(saved.proxy_jump, 'bastion');
    const content = await readFile(paths.sshConfigFile, 'utf8');
    assert.match(content, /Host prod-web/);
    assert.match(content, /ProxyJump bastion/);
    assert.match(content, /PreferredAuthentications publickey/);
    assert.doesNotMatch(content, /must-not-be-stored|password\s+must-not/i);
    const profiles = await store.list();
    assert.equal(profiles.length, 1);
    assert.equal(profiles[0]?.name, 'prod-web');
    assert.equal(profiles[0]?.host, 'prod.example.test');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('lists literal aliases from Include files and resolves them with ssh -G', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-include-'));
  try {
    const paths = testPaths(directory);
    const store = new ProfileStore(paths);
    await store.ensure();
    const included = join(paths.sshDir, 'included.conf');
    await writeFile(included, 'Host internal-db\n    HostName 10.20.30.40\n    User dbadmin\n    ProxyJump bastion\n');
    await writeFile(paths.sshConfigFile, `${await readFile(paths.sshConfigFile, 'utf8')}\nInclude "${included}"\n`);
    const profiles = await store.list();
    const profile = profiles.find((candidate) => candidate.name === 'internal-db');
    assert.equal(profile?.host, '10.20.30.40');
    assert.equal(profile?.username, 'dbadmin');
    assert.equal(profile?.proxy_jump, 'bastion');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('uses existing user config and known_hosts without replacing their contents', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-user-ssh-'));
  try {
    const paths = testPaths(directory);
    await mkdir(paths.sshDir, { recursive: true });
    const config = 'Host existing\n    HostName existing.example.test\n    User operator\n';
    const knownHosts = 'existing.example.test ssh-ed25519 AAAA\n';
    await writeFile(paths.sshConfigFile, config);
    await writeFile(paths.knownHostsFile, knownHosts);
    const store = new ProfileStore(paths);
    await store.ensure();
    assert.equal(await readFile(paths.sshConfigFile, 'utf8'), config);
    assert.equal(await readFile(paths.knownHostsFile, 'utf8'), knownHosts);
    const profile = await store.get('existing');
    assert.equal(profile.host, 'existing.example.test');
    assert.equal(profile.connect_timeout_ms, 30_000);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('requires a private key path for key profiles', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-profiles-'));
  try {
    const store = new ProfileStore(testPaths(directory));
    await assert.rejects(
      store.save('invalid', { host: 'host.test', username: 'user', auth_method: 'key' }),
      /INVALID_PROFILE/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('preserves existing SSH config mode and saves aliases before broad Host blocks', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-profile-mode-'));
  try {
    const paths = testPaths(directory);
    await mkdir(paths.sshDir, { recursive: true });
    await writeFile(paths.sshConfigFile, 'Host *\n    User default\n');
    await chmod(paths.sshConfigFile, 0o640);
    const store = new ProfileStore(paths);
    await store.save('specific', { host: 'specific.example.test', username: 'operator', auth_method: 'agent' });
    assert.equal((await stat(paths.sshConfigFile)).mode & 0o777, 0o640);
    assert.match(await readFile(paths.sshConfigFile, 'utf8'), /^Host specific/m);
    assert.equal((await store.get('specific')).host, 'specific.example.test');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
