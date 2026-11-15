import assert from 'node:assert/strict';
import { test } from 'node:test';
import { configPaths, splitConfigPaths, ssh2Algorithms, validateSsh2Options } from '../src/ssh/ssh2-config.js';
import { parseJump } from '../src/ssh/ssh2-connection.js';
import { SecretCache } from '../src/ssh/secret-cache.js';

test('fails closed on unsupported config instead of silently downgrading OpenSSH', () => {
  const defaults = new Map([['proxycommand', ['none']], ['pubkeyacceptedalgorithms', ['rsa-sha2-512']]]);
  assert.doesNotThrow(() => validateSsh2Options(defaults, defaults));
  for (const [key, value] of [['proxycommand', 'nc bastion 22'], ['certificatefile', '~/.ssh/id-cert.pub'], ['identityfile', '~/.ssh/custom'], ['identitiesonly', 'yes'], ['forwardagent', 'yes'], ['pubkeyacceptedalgorithms', 'ssh-rsa']] as const) {
    assert.throws(() => validateSsh2Options(new Map([...defaults, [key, [value]]]), defaults), /SSH_CONFIG_UNSUPPORTED/);
  }
  assert.throws(() => ssh2Algorithms(new Map([['hostkeyalgorithms', ['ssh-ed25519-cert-v01@openssh.com']]])), /SSH_CONFIG_UNSUPPORTED/);
  assert.deepEqual(ssh2Algorithms(new Map([['hostkeyalgorithms', ['ssh-ed25519-cert-v01@openssh.com,ssh-ed25519']]])).serverHostKey, ['ssh-ed25519']);
});

test('parses Windows paths and jump routes without a shell', () => {
  assert.deepEqual(splitConfigPaths('"C:\\Users\\Alice Smith\\.ssh\\known_hosts" C:/ProgramData/ssh/known_hosts'), ['C:\\Users\\Alice Smith\\.ssh\\known_hosts', 'C:/ProgramData/ssh/known_hosts']);
  assert.deepEqual(parseJump('admin@[::1]:2222'), { username: 'admin', host: '::1', port: 2222 });
  assert.deepEqual(parseJump('bastion'), { username: undefined, host: 'bastion', port: undefined });
  assert.throws(() => parseJump('user@host:99999'), /PROXY_JUMP_INVALID/);
});

test('rejects lossy ssh -G filenames rather than reading or writing the wrong trust store', () => {
  const name = 'userknownhostsfile';
  assert.throws(() => configPaths(new Map([[name, ['C:/Users/Alice Smith/.ssh/known_hosts']]]), name, 'host', 22, 'alice'), /SSH_CONFIG_UNSUPPORTED.*spaces/);
  assert.throws(() => configPaths(new Map([[name, ['/home/alice/known hosts']]]), name, 'host', 22, 'alice'), /SSH_CONFIG_UNSUPPORTED/);
  assert.throws(() => configPaths(new Map([[name, ['C:\\Users\\ Alice\\.ssh\\known_hosts']]]), name, 'host', 22, 'alice'), /SSH_CONFIG_UNSUPPORTED/);
  assert.equal(configPaths(new Map([[name, ['/trusted/known_hosts /trusted/known_hosts2']]]), name, 'host', 22, 'alice').length, 2);
});

test('coalesces RAM password prompts and clears them when the last reference closes', async () => {
  let calls = 0;
  const cache = new SecretCache(async () => { calls += 1; await Promise.resolve(); return 'synthetic'; });
  cache.retain('user:alice');
  cache.retain('user:alice');
  assert.deepEqual(await Promise.all([cache.get('user:alice', 'password', 'Password:'), cache.get('user:alice', 'password', 'Password:')]), ['synthetic', 'synthetic']);
  assert.equal(calls, 1);
  cache.release('user:alice');
  await cache.get('user:alice', 'password', 'Password:');
  assert.equal(calls, 1);
  cache.invalidate('user:alice');
  await cache.get('user:alice', 'password', 'Password:');
  assert.equal(calls, 2);
  cache.release('user:alice');
  cache.retain('user:alice');
  await cache.get('user:alice', 'password', 'Password:');
  assert.equal(calls, 3);
});
