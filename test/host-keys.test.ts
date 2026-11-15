import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import ssh2 from 'ssh2';
import { HostKeyStore, canonicalHost } from '../src/ssh/host-keys.js';
import { sshFingerprint } from '../src/ssh/fingerprint.js';
import { testKeyPair } from './helpers.js';

const { utils } = ssh2;

function publicKey() {
  const pair = testKeyPair();
  const parsed = utils.parseKey(pair.private);
  assert.ok(!(parsed instanceof Error));
  return { type: parsed.type, key: parsed.getPublicSSH() };
}

test('verifies plain and hashed known_hosts entries and detects changed keys', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-hosts-'));
  try {
    const knownHosts = join(directory, 'known_hosts');
    const first = publicKey();
    const second = publicKey();
    const host = canonicalHost('example.test', 2222);
    const salt = Buffer.from('test-salt');
    const hash = createHmac('sha1', salt).update(host).digest('base64');
    await writeFile(knownHosts, `|1|${salt.toString('base64')}|${hash} ${first.type} ${first.key.toString('base64')}\n`);
    const store = new HostKeyStore(knownHosts, [knownHosts]);
    await store.refresh();
    assert.equal(store.verify('example.test', 2222, first.key).status, 'trusted');
    assert.equal(store.verify('example.test', 2222, second.key).status, 'changed');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('persists only an explicitly pending unknown host key', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-trust-'));
  try {
    const appKnownHosts = join(directory, 'known_hosts');
    const hostKey = publicKey();
    const store = new HostKeyStore(appKnownHosts, [appKnownHosts]);
    await store.refresh();
    const pending = store.rememberUnknown('new.example.test', 22, hostKey.key);
    assert.equal(pending.status, 'unknown');
    assert.equal(pending.fingerprint, sshFingerprint(hostKey.key));
    const trusted = await store.trustPending('new.example.test', 22, pending.fingerprint);
    assert.equal(trusted.status, 'trusted');
    const content = await readFile(appKnownHosts, 'utf8');
    assert.match(content, new RegExp(`^new\\.example\\.test ${hostKey.type} `));
    await assert.rejects(
      store.trustPending('new.example.test', 22, pending.fingerprint),
      /HOST_KEY_NOT_PENDING/,
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('rejects revoked keys', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-revoked-'));
  try {
    const knownHosts = join(directory, 'known_hosts');
    const hostKey = publicKey();
    await writeFile(knownHosts, `@revoked revoked.test ${hostKey.type} ${hostKey.key.toString('base64')}\n`);
    const store = new HostKeyStore(knownHosts, [knownHosts]);
    await store.refresh();
    assert.equal(store.verify('revoked.test', 22, hostKey.key).status, 'revoked');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
