import assert from 'node:assert/strict';
import { mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { LocalPathPolicy } from '../src/local-path-policy.js';

test('allows regular files inside roots and rejects escapes and symlinks', async () => {
  const root = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-root-'));
  const outside = await mkdtemp(join(tmpdir(), 'mcp-ssh-ops-outside-'));
  try {
    const insideFile = join(root, 'inside.txt');
    const outsideFile = join(outside, 'outside.txt');
    const link = join(root, 'link.txt');
    await writeFile(insideFile, 'inside');
    await writeFile(outsideFile, 'outside');
    await symlink(outsideFile, link);
    const policy = new LocalPathPolicy([root]);
    assert.equal((await policy.sourceFile(insideFile)).path, insideFile);
    assert.equal((await policy.destinationFile(join(root, 'new.txt'))).stats, undefined);
    await assert.rejects(policy.sourceFile(outsideFile), /LOCAL_PATH_DENIED/);
    await assert.rejects(policy.sourceFile(link), /LOCAL_SYMLINK_REJECTED/);
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
