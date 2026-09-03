import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { buildRemoteCommand, shellQuote } from '../src/ssh/shell.js';

const execFileAsync = promisify(execFile);

test('quotes single quotes safely', () => {
  assert.equal(shellQuote("a'b"), `'a'"'"'b'`);
});

test('builds cwd and environment wrappers without command injection', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp ops shell-'));
  try {
    const value = `value'; printf injected`;
    const command = buildRemoteCommand('printf %s "$VALUE"; printf :; pwd', directory, { VALUE: value });
    const { stdout } = await execFileAsync('/bin/sh', ['-c', command]);
    assert.equal(stdout, `${value}:${directory}\n`);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
