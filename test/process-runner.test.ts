import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runProcess } from '../src/process-runner.js';

test('terminates a child process when the MCP request is cancelled', async () => {
  const controller = new AbortController();
  const startedAt = Date.now();
  const operation = runProcess('sleep', ['10'], {
    signal: controller.signal,
    timeout_ms: 15_000,
    max_output_bytes: 1_024,
  });
  setTimeout(() => controller.abort(), 50);
  await assert.rejects(operation, (error: Error) => error.name === 'AbortError');
  assert.ok(Date.now() - startedAt < 2_000);
});
