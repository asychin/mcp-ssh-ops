import { spawn } from 'node:child_process';

export interface ProcessResult {
  exit_code: number | null;
  signal: NodeJS.Signals | null;
  stdout: Buffer;
  stderr: Buffer;
  timed_out: boolean;
  output_truncated: boolean;
  duration_ms: number;
}

export interface ProcessOptions {
  input?: string | Buffer;
  env?: NodeJS.ProcessEnv;
  signal?: AbortSignal;
  timeout_ms: number;
  max_output_bytes: number;
}

export function runProcess(command: string, args: string[], options: ProcessOptions): Promise<ProcessResult> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(abortError());
      return;
    }
    const startedAt = Date.now();
    const child = spawn(command, args, {
      env: options.env ?? process.env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let storedBytes = 0;
    let outputTruncated = false;
    let timedOut = false;
    let aborted = false;
    let settled = false;
    let killTimer: NodeJS.Timeout | undefined;

    const append = (target: Buffer[], chunk: Buffer) => {
      const remaining = options.max_output_bytes - storedBytes;
      if (remaining <= 0) {
        outputTruncated = true;
        return;
      }
      const accepted = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
      target.push(Buffer.from(accepted));
      storedBytes += accepted.length;
      if (accepted.length < chunk.length) outputTruncated = true;
    };
    const finish = (error?: Error, exitCode: number | null = null, signal: NodeJS.Signals | null = null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (killTimer) clearTimeout(killTimer);
      options.signal?.removeEventListener('abort', onAbort);
      if (error) {
        reject(error);
        return;
      }
      resolve({
        exit_code: exitCode,
        signal,
        stdout: Buffer.concat(stdout),
        stderr: Buffer.concat(stderr),
        timed_out: timedOut,
        output_truncated: outputTruncated,
        duration_ms: Date.now() - startedAt,
      });
    };
    const terminate = () => {
      child.kill('SIGTERM');
      killTimer ??= setTimeout(() => child.kill('SIGKILL'), 1_000);
    };
    const onAbort = () => {
      aborted = true;
      terminate();
    };
    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, options.timeout_ms);
    options.signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout.on('data', (chunk: Buffer) => append(stdout, chunk));
    child.stderr.on('data', (chunk: Buffer) => append(stderr, chunk));
    child.once('error', (error) => finish(error));
    child.once('close', (code, signal) => finish(aborted ? abortError() : undefined, code, signal));
    if (options.input !== undefined) child.stdin.end(options.input);
    else child.stdin.end();
  });
}

function abortError(): Error {
  const error = new Error('Operation cancelled by the MCP client.');
  error.name = 'AbortError';
  return error;
}
