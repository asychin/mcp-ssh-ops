#!/usr/bin/env node
import { spawn } from 'node:child_process';
import { createConnection } from 'node:net';

const prompt = process.argv[2] ?? '';
const hostKeyPrompt = /authenticity of host/i.test(prompt) && /SHA256:[A-Za-z0-9+/]+/.test(prompt);
const brokerAllPrompts = process.env.MCP_SSH_OPS_ASKPASS_MODE === 'broker';

if (!hostKeyPrompt && !brokerAllPrompts) {
  process.exitCode = await runNativeAskpass(prompt);
} else {
  const socketPath = process.env.MCP_SSH_OPS_ASKPASS_SOCKET;
  const contextId = process.env.MCP_SSH_OPS_ASKPASS_CONTEXT;
  if (!socketPath || !contextId || prompt.length > 32_768) {
    process.exitCode = 1;
  } else {
    process.exitCode = await requestBroker(socketPath, contextId, prompt);
  }
}

async function runNativeAskpass(message: string): Promise<number> {
  const ksshaskpass = { command: 'ksshaskpass', args: [message] };
  const zenity = { command: 'zenity', args: ['--password', '--title=MCP SSH Ops', `--text=${message}`] };
  const kdialog = { command: 'kdialog', args: ['--title', 'MCP SSH Ops', '--password', message] };
  const commands = process.env.XDG_CURRENT_DESKTOP?.toUpperCase().includes('KDE')
    ? [ksshaskpass, kdialog, zenity]
    : [zenity, ksshaskpass, kdialog];
  for (const { command, args } of commands) {
    const result = await runDialog(command, args);
    if (result.missing) continue;
    if (result.code === 0) process.stdout.write(result.stdout);
    return result.code;
  }
  return 1;
}

function runDialog(command: string, args: string[]): Promise<{ code: number; stdout: Buffer; missing: boolean }> {
  return new Promise((resolve) => {
    const child = spawn(command, args, { env: process.env, stdio: ['ignore', 'pipe', 'ignore'] });
    const chunks: Buffer[] = [];
    child.stdout.on('data', (chunk: Buffer) => chunks.push(chunk));
    child.once('error', (error: NodeJS.ErrnoException) => resolve({ code: 1, stdout: Buffer.alloc(0), missing: error.code === 'ENOENT' }));
    child.once('close', (code) => resolve({ code: code ?? 1, stdout: Buffer.concat(chunks), missing: false }));
  });
}

function requestBroker(socketPath: string, contextId: string, message: string): Promise<number> {
  return new Promise((resolve) => {
    const socket = createConnection(socketPath);
    let response = '';
    let finished = false;
    const finish = (code: number) => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(code);
    };
    const timer = setTimeout(() => finish(1), 125_000);
    socket.setEncoding('utf8');
    socket.once('connect', () => socket.write(`${JSON.stringify({ context_id: contextId, prompt: message })}\n`));
    socket.on('data', (chunk: string) => {
      response += chunk;
      if (response.length > 65_536) finish(1);
    });
    socket.once('error', () => finish(1));
    socket.once('end', () => {
      try {
        const parsed = JSON.parse(response) as { ok?: boolean; value?: string };
        if (!parsed.ok || typeof parsed.value !== 'string') {
          finish(1);
          return;
        }
        process.stdout.write(`${parsed.value}\n`);
        finish(0);
      } catch {
        finish(1);
      }
    });
  });
}
