#!/usr/bin/env node
import { createConnection } from 'node:net';
import { promptSecret } from './password-prompt.js';

const prompt = process.argv[2] ?? '';
const hostKeyPrompt = /authenticity of host/i.test(prompt) && /SHA256:[A-Za-z0-9+/]+/.test(prompt);
const brokerAllPrompts = process.env.MCP_SSH_OPS_ASKPASS_MODE === 'broker';

if (!hostKeyPrompt && !brokerAllPrompts) {
  process.env.SSH_ASKPASS = process.env.MCP_SSH_OPS_NATIVE_ASKPASS ?? '';
  try {
    process.stdout.write(`${await promptSecret('MCP SSH Ops', prompt)}\n`);
  } catch {
    process.exitCode = 1;
  }
} else {
  const socketPath = process.env.MCP_SSH_OPS_ASKPASS_SOCKET;
  const contextId = process.env.MCP_SSH_OPS_ASKPASS_CONTEXT;
  if (!socketPath || !contextId || prompt.length > 32_768) {
    process.exitCode = 1;
  } else {
    process.exitCode = await requestBroker(socketPath, contextId, prompt);
  }
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
