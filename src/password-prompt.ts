import { spawn } from 'node:child_process';
import { McpOpsError } from './errors.js';

interface PromptCommand {
  command: string;
  args: string[];
}

export async function promptSecret(title: string, message: string): Promise<string> {
  if (!process.env.DISPLAY && !process.env.WAYLAND_DISPLAY) {
    throw new McpOpsError('GUI_UNAVAILABLE', 'Password authentication needs a graphical session with DISPLAY or WAYLAND_DISPLAY. Use ssh-agent/key authentication or run from a desktop session.');
  }

  const ksshaskpass = { command: 'ksshaskpass', args: [message] };
  const zenity = { command: 'zenity', args: ['--password', `--title=${title}`, `--text=${message}`] };
  const kdialog = { command: 'kdialog', args: ['--title', title, '--password', message] };
  const commands: PromptCommand[] = process.env.XDG_CURRENT_DESKTOP?.toUpperCase().includes('KDE')
    ? [kdialog, ksshaskpass, zenity]
    : [zenity, ksshaskpass, kdialog];
  let lastError: unknown;
  for (const command of commands) {
    try {
      return await runPrompt(command);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      lastError = error;
    }
  }
  throw new McpOpsError('PASSWORD_PROMPT_UNAVAILABLE', `No supported askpass dialog is available: ${String(lastError)}`);
}

function runPrompt({ command, args }: PromptCommand): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { detached: true, stdio: ['ignore', 'pipe', 'pipe'], env: process.env });
    const chunks: Buffer[] = [];
    let byteLength = 0;
    let stderr = '';
    let settled = false;
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new McpOpsError('PASSWORD_PROMPT_TIMEOUT', 'The password dialog timed out.'));
    }, 120_000);

    const finish = (error?: unknown, value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value ?? '');
    };

    child.stdout.on('data', (chunk: Buffer) => {
      byteLength += chunk.length;
      if (byteLength > 16_384) {
        child.kill('SIGTERM');
        finish(new McpOpsError('PASSWORD_PROMPT_INVALID', 'The password dialog returned too much data.'));
        return;
      }
      chunks.push(chunk);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < 4096) stderr += chunk.toString('utf8');
    });
    child.once('error', (error) => finish(error));
    child.once('close', (code) => {
      if (code === 0) {
        const secret = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
        if (!secret) finish(new McpOpsError('EMPTY_PASSWORD', 'The password dialog returned an empty value.'));
        else finish(undefined, secret);
      } else if (code === 1) {
        finish(new McpOpsError('AUTH_CANCELLED', 'Password entry was cancelled by the operator.'));
      } else {
        finish(new McpOpsError('PASSWORD_PROMPT_FAILED', `${command} exited with code ${code}: ${stderr.trim()}`));
      }
    });
  });
}
