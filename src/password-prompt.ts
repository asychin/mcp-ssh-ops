import { spawn } from 'node:child_process';
import { resolve } from 'node:path';
import { ASKPASS_TIMEOUT_MS } from './config.js';
import { McpOpsError } from './errors.js';
import { macOsPromptScript, windowsPromptScript } from './native-prompt-scripts.js';

export interface PromptCommand {
  command: string;
  args: string[];
  input?: string;
}

export function promptCommands(title: string, message: string, platform = process.platform, env = process.env): PromptCommand[] {
  if (platform === 'win32') {
    return [{ command: 'powershell.exe', args: ['-NoLogo', '-NoProfile', '-NonInteractive', '-STA', '-Command', windowsPromptScript] }];
  }
  if (platform === 'darwin') {
    return [{ command: '/usr/bin/osascript', args: ['-', title, message], input: macOsPromptScript }];
  }
  if (platform !== 'linux') throw new McpOpsError('PLATFORM_UNSUPPORTED', `No secret dialog provider for ${platform}.`);
  if (!env.DISPLAY && !env.WAYLAND_DISPLAY) {
    throw new McpOpsError('GUI_UNAVAILABLE', 'Password authentication needs a graphical desktop (DISPLAY or WAYLAND_DISPLAY). Use ssh-agent/key authentication or run MCP from a desktop session.');
  }
  const configured = env.SSH_ASKPASS;
  const system = [configured, 'ssh-askpass', '/usr/bin/ssh-askpass', '/usr/lib/openssh/gnome-ssh-askpass', '/usr/lib/ssh/ssh-askpass']
    .filter((command): command is string => Boolean(command) && (!env.MCP_SSH_OPS_ASKPASS_CLIENT || resolve(command!) !== resolve(env.MCP_SSH_OPS_ASKPASS_CLIENT)))
    .map((command) => ({ command, args: [message] }));
  const ksshaskpass = { command: 'ksshaskpass', args: [message] };
  const zenity = { command: 'zenity', args: ['--password', `--title=${title}`, `--text=${message}`] };
  const kdialog = { command: 'kdialog', args: ['--title', title, '--password', message] };
  const gnome = { command: 'gnome-ssh-askpass', args: [message] };
  const lxqt = { command: 'lxqt-openssh-askpass', args: [message] };
  const yad = { command: 'yad', args: ['--entry', '--hide-text', `--title=${title}`, `--text=${message}`] };
  const desktop = env.XDG_CURRENT_DESKTOP?.toUpperCase() ?? '';
  const preferred = desktop.includes('KDE') ? [kdialog, ksshaskpass]
    : desktop.includes('LXQT') ? [lxqt] : [gnome, zenity];
  const commands = [...system, ...preferred, ksshaskpass, gnome, lxqt, zenity, kdialog, yad];
  return commands.filter((command, index) => commands.findIndex((other) => other.command === command.command) === index);
}

export async function promptSecret(title: string, message: string): Promise<string> {
  const commands = promptCommands(title, message);
  let lastError: unknown;
  for (const command of commands) {
    try {
      return await runPrompt(command, title, message);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
      lastError = error;
    }
  }
  throw new McpOpsError('PASSWORD_PROMPT_UNAVAILABLE', `No password dialog is installed. Configure SSH_ASKPASS or install an askpass provider, kdialog, zenity, or yad. ${String(lastError)}`);
}

function runPrompt({ command, args, input }: PromptCommand, title: string, message: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      detached: process.platform !== 'win32', windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, MCP_SSH_OPS_PROMPT_TITLE: title, MCP_SSH_OPS_PROMPT_MESSAGE: message },
    });
    child.stdin.on('error', () => undefined);
    child.stdin.end(input);
    const chunks: Buffer[] = [];
    let byteLength = 0;
    let settled = false;
    const timer = setTimeout(() => {
      child.kill('SIGTERM');
      finish(new McpOpsError('PASSWORD_PROMPT_TIMEOUT', 'The password dialog timed out.'));
    }, ASKPASS_TIMEOUT_MS);

    const finish = (error?: unknown, value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const chunk of chunks) chunk.fill(0);
      if (error) reject(error);
      else resolve(value ?? '');
    };

    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return;
      byteLength += chunk.length;
      if (byteLength > 16_384) {
        child.kill('SIGTERM');
        finish(new McpOpsError('PASSWORD_PROMPT_INVALID', 'The password dialog returned too much data.'));
        return;
      }
      chunks.push(Buffer.from(chunk));
    });
    child.stderr.resume();
    child.once('error', (error) => finish(error));
    child.once('close', (code) => {
      if (code === 0) {
        const buffer = Buffer.concat(chunks);
        const secret = buffer.toString('utf8').replace(/\r?\n$/, '');
        buffer.fill(0);
        if (!secret) finish(new McpOpsError('EMPTY_PASSWORD', 'The password dialog returned an empty value.'));
        else finish(undefined, secret);
      } else if (code === 1) {
        finish(new McpOpsError('AUTH_CANCELLED', 'Password entry was cancelled by the operator.'));
      } else {
        finish(new McpOpsError('PASSWORD_PROMPT_FAILED', `The password dialog exited with code ${code}. Check the desktop session and provider configuration.`));
      }
    });
  });
}
