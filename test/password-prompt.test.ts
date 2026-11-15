import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { promptCommands, promptSecret } from '../src/password-prompt.js';
import { windowsPromptScript } from '../src/native-prompt-scripts.js';
import { runProcess } from '../src/process-runner.js';

test('compiles the native Windows Credential UI helper without displaying a prompt', { skip: process.platform !== 'win32' }, async () => {
  const script = windowsPromptScript.replace(/^\[McpSshCredentialPrompt\]::Prompt\(.*$/m, '');
  const result = await runProcess('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], {
    timeout_ms: 30_000, max_output_bytes: 4096,
  });
  assert.equal(result.exit_code, 0, result.stderr.toString());
  assert.equal(result.stdout.length, 0);
});

test('selects desktop providers without depending on a Linux distribution', () => {
  for (const desktop of ['KDE', 'GNOME', 'XFCE', 'LXQt', 'sway']) {
    const providers = promptCommands('SSH', 'Password:', 'linux', { WAYLAND_DISPLAY: 'wayland-0', XDG_CURRENT_DESKTOP: desktop });
    for (const name of ['ssh-askpass', 'ksshaskpass', 'gnome-ssh-askpass', 'lxqt-openssh-askpass', 'zenity', 'kdialog', 'yad']) {
      assert.ok(providers.some((provider) => provider.command === name));
    }
    assert.equal(providers.length, new Set(providers.map((provider) => provider.command)).size);
  }
  assert.equal(promptCommands('SSH', 'Password:', 'linux', { DISPLAY: ':0', SSH_ASKPASS: '/custom/prompt' })[0]!.command, '/custom/prompt');
  assert.throws(() => promptCommands('SSH', 'Password:', 'linux', {}), /GUI_UNAVAILABLE/);
});

test('does not select the MCP helper recursively and supports native non-Linux prompts', () => {
  assert.ok(!promptCommands('SSH', 'Password:', 'linux', {
    DISPLAY: ':0', SSH_ASKPASS: '/app/askpass-client.js', MCP_SSH_OPS_ASKPASS_CLIENT: '/app/askpass-client.js',
  }).some((provider) => provider.command === '/app/askpass-client.js'));
  const windows = promptCommands('SSH', 'Password:', 'win32', {});
  assert.equal(windows[0]!.command, 'powershell.exe');
  assert.ok(windows[0]!.args.includes('-NoProfile'));
  assert.ok(windows[0]!.args.at(-1)!.includes('CredUIPromptForWindowsCredentialsW'));
  const mac = promptCommands('SSH', 'Password:', 'darwin', {});
  assert.equal(mac[0]!.command, '/usr/bin/osascript');
  assert.match(mac[0]!.input!, /hidden answer/);
});

test('honors configured askpass and stops on cancel, failure, or oversized output', { skip: process.platform !== 'linux' }, async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mcp-prompts-'));
  const provider = join(directory, 'askpass');
  const mark = join(directory, 'called');
  const old = { DISPLAY: process.env.DISPLAY, SSH_ASKPASS: process.env.SSH_ASKPASS };
  try {
    process.env.DISPLAY = ':test';
    process.env.SSH_ASKPASS = provider;
    await writeFile(provider, `#!/bin/sh\nprintf 'called' > '${mark}'\nprintf 'synthetic-password\\n'\n`, { mode: 0o700 });
    assert.equal(await promptSecret('SSH', 'Password:'), 'synthetic-password');
    assert.equal(await readFile(mark, 'utf8'), 'called');
    await writeFile(provider, '#!/bin/sh\nexit 1\n');
    await assert.rejects(promptSecret('SSH', 'Password:'), /AUTH_CANCELLED/);
    await writeFile(provider, '#!/bin/sh\nprintf "sensitive diagnostic" >&2\nexit 2\n');
    await assert.rejects(promptSecret('SSH', 'Password:'), (error: Error) => /PASSWORD_PROMPT_FAILED/.test(error.message) && !error.message.includes('sensitive diagnostic'));
    await writeFile(provider, '#!/bin/sh\nhead -c 17000 /dev/zero\n');
    await assert.rejects(promptSecret('SSH', 'Password:'), /PASSWORD_PROMPT_INVALID/);
  } finally {
    for (const [key, value] of Object.entries(old)) {
      if (value === undefined) delete process.env[key]; else process.env[key] = value;
    }
    await rm(directory, { recursive: true, force: true });
  }
});
