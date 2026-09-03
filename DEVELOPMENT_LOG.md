# Development log

This file should be read at the start of the next development session and updated after significant changes.

## 2026-08-20 — first working version

### Goal

Create a local MCP server for persistent SSH sessions, safe command execution, and remote file operations.

### Operator decisions

- Live SSH sessions are isolated per agent/MCP process.
- Non-secret connection profiles can be shared.
- Passwords are requested via a local GUI dialog and stored only in RAM.
- The first version includes sessions, clone, exec, SFTP read/list/stat, and patch editing.

### Implemented architecture

- Node.js/TypeScript, ESM, stdio, and the official MCP SDK v2.
- `ssh2` holds one multiplexed SSH transport per session; commands and SFTP use separate channels within it.
- Supports `ssh-agent`, private key, encrypted key with GUI passphrase prompt, and password with GUI prompt.
- Secrets are never accepted as MCP arguments and never written to disk.
- Host keys are verified against app-level, user, and system `known_hosts`.
- An unknown key is stored in memory as pending and requires a separate `ssh_trust_host` call with the exact fingerprint.
- Changed and revoked host keys are blocked without automatic bypass.
- Profiles and app-trusted keys are located in `~/.config/mcp-ops` by default.
- `ssh_exec` runs without PTY, closes stdin, limits time and output volume.
- SFTP read uses ranges and limits; list limits the number of entries.
- Patch-edit requires SHA-256 of the current file, accepts a strict unified diff, re-verifies the file before replacing, preserves mode, creates a backup by default, and prefers OpenSSH POSIX rename.

### MCP tools

- `ssh_save_profile`
- `ssh_list_profiles`
- `ssh_create_session`
- `ssh_trust_host`
- `ssh_list_sessions`
- `ssh_session_info`
- `ssh_clone_session`
- `ssh_close_session`
- `ssh_exec`
- `ssh_stat`
- `ssh_list_directory`
- `ssh_read_file`
- `ssh_apply_patch`

### Checks

Successfully completed:

```text
npm run typecheck
npm test
npm run build
npm audit --omit=dev
```

Test results: 12 passed, 0 failed.

Covered:

- plain and hashed `known_hosts`, unknown/trust, changed and revoked keys;
- saving profiles without secrets;
- shell quoting for cwd/env;
- SHA-256 guarded patch and backup;
- tool list via in-memory MCP client;
- local SSH server: multiple commands over a single transport;
- clone as a separate transport;
- password auth handler with a single safe prompt and secret reuse in clone.

A separate smoke test ran the built `dist/index.js` over a real stdio transport: 13 tools published, `ssh_list_sessions` executed successfully.

Production `npm audit`: 0 known vulnerabilities.

### Devin configuration

The server is registered in the project's local scope:

```text
.devin/mcp_config.local.json
node /path/to/mcp-ssh-ops/dist/index.js
```

The `devin mcp list` command shows `mcp-ssh-ops`. A new client/agent session is needed for the tools to appear in the agent.

### Real-world verification 2026-08-20

- MCP successfully connected to a remote SSH server with password authentication.
- The operator explicitly confirmed the ED25519 host fingerprint; the key was written to a separate `~/.config/mcp-ops/known_hosts`.
- A GUI issue was found: on KDE/Wayland, Zenity was launched first but the window did not appear. For KDE, priority was switched to KDialog.
- After the fix, typecheck, 12 tests, and build passed again; a real KDialog window appeared and password authentication completed successfully.
- SFTP and exec were verified through a single persistent SSH session. The path `/opt/express` does not exist on the server; directories `pbis` and `spoa-modsec` were found in `/opt`.
- Secrets and live session IDs were not written to the log.

### Current state

The first version is ready and verified against a real external SSH server. Active connections still belong only to the specific agent's MCP process.

## 2026-08-20 — switch to native OpenSSH 0.2.0

### Operator decision

Fully switch from the `ssh2` runtime library to system OpenSSH with `ControlMaster` and native `ProxyJump` support.

### Implementation

- Profiles source became `~/.ssh/mcp-ops/config`; `ssh_save_profile` writes OpenSSH Host blocks, and `ssh_list_profiles` reads literal aliases and resolves them via `ssh -G`.
- Supports `Include`, `Match`, `ProxyJump`, multi-hop, `IdentityFile`, certificates, hardware keys, and OpenSSH's own agent settings.
- Isolated trust store moved to `~/.ssh/mcp-ops/known_hosts`; legacy profiles/known_hosts are copied on first initialization without removing old files.
- Each MCP session creates a separate `ssh -MNf` master and control socket in a process-specific runtime directory.
- Exec and SFTP open only multiplexed channels through the existing master.
- Clone creates a separate master and reuses the password/passphrase only from the RAM askpass broker.
- The askpass helper communicates with MCP via a 0600 Unix socket; secrets never enter arguments, environment, MCP protocol, or files.
- Unknown host-key prompts are intercepted by the askpass broker and rejected. After exact approval, the next connect allows OpenSSH to write only the confirmed key.
- Jump host and target are verified and authenticated independently; agent forwarding remains disabled.
- Per-process runtime provides agent isolation. A heartbeat keeps masters alive, and `ControlPersist=300` limits orphan processes after abnormal termination.
- File stat/list/range use bounded binary-safe OpenSSH exec channels; transfer, backup, and rename use native SFTP.

### Automated checks

Typecheck, build, production audit, and 16 tests passed successfully:

- native ControlMaster and multiple exec over a single TCP/SSH connection;
- separate master for clone;
- host key pending/approve/write;
- password via askpass and RAM reuse without a second prompt;
- real end-to-end ProxyJump through a local bastion `direct-tcpip` to target;
- independent fingerprints for jump host and target;
- OpenSSH config save/list/Include/`ssh -G`/legacy migration;
- native stat/list/ranged read and SFTP patch workflow;
- stdio smoke: 13 MCP tools and isolated OpenSSH config initialization.

Production `npm audit`: 0 known vulnerabilities.

### Current state

Backend 0.2.0 is built and automatically verified. The Devin configuration was temporarily disabled before a controlled launch of the new version. Remaining: enable MCP, create a test Host, verify real ControlMaster/exec/SFTP on a remote server, and record the result.

## 2026-08-21 — user OpenSSH config and real-world verification

### Architecture fix

The operator required using the standard user `~/.ssh/config`, `known_hosts`, and keys instead of a separate `~/.ssh/mcp-ops`.

This revealed the root cause of previous auth errors: the user config resolves an alias to an internal hostname, while the isolated config connected directly to a different public SSH endpoint. Manual OpenSSH therefore worked with a different target.

Changes:

- default source switched to `~/.ssh/config` and `~/.ssh/known_hosts`;
- `Include`, `Match`, `HostName`, identity, certificate, ProxyJump, and auth options are fully taken from the user config via `ssh -G`;
- only per-process control sockets and the askpass Unix socket in `XDG_RUNTIME_DIR` remain separate;
- `MCP_SSH_OPS_SSH_CONFIG`, `MCP_SSH_OPS_KNOWN_HOSTS`, and `MCP_SSH_OPS_SSH_DIR` allow overriding paths;
- the separate `~/.ssh/mcp-ops` is no longer used or removed automatically;
- the initial master is created by a regular `ControlMaster=auto` connection with remote `true`, then kept alive via `ControlPersist=300`;
- password/passphrase are passed directly through the native askpass; the broker handles host-key approval;
- fixed a Unix socket half-close race where a slow GUI response could be lost;
- MCP cancellation terminates the child process; UI cancellation no longer leaves a pending ssh;
- `ssh -G` value `ConnectTimeout none` is correctly converted to the default 30000 ms.

### Test safety

After the first transitional run, four localhost host keys from test SSH servers ended up in the user's `known_hosts`. With the operator's explicit permission, only those four lines were removed. Tests were fixed: each uses a separate temporary `UserKnownHostsFile`. A recheck showed 0 localhost entries in the user's file.

### Checks

- 18 tests passed, 0 failed;
- separate end-to-end ProxyJump test through bastion `direct-tcpip`;
- production askpass passthrough test;
- existing user config/known_hosts preservation test;
- process cancellation test;
- typecheck and build successful.

### Real server

- `ssh_list_profiles` read the user config and resolved a host alias to its internal hostname;
- created native ControlMaster `test-native`, PID 352393;
- exec via master returned the remote hostname and user;
- native directory list showed application config files on the server;
- created independent clone-master `test-native-clone`, PID 352441;
- exec via clone successfully returned `clone-ok`;
- `dpl.env` was not read due to likely secrets;
- session IDs and secrets were not written to the log.

## 2026-08-21 — shorthand host and RAM credential scope

The operator fixed the expected semantics of natural-language requests:

- host without login means an existing literal `Host` from `~/.ssh/config`;
- host with login is still first resolved via `ssh -G`, then only the explicitly given `User` and other explicit fields are overridden;
- a single SSH username's password should be reused for other sessions without a new prompt.

Implemented:

- `ssh_create_session(host="my-server")` without username finds the alias in the user config;
- an unknown alias without username returns `PROFILE_NOT_FOUND` instead of trying to guess the user;
- `host + username` preserves resolved HostName/Port/ProxyJump/IdentityFile/Match and adds a command-line User override;
- create input no longer gets implicit defaults from the schema, so config values and explicit overrides are distinguishable;
- credential group has scope `user:<username>`;
- password prompts within the scope are cached in RAM and reused by independent sessions of the same user;
- prompts for different usernames and passphrases for different keys are separated;
- `Permission denied` invalidates the cache so the next attempt prompts again;
- closing the last session of a scope clears the secret;
- KDE GUI is launched in a separate process session (`detached`), which fixed the invisible KDialog from the MCP broker.

Real-world verification:

- first `host="my-server"` showed one KDialog window and created `test-by-host`, PID 355538;
- second `host="my-server", username="admin"` created independent `test-by-user-host`, PID 355557, without a second window;
- both sessions resolved to the same internal hostname;
- parallel exec successfully returned the target hostname.

### Current state

Backend 0.2.0 works with the user's OpenSSH config, shorthand host resolution, and RAM password reuse by username. Active sessions `test-by-host` and `test-by-user-host` were left in the current MCP process.

### Global Devin registration

`mcp-ops` was added to the user scope:

```text
~/.config/devin/mcp_config.json
node /path/to/mcp-ssh-ops/dist/index.js
```

Now new Devin sessions see the server regardless of the current working directory. The project-local configuration was also kept for compatibility.

## 2026-08-21 — upload/download

By operator decision, both file transfer directions were added:

- `ssh_upload_file`: local → remote;
- `ssh_download_file`: remote → local.

Policy:

- default local roots: the MCP process workspace and `/tmp`;
- additional roots: `MCP_SSH_OPS_LOCAL_ROOTS`;
- default transfer limit: 100 MiB, override via `MCP_SSH_OPS_MAX_TRANSFER_BYTES`;
- symlinks, directories, and known credential directories are blocked locally;
- overwrite is forbidden by default;
- `overwrite=true` creates a backup of the destination first;
- upload uses remote temp + SFTP rename;
- download uses temp in the local destination directory + atomic rename;
- SHA-256 is verified before and after transfer;
- optional expected hashes are used as a precondition;
- transfer works through the SFTP channel of the existing ControlMaster.

Checks:

- total test suite grew to 20 tests;
- unit/integration cover upload/download, hashes, overwrite guards, local/remote backups, local root escape, and symlink rejection;
- real smoke via a remote server: a 35-byte file was uploaded to remote `/tmp`, downloaded back, SHA-256 matched;
- created smoke files local/remote were removed after verification;
- active session `exp-transfer-test` was left open.

## 2026-08-24 — visual session target identification

The operator noticed that the MCP UI showed only a UUID in `ssh_exec` and the target could not be determined from the card.

Changes:

- public session ID now has the format `name | alias -> user@resolved-host:port | short-token`;
- the control socket still uses an internal UUID and does not depend on the display ID;
- MCP schema no longer constrains the session ID to UUID format;
- `ssh_exec` returns an explicit `session` block before stdout/stderr;
- session metadata is added to all file operations and the close result;
- metadata contains name, alias, target, resolved host, port, username, and ProxyJump;
- tests verify the readable ID and exec session metadata.

Real-world verification:

- created session `visual-check` for a host alias;
- UI-visible ID contains the alias and resolved target;
- `ssh_exec` output contains session metadata and successfully returned the remote hostname;
- `visual-check` was left active.

### Possible next features

- a separate safe mechanism for commands requiring `sudo`;
- explicit deletion/renaming of Host profiles;
- automatic reconnect after network failure;
- a separate shared daemon only if the operator later deliberately wants to share live sessions between agents.
