# MCP SSH Ops

A local MCP server for DevOps tasks over persistent SSH connections. Linux/macOS use native OpenSSH `ControlMaster`; Windows uses the `ssh2` Node.js library. Each MCP session authenticates once; commands and file operations open additional channels on that transport without repeated TCP/SSH handshakes.

## Features

- Multiple concurrent SSH sessions with human-readable IDs and names; separate master PIDs on Linux/macOS.
- Native OpenSSH config resolution via `ssh -G` on every platform; full OpenSSH behavior on Linux/macOS and explicit unsupported-setting errors on Windows.
- Native `Host`, `HostName`, `Include`, `Match`, `ProxyJump`, multi-hop, `IdentityFile`, SSH certificates, hardware keys, and `ssh-agent`.
- Clone as a separate independent ControlMaster.
- Passwords and passphrases go through a local askpass broker, stored only in the MCP process RAM and never sent to the agent.
- Unknown host fingerprints require explicit confirmation; changed keys are blocked.
- Exec without PTY and stdin, with timeout and output limit.
- Stat, bounded list, range read, and hash-guarded patch edit with backup.
- Isolation of live sessions across different MCP processes.

## SSH Configuration Source

By default, MCP SSH Ops uses the standard user files:

```text
~/.ssh/config
~/.ssh/known_hosts
~/.ssh/id_*
```

All key paths, `ProxyJump`, aliases, and special parameters are taken from `~/.ssh/config` via the system `ssh -G` command.

For example, with this configuration:

```sshconfig
Host my-server
    HostName 10.0.0.42
    User admin
    Port 22
```

calling `ssh_create_session(profile_name="my-server")` connects to `10.0.0.42`, not directly to the public DNS address.

Paths can be overridden with environment variables:

```text
MCP_SSH_OPS_SSH_CONFIG
MCP_SSH_OPS_KNOWN_HOSTS
MCP_SSH_OPS_SSH_DIR
MCP_SSH_OPS_LOCAL_ROOTS
MCP_SSH_OPS_MAX_TRANSFER_BYTES
```

The legacy experimental directory `~/.ssh/mcp-ssh-ops` is no longer used automatically and is not removed.

## Server List

`ssh_list_profiles` reads literal `Host` aliases from `~/.ssh/config` and `Include` files, then resolves each one via `ssh -G`.

Wildcard sections like `Host *.internal` are applied by OpenSSH but are not listed as individual servers.

`ssh_save_profile` writes or replaces a single `Host` block directly in the user's `~/.ssh/config`. It does not automatically modify multi-pattern blocks.

## How MCP Resolves Addresses

The operator phrase:

```text
Connect to my-server
```

means calling `ssh_create_session(host="my-server")`. Without a username, MCP requires a literal `Host my-server` in the user's config and applies it as-is.

The phrase:

```text
Connect as root to my-server
```

means `host="my-server", username="root"`. MCP SSH Ops still runs `ssh -G my-server` first, preserves `HostName`, `Port`, `ProxyJump`, `IdentityFile`, `Match`, and other settings, then overrides only `User`.

If the host is missing from the config, connecting without a username is rejected and the agent asks the user. With an explicit username, a regular hostname/IP is allowed with `Host *` and matching wildcard sections applied.

## Jump Host

Example:

```sshconfig
Host bastion
    HostName bastion.example.com
    User jump-admin
    IdentityFile ~/.ssh/id_ed25519

Host internal-db
    HostName 10.20.30.40
    User dbadmin
    ProxyJump bastion
```

For multiple hops:

```sshconfig
Host deep-server
    HostName 10.50.0.15
    User operator
    ProxyJump edge-bastion,internal-bastion
```

When connecting, OpenSSH applies each hop's settings independently, verifies the jump host and target separately, and opens `direct-tcpip`. Agent forwarding is not enabled by default by MCP SSH Ops.

## Session Creation

The agent calls:

```text
ssh_create_session(profile_name="internal-db", session_name="production")
```

Internally, the first safe connection is established:

```text
ssh -S <control-socket> -o ControlMaster=auto -o ControlPersist=300 ... <Host> true
```

The `true` command is only needed for initial authentication. After it, OpenSSH keeps the master alive.

If the key is already in the agent, no prompt appears. Otherwise a local graphical password dialog is used. On Windows, keys must already be loaded in an agent; MCP does not read private keys.

### Desktop password dialogs

Linux selection is based on the available desktop tools, not the distribution:

1. The `SSH_ASKPASS` inherited when MCP starts, then a system `ssh-askpass` helper.
2. Desktop-preferred helpers (KDialog on KDE, GNOME askpass/Zenity, LXQt askpass).
3. Remaining installed providers: `ksshaskpass`, `gnome-ssh-askpass`, `lxqt-openssh-askpass`, Zenity, KDialog, and Yad.

Both Wayland and X11 are supported when the selected helper supports the running display server. The graphical session environment must be inherited by the MCP process. Install a compatible helper if none is present. Missing executables try the next provider; cancellation or failure stops immediately instead of opening another password window.

Windows uses Windows Credential UI via Windows PowerShell, without saving credentials. The password applies to the SSH username resolved from the profile, not the editable username field in the Windows dialog. macOS uses an AppleScript dialog with a hidden answer; it does not access or save to Keychain.

Helpers are launched without a shell, with a two-minute timeout and bounded output. Secrets return over a private child-process pipe, never MCP stdio, arguments, environment variables, or temporary files. The MCP cache is RAM-only; a user-selected external askpass helper may have its own wallet/storage policy.

### Windows transport compatibility

Windows still needs `ssh.exe` for `ssh -G` (including `Include` and `Match` resolution), but does not require ControlMaster or a Unix askpass socket. Each session owns one `ssh2` transport; commands and SFTP use separate channels. A clone owns an independent transport.

Supported: passwords, keyboard-interactive prompts, agent authentication (including the Windows OpenSSH agent named pipe), literal Host aliases, explicit User/Port overrides, ProxyJump chains, configured user/global known_hosts, hashed/revoked host keys, and supported algorithm restrictions. OTP/other interactive challenges are not cached as passwords.

Private key files are never read by MCP. Load keys with `ssh-add` first. Custom `IdentityFile` settings, `IdentitiesOnly`, explicit certificates, ProxyCommand, agent forwarding, and other non-default OpenSSH settings that cannot be preserved are rejected with `SSH_CONFIG_UNSUPPORTED`, not silently ignored. Certificate-only host-key policies are rejected; the backend does not implement OpenSSH host-certificate validation. Host trust always requires explicit approval; automatic host-key rotation is not performed. Use the existing OpenSSH backend inside WSL when full OpenSSH feature parity is required.

## Host Key Verification

OpenSSH reads the standard `UserKnownHostsFile` and `GlobalKnownHostsFile`, including overrides from the config.

On an unknown key:

1. The askpass helper intercepts only the host-confirmation prompt.
2. MCP returns the host, port, key type, and SHA-256 fingerprint.
3. The operator verifies the fingerprint via a trusted source.
4. After `ssh_trust_host`, the next connect allows OpenSSH to write the confirmed key.
5. Changed host keys are never replaced automatically.

If the server was legitimately reinstalled, it's best to remove the old entry specifically:

```bash
ssh-keygen -R hostname
ssh-keygen -R '[hostname]:port'
```

Deleting the entire `known_hosts` disables the accumulated protection against spoofing of all previously known servers.

## Passwords and Secrets

- A password cannot be passed as an MCP argument or written in chat.
- GUI password flows through `KDialog/ksshaskpass → RAM askpass broker → helper stdout → ssh`.
- MCP does not log or persist the password to disk.
- The cache is grouped by SSH username. While an active session exists for that user, new sessions reuse the same password without a new prompt.
- Password prompts for different users and passphrases for different keys are stored separately.
- If another server rejects the cached password, the corresponding RAM cache is cleared and the next attempt shows the prompt again.
- When the last session of a credential scope closes, the secret is removed from the cache; MCP termination clears all secrets.
- Keys are never copied or read by MCP: OpenSSH gets paths from the user's config.

## File Transfer

Regular files are supported in both directions:

```text
ssh_upload_file    local → remote
ssh_download_file  remote → local
```

Both operations use SFTP channels of the existing SSH transport and do not create a new SSH connection.

Safety rules:

- locally, the current workspace and `/tmp` are allowed;
- additional roots are set via `MCP_SSH_OPS_LOCAL_ROOTS` using the system path delimiter;
- `.ssh`, `.gnupg`, password stores, and keyring directories are blocked;
- symlinks are not followed for either source or existing destination;
- only regular files are copied, not directories;
- default limit is 100 MiB, overridable via `MCP_SSH_OPS_MAX_TRANSFER_BYTES`;
- an existing destination is not modified without `overwrite=true`;
- on overwrite, a backup is created next to the destination first;
- upload uses a remote temporary file and rename;
- download uses a local temporary file and atomic local rename;
- SHA-256 is verified before and after transfer;
- optional expected hashes protect against concurrent modification of source/destination.

Example:

```text
Upload ./nginx.conf via the production session to /tmp/nginx.conf without overwriting the existing file.
```

```text
Download /var/log/app.log to /tmp/app.log; if the file already exists, create a backup and replace it.
```

## Session Visual Identification

The public `session_id` contains a readable route, not a bare UUID:

```text
random-coffee | my-server -> admin@10.0.0.42:22 | 1af07a42
```

So the target is visible right in the `ssh_exec` arguments card before the command runs.

Every session operation result additionally contains:

```json
{
  "session": {
    "session_id": "...",
    "name": "random-coffee",
    "ssh_alias": "my-server",
    "target": "admin@10.0.0.42:22",
    "host": "10.0.0.42",
    "port": 22,
    "username": "admin",
    "proxy_jump": null
  }
}
```

Metadata is included in exec, stat/list/read, upload/download, patch, and close results.

## Tools

| Tool | Purpose |
|---|---|
| `ssh_save_profile` | Write/replace a single Host block |
| `ssh_list_profiles` | Show Host aliases and resolved parameters |
| `ssh_create_session` | Create a persistent SSH transport |
| `ssh_trust_host` | Approve a specific pending fingerprint |
| `ssh_list_sessions` | Show the current agent's sessions |
| `ssh_session_info` | Show target, ProxyJump, backend, PID (if applicable), and state |
| `ssh_clone_session` | Create an independent transport |
| `ssh_close_session` | Close the transport and release cached credentials |
| `ssh_exec` | Execute a command via the existing transport |
| `ssh_stat` | Get path metadata |
| `ssh_list_directory` | Bounded directory listing |
| `ssh_read_file` | Read a byte range of a file |
| `ssh_upload_file` | Upload a local file with hash/backup |
| `ssh_download_file` | Download a remote file with hash/backup |
| `ssh_apply_patch` | Apply a unified diff with SHA-256 and backup |

## Runtime and Isolation

Configuration and keys are shared user-wide, but each agent's runtime is separate:

```text
$XDG_RUNTIME_DIR/mcp-ssh-ops/agent-<pid>-<random>/
├── askpass.sock
└── cm-*
```

- One MCP process cannot see another's session IDs and sockets.
- A heartbeat keeps masters alive while the agent is running.
- `ControlPersist=300` limits orphan-master lifetime after abnormal termination.
- Normal termination calls `ssh -O exit` for each session.

On Windows the transports live directly in the MCP process, with no ControlMaster child or control socket. Disconnect/termination closes the transport and clears its final credential reference. Session descriptions include `backend: "openssh" | "ssh2"` and `master_pid: null` for ssh2.

## Installation

```bash
npm install -g mcp-ssh-ops
```

Or use via `npx` without global installation:

```bash
npx mcp-ssh-ops
```

## Connecting to an MCP Client

### Devin

```text
.devin/mcp_config.local.json
node /path/to/mcp-ssh-ops/dist/index.js
```

Management:

```bash
devin mcp enable mcp-ssh-ops
devin mcp disable mcp-ssh-ops
devin mcp list
```

### Claude Desktop / Cursor / Other MCP Clients

Add to your MCP client config:

```json
{
  "mcpServers": {
    "mcp-ssh-ops": {
      "command": "npx",
      "args": ["mcp-ssh-ops"]
    }
  }
}
```

After rebuilding the backend, the MCP process needs to be restarted.

## Limitations

- Requires Node.js 22+ and system OpenSSH. Linux/macOS additionally require `ControlMaster` and `SSH_ASKPASS_REQUIRE`; see Windows compatibility above.
- File metadata/range commands are designed for Linux targets with GNU `stat`, `find`, `head`, and `dd`; transfer and rename use SFTP.
- `ssh_exec` does not allocate a PTY and closes stdin: interactive editors and `sudo` password prompts do not work.
- Output: 1 MiB default, 5 MiB max.
- Command timeout: 30 seconds default, 10 minutes max.
- Read/edit: max 2 MiB per operation.
- Upload/download: 100 MiB default per file.
- Patch-edit accepts UTF-8 without NUL, requires SHA-256 of the full file, and creates a backup by default.

## Development

```bash
npm install
npm run typecheck
npm test
npm run build
npm audit --omit=dev
```

Development state is recorded in `DEVELOPMENT_LOG.md`.
