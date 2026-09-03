# Project instructions

- Runtime: Node.js 20+ with TypeScript, ESM, and the system OpenSSH client.
- Install dependencies with `npm install`.
- Run all checks with `npm run typecheck`, `npm test`, `npm run build`, and `npm audit --omit=dev`.
- MCP uses stdio; never write logs or diagnostics to stdout.
- Native SSH profiles and trust data come from the user's `~/.ssh/config`, its Include files, and configured known_hosts paths.
- Preserve OpenSSH `ProxyJump`, `Include`, `Match`, agent, certificate, and identity behavior.
- A host without username must resolve to a literal user-config Host; an explicit username overrides only User after `ssh -G` resolution.
- Cache password prompts in RAM by SSH username while that credential scope has active sessions; invalidate on auth failure.
- Never accept SSH passwords, private keys, or passphrases as MCP tool arguments or persist them.
- Keep host-key verification fail-closed; changed keys require manual investigation.
- Keep live sessions isolated by MCP process and use per-process ControlMaster sockets.
- Public session IDs must remain human-readable (`name | alias -> user@host:port | token`), and every session operation result must include explicit session metadata.
- Local file transfer is restricted to configured roots (workspace and /tmp by default), rejects symlinks/sensitive credential directories, and refuses overwrite unless explicitly requested with backup.
- Update `DEVELOPMENT_LOG.md` after meaningful development work so later sessions can resume safely.
