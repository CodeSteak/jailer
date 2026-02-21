# ja — Alpine Linux jails for your terminal

Run commands inside a persistent, isolated Alpine Linux environment. No root. No Docker. No config files.

> **Vibecoded** — built in one session with Claude Code. Use at your own risk.

---

## Motivation

AI coding assistants like [Claude Code](https://claude.ai/claude-code) are powerful, but running them with `--dangerously-skip-permissions` on your real home directory is a leap of faith. `ja` wraps any command in an Alpine Linux sandbox where the tool can do whatever it wants — to Alpine's filesystem — while your real machine stays untouched.

The current directory is always mounted as `/data` inside the jail, so the assistant still sees and edits your project files. Everything else is isolated.

```
your home dir          ─── untouched
your project dir  ─────── mounted read/write at /data
~/.jails/claude/  ─────── Alpine Linux root the AI lives in
```

---

## How it works

`ja` uses Linux user namespaces + mount namespaces + PID namespaces — the same kernel primitives that power containers — implemented directly in Rust with no external tools (no `bwrap`, no `runc`, no `docker`). It doesn't require root.

On first run it downloads the Alpine Linux minirootfs (~4 MB) from the official CDN and extracts it to `~/.jails/<name>/`. Subsequent runs start in milliseconds.

---

## Installation

### From source

```sh
git clone https://github.com/CodeSteak/jailer
cd jailer
cargo build --release
cp target/release/ja ~/.local/bin/
```

### Arch Linux (AUR / makepkg)

```sh
git clone https://github.com/CodeSteak/jailer
cd jailer
makepkg -si
```

### Requirements

- Linux kernel ≥ 5.0 with user namespaces enabled
- `rustup` / `cargo` (build only)

---

## Usage

```
ja <jailname> [extra-args...]
ja <jailname> -- <command> [args...]
```

### Run Claude Code with full autonomy, safely

```sh
ja claude --dangerously-skip-permissions
```

Creates the `claude` jail on first run (downloads Alpine), then launches Claude Code inside it. Your current project directory is at `/data`. Claude can trash the Alpine system all it wants — your home dir is safe.

### Open a shell in the jail

```sh
ja claude -- sh
```

### Run any command

```sh
ja claude -- apk add git nodejs npm
ja claude -- node server.js
```

### Use the jailname as the command

If no arguments are given, `ja` runs a binary with the same name as the jail:

```sh
ja claude   # equivalent to: ja claude -- claude
```

If that binary isn't installed yet, `ja` drops you into `sh` with a message:

```
ja: 'claude' not found, falling back to sh
```

### Jails are persistent

```
~/.jails/
└── claude/       ← full Alpine rootfs, survives reboots
    ├── etc/
    ├── usr/
    └── ...
```

Install packages once, they stay:

```sh
ja claude -- apk add curl jq
ja claude -- curl https://example.com   # curl is still there next run
```

---

## Isolation model

| What's isolated | What's shared |
|---|---|
| Filesystem (Alpine root) | Network (host network stack) |
| PID namespace | Current directory (mounted at `/data`) |
| Mount namespace | `/etc/resolv.conf` (live DNS from host) |
| User namespace (appears as root inside) | Kernel |

The jail appears as `uid=0 (root)` inside, mapped to your real UID outside. No real privileges are granted.

---

## Typical Claude Code workflow

```sh
cd ~/projects/myapp

# First time: creates the jail and installs Claude
ja claude -- sh -c "apk add curl nodejs npm bash"
ja claude -- sh -c "curl -fsSL https://claude.ai/install.sh | bash"


# Every subsequent time: instant startup
ja claude --dangerously-skip-permissions
```

Or put it in a shell alias:

```sh
alias claude-safe='ja claude --dangerously-skip-permissions'
```
