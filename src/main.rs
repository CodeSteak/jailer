use std::ffi::CString;
use std::fs;
use std::io::{Read as IoRead, Write as IoWrite};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context};
use flate2::read::GzDecoder;
use indicatif::{ProgressBar, ProgressStyle};
use nix::mount::{mount, MsFlags};
use nix::sched::{unshare, CloneFlags};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{chroot, execvp, fork, getgid, getuid, ForkResult};
use sha2::{Digest, Sha256};

fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().collect();

    // Print help and exit
    if argv.len() < 2 || argv[1] == "--help" || argv[1] == "-h" {
        eprintln!("Usage: ja <jailname> [extra-args...]");
        eprintln!("       ja <jailname> -- <command> [args...]");
        eprintln!();
        eprintln!(
            "  ja claude                                 run 'claude' inside the claude jail"
        );
        eprintln!("  ja claude --dangerously-skip-permissions  run 'claude --dangerously-skip-permissions'");
        eprintln!("  ja claude -- sh                           run 'sh' inside the claude jail");
        eprintln!();
        eprintln!("Jails are stored in ~/.jails/<jailname>/ (Alpine Linux minirootfs).");
        eprintln!("Current directory is mounted as /data inside the jail.");
        std::process::exit(0);
    }

    let jailname = &argv[1];
    if jailname.is_empty()
        || !jailname
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!(
            "Invalid jail name '{}': must be non-empty and contain only [a-zA-Z0-9_-]",
            jailname
        );
    }
    let rest = &argv[2..];

    // Split on "--": everything after it is an explicit command override.
    // Without "--", trailing args are extra flags appended to the jailname command.
    let command: Vec<String> = if let Some(pos) = rest.iter().position(|a| a == "--") {
        rest[pos + 1..].to_vec()
    } else if rest.is_empty() {
        vec![jailname.clone()]
    } else {
        let mut cmd = vec![jailname.clone()];
        cmd.extend_from_slice(rest);
        cmd
    };

    let root = setup_jail(jailname)?;
    run_jail(&root, &command)
}

// ── Alpine helpers ───────────────────────────────────────────────────────────

fn alpine_arch(rust_arch: &str) -> anyhow::Result<&'static str> {
    match rust_arch {
        "x86_64" => Ok("x86_64"),
        "x86" => Ok("x86"),
        "aarch64" => Ok("aarch64"),
        "arm" => Ok("armhf"),
        "riscv64" => Ok("riscv64"),
        "powerpc64" => Ok("ppc64le"),
        "s390x" => Ok("s390x"),
        other => bail!(
            "Architecture '{}' is not supported by Alpine Linux. \
             Supported: x86_64, x86, aarch64, armhf, riscv64, ppc64le, s390x",
            other
        ),
    }
}

/// Returns (filename, sha256) for the alpine-minirootfs release.
fn fetch_minirootfs_info(arch: &str) -> anyhow::Result<(String, String)> {
    let url = format!(
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/{}/latest-releases.yaml",
        arch
    );

    eprintln!("Fetching release info...");

    let body = reqwest::blocking::get(&url)
        .with_context(|| format!("Failed to fetch {}", url))?
        .text()
        .context("Failed to read release metadata")?;

    // Parse YAML with simple string search — the format is predictable.
    // We look for a block containing `flavor: alpine-minirootfs` and then
    // find the `file:` and `sha256:` keys within the same YAML list entry
    // (delimited by lines starting with `-`).
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.trim() == "flavor: alpine-minirootfs" {
            let mut filename = None;
            let mut sha256 = None;
            for l in lines.iter().skip(i + 1) {
                let l = l.trim();
                // Stop at the next YAML list entry
                if l.starts_with('-') {
                    break;
                }
                if let Some(rest) = l.strip_prefix("file:") {
                    filename = Some(rest.trim().to_string());
                }
                if let Some(rest) = l.strip_prefix("sha256:") {
                    sha256 = Some(rest.trim().to_string());
                }
            }
            match (filename, sha256) {
                (Some(f), Some(s)) => return Ok((f, s)),
                (Some(f), None) => return Ok((f, String::new())),
                _ => {}
            }
        }
    }

    bail!(
        "Could not find alpine-minirootfs entry in latest-releases.yaml for arch '{}'",
        arch
    )
}

fn download_and_extract(
    arch: &str,
    filename: &str,
    expected_sha256: &str,
    dest: &Path,
) -> anyhow::Result<()> {
    let url = format!(
        "https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/{}/{}",
        arch, filename
    );

    eprintln!("Downloading {}", filename);

    let response = reqwest::blocking::get(&url)
        .with_context(|| format!("Failed to start download from {}", url))?;

    if !response.status().is_success() {
        bail!(
            "Download failed: server returned HTTP {}",
            response.status()
        );
    }

    let total = response.content_length();
    let pb = if let Some(n) = total {
        let pb = ProgressBar::new(n);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})",
            )
            .unwrap()
            .progress_chars("=>-"),
        );
        pb
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner:.green} {bytes} downloaded").unwrap());
        pb
    };

    // Read the entire archive into memory (~4 MB) so we can verify the checksum
    // before extracting.
    let mut buf = Vec::new();
    pb.wrap_read(response)
        .read_to_end(&mut buf)
        .context("Failed to read download")?;
    pb.finish_with_message("Done");

    if !expected_sha256.is_empty() {
        let actual = format!("{:x}", Sha256::digest(&buf));
        if actual != expected_sha256 {
            bail!(
                "SHA-256 mismatch for {}:\n  expected: {}\n  actual:   {}",
                filename,
                expected_sha256,
                actual
            );
        }
    }

    let gz = GzDecoder::new(buf.as_slice());
    let mut archive = tar::Archive::new(gz);
    archive.set_preserve_permissions(true);
    archive.set_overwrite(true);
    archive
        .unpack(dest)
        .with_context(|| format!("Failed to extract minirootfs to {}", dest.display()))?;

    Ok(())
}

// ── Jail setup ───────────────────────────────────────────────────────────────

fn jail_root(jailname: &str) -> anyhow::Result<PathBuf> {
    let home = dirs::home_dir().context("Cannot determine home directory")?;
    Ok(home.join(".jails").join(jailname))
}

fn setup_jail(jailname: &str) -> anyhow::Result<PathBuf> {
    let root = jail_root(jailname)?;

    // Idempotency: Alpine installs this file in the minirootfs
    if root.join("etc/alpine-release").exists() {
        return Ok(root);
    }

    eprintln!("Creating jail '{}' at {}", jailname, root.display());
    fs::create_dir_all(&root).with_context(|| format!("Failed to create {}", root.display()))?;

    let arch = alpine_arch(std::env::consts::ARCH)?;
    let (filename, sha256) = fetch_minirootfs_info(arch)?;
    download_and_extract(arch, &filename, &sha256, &root)?;

    // Ensure mount-target directories exist
    for dir in &["data", "proc", "dev", "dev/pts", "run", "tmp"] {
        fs::create_dir_all(root.join(dir))
            .with_context(|| format!("Failed to create {}/{}", root.display(), dir))?;
    }

    eprintln!("Jail '{}' ready.", jailname);
    Ok(root)
}

// ── Run jail ─────────────────────────────────────────────────────────────────

fn run_jail(root: &Path, command: &[String]) -> anyhow::Result<()> {
    let cwd = std::env::current_dir().context("Failed to get current directory")?;
    let real_uid = getuid().as_raw();
    let real_gid = getgid().as_raw();

    // 1. Enter user + mount + PID namespaces in a single atomic call.
    //    CLONE_NEWPID is required for mounting proc; the calling process stays
    //    in the old PID namespace — only children enter the new one, hence the
    //    fork below.
    unshare(CloneFlags::CLONE_NEWUSER | CloneFlags::CLONE_NEWNS | CloneFlags::CLONE_NEWPID)
        .context("unshare failed — ensure user namespaces are enabled on this kernel")?;

    // 2. Map real uid/gid → 0 inside the user namespace.
    //    setgroups must be denied before writing gid_map (kernel requirement).
    write_file("/proc/self/setgroups", b"deny")?;
    write_file(
        "/proc/self/uid_map",
        format!("0 {} 1\n", real_uid).as_bytes(),
    )?;
    write_file(
        "/proc/self/gid_map",
        format!("0 {} 1\n", real_gid).as_bytes(),
    )?;

    // 3. Fork so the child enters the new PID namespace (becomes PID 1 there).
    //    Safety: we are single-threaded at this point; no Rust runtime threads
    //    have been spawned, so fork is safe here.
    match unsafe { fork() }.context("fork failed")? {
        ForkResult::Parent { child } => {
            // Parent: wait for the child and mirror its exit code.
            match waitpid(child, None).context("waitpid failed")? {
                WaitStatus::Exited(_, code) => std::process::exit(code),
                WaitStatus::Signaled(_, sig, _) => std::process::exit(128 + sig as i32),
                _ => std::process::exit(1),
            }
        }
        ForkResult::Child => {
            // Child is now PID 1 in the new PID namespace.
            if let Err(e) = jail_child(root, &cwd, command) {
                eprintln!("Error: {:?}", e);
                std::process::exit(1);
            }
            unreachable!()
        }
    }
}

fn jail_child(root: &Path, cwd: &Path, command: &[String]) -> anyhow::Result<()> {
    // 4. Make the entire host mount tree private so our mounts don't propagate.
    mount(
        None::<&str>,
        "/",
        None::<&str>,
        MsFlags::MS_PRIVATE | MsFlags::MS_REC,
        None::<&str>,
    )
    .context("Failed to make root private")?;

    // 5. /proc (works now because we're in a new PID namespace)
    mount(
        Some("proc"),
        &root.join("proc"),
        Some("proc"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC,
        None::<&str>,
    )
    .context("Failed to mount /proc")?;

    // 6. /dev — tmpfs then bind individual devices from host.
    //    We cannot mknod in an unprivileged namespace, so we bind-mount
    //    the host device files onto empty file mountpoints.
    mount(
        Some("tmpfs"),
        &root.join("dev"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("mode=755"),
    )
    .context("Failed to mount tmpfs at /dev")?;

    for dev in &["null", "zero", "full", "random", "urandom", "tty"] {
        let src = PathBuf::from("/dev").join(dev);
        let dst = root.join("dev").join(dev);
        if src.exists() {
            fs::write(&dst, b"").with_context(|| format!("Failed to create {}", dst.display()))?;
            mount(
                Some(&src),
                &dst,
                None::<&str>,
                MsFlags::MS_BIND,
                None::<&str>,
            )
            .with_context(|| format!("Failed to bind-mount /dev/{}", dev))?;
        }
    }

    let dev_pts = root.join("dev/pts");
    fs::create_dir_all(&dev_pts).context("Failed to create /dev/pts")?;
    mount(
        Some("devpts"),
        &dev_pts,
        Some("devpts"),
        MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC,
        Some("newinstance,ptmxmode=0666,mode=0620"),
    )
    .unwrap_or_else(|e| eprintln!("warning: devpts: {}", e));

    // 7. /tmp and /run
    mount(
        Some("tmpfs"),
        &root.join("tmp"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=1777"),
    )
    .context("Failed to mount /tmp")?;

    mount(
        Some("tmpfs"),
        &root.join("run"),
        Some("tmpfs"),
        MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
        Some("mode=0755"),
    )
    .context("Failed to mount /run")?;

    // 8. Bind-mount current working directory as /data
    fs::create_dir_all(root.join("data")).context("Failed to create /data mount target")?;
    mount(
        Some(cwd),
        &root.join("data"),
        None::<&str>,
        MsFlags::MS_BIND,
        None::<&str>,
    )
    .context("Failed to bind-mount current directory as /data")?;

    // 9. Write resolv.conf for DNS.
    //    We copy the host file and append a public fallback nameserver because
    //    Alpine's curl uses c-ares, which can time out on some local resolvers
    //    (e.g. router DNS) inside namespaces.
    {
        let resolv = root.join("etc/resolv.conf");
        let mut contents = fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
        if !contents.contains("1.1.1.1") && !contents.contains("8.8.8.8") {
            contents.push_str("\nnameserver 1.1.1.1\n");
        }
        fs::write(&resolv, contents)
            .unwrap_or_else(|e| eprintln!("warning: resolv.conf: {}", e));
    }

    // 10. chroot into the jail
    chroot(root).with_context(|| format!("chroot({}) failed", root.display()))?;
    std::env::set_current_dir("/data").context("chdir /data failed")?;

    // 11. Set environment — clear host vars, keep only what the jail needs.
    let term = std::env::var("TERM").ok();
    for (key, _) in std::env::vars_os() {
        std::env::remove_var(&key);
    }
    std::env::set_var("HOME", "/root");
    std::env::set_var(
        "PATH",
        "/root/.local/bin:/root/bin:/root/.cargo/bin:/root/.npm-global/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    );
    std::env::set_var("IS_SANDBOX", "1");
    if let Some(term) = term {
        std::env::set_var("TERM", term);
    }

    // 12. execvp — replaces this process image; never returns on success.
    //     If the command is not found, fall back to sh.
    let c_prog = CString::new(command[0].as_str()).context("Command contains null byte")?;
    let c_args: Vec<CString> = command
        .iter()
        .map(|s| CString::new(s.as_str()))
        .collect::<Result<_, _>>()
        .context("Argument contains null byte")?;

    match execvp(&c_prog, &c_args) {
        Err(nix::errno::Errno::ENOENT) => {
            eprintln!("ja: '{}' not found, falling back to sh", command[0]);
            let sh = CString::new("sh").unwrap();
            execvp(&sh, std::slice::from_ref(&sh)).context("exec sh failed")?;
        }
        Err(e) => return Err(e).with_context(|| format!("exec '{}' failed", command[0])),
        Ok(_) => {}
    }

    unreachable!()
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn write_file(path: &str, data: &[u8]) -> anyhow::Result<()> {
    let mut f = fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("Failed to open {}", path))?;
    f.write_all(data)
        .with_context(|| format!("Failed to write {}", path))
}
