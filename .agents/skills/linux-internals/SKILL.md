---
name: linux-internals
description: Linux operating system internals for detection engineering — process model (fork/exec, /proc filesystem, namespaces), user/group/capability model, auditd subsystem and rule authoring, eBPF hook points and security tools (Falco, Tetragon), systemd service model, PAM authentication, SSH key management, common persistence locations, container isolation boundaries (namespaces, cgroups, seccomp), and the mapping between Linux operations and detection telemetry. Use when authoring detections targeting Linux endpoints, servers, or container workloads.
---

# Linux Internals — detection-relevant knowledge

This skill encodes how Linux works at the level needed to write detections for Linux endpoints, servers, and container workloads.

---

## 1. Process model

### fork/exec

```
Parent process → fork() → child process (copy of parent)
  → execve() → new program loaded into child's address space
  → Program executes with inherited file descriptors, environment, UID/GID
```

**Detection-relevant**: Unlike Windows (single `CreateProcess`), Linux separates process creation (`fork`) from program loading (`exec`). A `fork` without `exec` creates a child running the same code as the parent — used in daemonisation and some evasion techniques.

### /proc filesystem

`/proc/<pid>/` exposes process information:

| Path | Content | Detection use |
|---|---|---|
| `/proc/<pid>/cmdline` | Command line (null-separated) | Process command-line inspection |
| `/proc/<pid>/exe` | Symlink to executable | Verify actual binary (survives argv[0] spoofing) |
| `/proc/<pid>/environ` | Environment variables | Credential exposure, configuration |
| `/proc/<pid>/fd/` | Open file descriptors | Network connections, open files |
| `/proc/<pid>/maps` | Memory mappings | Injected libraries, memory-only payloads |
| `/proc/<pid>/status` | Process status (UID, GID, capabilities) | Privilege verification |
| `/proc/<pid>/ns/` | Namespace membership | Container escape detection |

**Key insight**: `argv[0]` (process name) can be spoofed. `/proc/<pid>/exe` reveals the actual binary. Detections should verify the executable path, not just the displayed name.

---

## 2. User/group/capability model

### Traditional model

| Concept | Detail | Detection relevance |
|---|---|---|
| **UID 0 (root)** | Full system access | Any process running as UID 0 has unrestricted access |
| **SUID bit** | Executable runs as file owner (often root) | SUID binaries are privilege escalation targets. New SUID files are high-signal. |
| **SGID bit** | Executable runs with file group | Similar to SUID but for group privileges |
| **Sticky bit** | Only owner can delete files in directory | `/tmp` protection — removal is suspicious |

### Linux capabilities

Capabilities split root's power into discrete units. Key capabilities:

| Capability | What it grants | Detection relevance |
|---|---|---|
| `CAP_SYS_ADMIN` | Broad admin operations (mount, namespace, etc.) | Near-equivalent to root. Container escape vector. |
| `CAP_SYS_PTRACE` | Trace/debug any process | Process injection, credential theft from memory |
| `CAP_NET_RAW` | Raw socket access | Network sniffing, packet injection |
| `CAP_NET_ADMIN` | Network configuration | Firewall modification, routing changes |
| `CAP_DAC_OVERRIDE` | Bypass file permission checks | Read any file regardless of permissions |
| `CAP_SETUID` / `CAP_SETGID` | Change UID/GID | Privilege escalation |
| `CAP_SYS_MODULE` | Load kernel modules | Rootkit installation |
| `CAP_BPF` | eBPF operations | Kernel-level monitoring or evasion |

---

## 3. auditd

The Linux Audit Framework (`auditd`) is the primary native security telemetry source.

### Key audit record types

| Type | Description | Detection use |
|---|---|---|
| `SYSCALL` | System call with arguments | Process creation, file access, network operations |
| `EXECVE` | Program execution with full arguments | Command-line capture (equivalent to Windows 4688 + cmdline) |
| `PATH` | File path accessed | File access auditing |
| `PROCTITLE` | Process title (command line) | Backup command-line source |
| `USER_AUTH` | Authentication attempt | Login detection |
| `USER_LOGIN` | Login event | Session tracking |
| `USER_CMD` | Command executed via sudo | Privileged command auditing |
| `ANOM_PROMISCUOUS` | Network interface set to promiscuous mode | Network sniffing detection |
| `ANOM_ABEND` | Abnormal process termination | Crash/exploit detection |

### Critical audit rules

```bash
# Process execution
-a always,exit -F arch=b64 -S execve -k exec

# File access to sensitive files
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privilege

# SSH key modifications
-w /root/.ssh/ -p wa -k ssh_keys
-w /home/ -p wa -k ssh_keys

# Kernel module loading
-a always,exit -F arch=b64 -S init_module -S finit_module -k modules

# Network connections
-a always,exit -F arch=b64 -S connect -k network

# Privilege escalation
-a always,exit -F arch=b64 -S setuid -S setgid -k privilege_escalation

# Cron modifications
-w /etc/crontab -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
```

---

## 4. eBPF and security tools

### eBPF hook points

eBPF programs attach to kernel hook points for security monitoring:

| Hook type | Examples | Security use |
|---|---|---|
| **kprobes** | Any kernel function entry/exit | System call monitoring, function tracing |
| **tracepoints** | Stable kernel trace points | Process lifecycle, network events |
| **LSM hooks** | Linux Security Module hooks | Policy enforcement (file access, network, process) |
| **XDP** | Network packet processing | Network filtering, DDoS mitigation |
| **cgroup** | Container-scoped hooks | Per-container policy enforcement |

### Security tools

| Tool | Mechanism | Detection surface |
|---|---|---|
| **Falco** | eBPF + rules engine | Process, file, network, container events. Sigma-like rule format. |
| **Tetragon** | eBPF (Cilium) | Process lifecycle, network, file access with enforcement capability |
| **Tracee** | eBPF (Aqua) | System call tracing, container-aware |
| **auditd** | Kernel audit framework | Traditional audit logging |
| **Sysdig** | eBPF + system call capture | Full system call capture with filtering |

---

## 5. systemd service model

| Concept | Detail | Detection relevance |
|---|---|---|
| **Unit files** | `/etc/systemd/system/`, `/usr/lib/systemd/system/` | New unit files = persistence. User-writable paths are higher signal. |
| **Service types** | `simple`, `forking`, `oneshot`, `notify` | `oneshot` with `RemainAfterExit=yes` = runs once then appears active |
| **Timers** | systemd equivalent of cron | Timer creation = persistence (like Windows scheduled tasks) |
| **Socket activation** | Service started on incoming connection | Backdoor listener pattern |
| **Drop-in overrides** | `/etc/systemd/system/<service>.d/*.conf` | Modify existing service behaviour without changing the unit file |

### Persistence locations

| Location | Mechanism | Detection signal |
|---|---|---|
| `/etc/systemd/system/` | System service | New `.service` or `.timer` file |
| `~/.config/systemd/user/` | User service | User-level persistence |
| `/etc/crontab`, `/var/spool/cron/` | Cron jobs | File modification |
| `/etc/init.d/` | SysV init scripts (legacy) | New script |
| `~/.bashrc`, `~/.profile`, `~/.bash_profile` | Shell profile | Login-triggered execution |
| `/etc/ld.so.preload` | Shared library preloading | Every process loads the specified library — rootkit technique |
| `/etc/pam.d/` | PAM configuration | Authentication backdoor |
| `~/.ssh/authorized_keys` | SSH key-based access | New key = persistent access |

---

## 6. PAM (Pluggable Authentication Modules)

PAM controls authentication on Linux. Configuration in `/etc/pam.d/`.

| PAM module | Purpose | Detection relevance |
|---|---|---|
| `pam_unix.so` | Standard password authentication | Modification = authentication bypass |
| `pam_exec.so` | Execute arbitrary command during auth | Backdoor: run script on every login |
| `pam_permit.so` | Always permit | Replacing `pam_unix.so` with `pam_permit.so` = no-password login |

**Detection**: File modification to `/etc/pam.d/*` files. New PAM modules in `/lib/security/` or `/lib64/security/`.

---

## 7. SSH

| Concept | Detail | Detection relevance |
|---|---|---|
| **Key-based auth** | `~/.ssh/authorized_keys` | New key addition = persistence |
| **Agent forwarding** | SSH agent socket forwarded to remote host | Credential theft from forwarded agent |
| **ProxyJump / tunnelling** | SSH used as SOCKS proxy or port forwarder | Lateral movement, C2 tunnelling |
| **Known hosts** | `~/.ssh/known_hosts` | Cleared known_hosts = anti-forensics |
| **sshd_config** | `/etc/ssh/sshd_config` | Modification to allow root login, change port, disable logging |

---

## 8. Container isolation boundaries

| Boundary | Mechanism | Escape vector |
|---|---|---|
| **PID namespace** | Isolated process tree | `/proc` mount from host, `nsenter` |
| **Network namespace** | Isolated network stack | Host network mode (`--net=host`) |
| **Mount namespace** | Isolated filesystem | Sensitive host path mounts (`/`, `/etc`, Docker socket) |
| **User namespace** | UID mapping | Misconfigured mapping granting host root |
| **cgroups** | Resource limits | cgroup escape via `release_agent` (CVE-2022-0492) |
| **seccomp** | System call filtering | Disabled seccomp profile allows dangerous syscalls |
| **AppArmor/SELinux** | Mandatory access control | Disabled or permissive profiles |

**Detection**: Container escape indicators:
- Process in container namespace accessing host PID namespace
- Docker socket (`/var/run/docker.sock`) mounted inside container
- `CAP_SYS_ADMIN` capability inside container
- `--privileged` flag on container creation
- `nsenter` execution targeting host namespaces

---

## 9. Telemetry mapping

| Linux operation | auditd record | Falco rule | Sysmon for Linux | SIEM table |
|---|---|---|---|---|
| Process execution | `EXECVE` + `SYSCALL` | `Spawned process` | EID 1 | `Syslog`, `SysmonEvent` |
| File creation | `PATH` + `SYSCALL` | `File below /etc opened for writing` | EID 11 | `Syslog` |
| Network connection | `SYSCALL` (connect) | `Outbound connection` | EID 3 | `Syslog` |
| User authentication | `USER_AUTH` | `User login` | — | `Syslog` |
| Kernel module load | `SYSCALL` (init_module) | `Linux kernel module injection` | — | `Syslog` |
| Container event | — | `Container started/stopped` | — | Container runtime logs |

---

## 10. Quality checklist

- [ ] Detection targets the system call or kernel operation, not just a tool name.
- [ ] `/proc/<pid>/exe` used to verify actual binary (not just `argv[0]`).
- [ ] Capabilities checked (not just UID 0) for privilege assessment.
- [ ] auditd rule requirements declared for detections depending on audit records.
- [ ] Container context considered (is the process in a container namespace?).
- [ ] Persistence detection covers all locations (systemd, cron, shell profiles, SSH keys, PAM, ld.so.preload).
- [ ] SUID/SGID file creation monitored.
- [ ] eBPF tool requirements declared (Falco, Tetragon, etc.).
- [ ] SSH key additions and sshd_config modifications monitored.
- [ ] Container escape indicators documented (privileged mode, Docker socket mount, CAP_SYS_ADMIN).
