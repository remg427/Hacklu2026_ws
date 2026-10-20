---
name: macos-internals
description: macOS operating system internals for detection engineering — process model (XPC, launchd, posix_spawn), TCC (Transparency, Consent, and Control) framework, Gatekeeper and notarisation, code signing enforcement, System Extensions vs kernel extensions, Endpoint Security framework, persistence locations (LaunchAgents, LaunchDaemons, login items), Keychain access, and the mapping between macOS operations and EDR telemetry. Use when authoring detections targeting macOS endpoints.
---

# macOS Internals — detection-relevant knowledge

This skill encodes how macOS works at the level needed to write detections for macOS endpoints. macOS has fundamentally different security architecture from Windows and Linux — detections cannot be ported without understanding these differences.

---

## 1. Process model

### Process creation

macOS uses `posix_spawn()` (preferred) or `fork()/exec()` for process creation. Key differences from Windows:

| Concept | macOS | Windows equivalent | Detection relevance |
|---|---|---|---|
| **launchd (PID 1)** | Init system, manages all services | SCM + Task Scheduler | Parent of all system services. Unexpected launchd children are suspicious. |
| **XPC services** | Inter-process communication framework | COM/DCOM | Sandboxed helper processes. XPC service abuse = privilege escalation. |
| **App bundles** | `.app` directories with `Info.plist` | `.exe` files | Malware can hide in app bundle resources |
| **Universal binaries** | Fat binaries with multiple architectures | N/A | Can contain both x86_64 and arm64 code |
| **Rosetta 2** | x86_64 translation on Apple Silicon | WoW64 | x86_64 processes on arm64 hardware — unusual for native apps |

### Process hierarchy

```
launchd (PID 1)
  ├── System services (LaunchDaemons)
  ├── Per-user launchd
  │     ├── User services (LaunchAgents)
  │     ├── Applications
  │     └── Login items
  └── Kernel extensions / System Extensions
```

---

## 2. TCC (Transparency, Consent, and Control)

TCC controls access to sensitive resources. Applications must be granted permission via user consent or MDM profile.

| TCC-protected resource | What it controls | Detection relevance |
|---|---|---|
| **Full Disk Access** | Read all files including protected locations | Required for EDR sensors. Malware seeking FDA = high-signal. |
| **Screen Recording** | Capture screen content | Spyware indicator |
| **Accessibility** | Control other applications | Keylogging, UI manipulation |
| **Camera / Microphone** | Audio/video capture | Surveillance |
| **Contacts / Calendar / Photos** | Personal data access | Data theft |
| **Location Services** | GPS/Wi-Fi location | Tracking |
| **Automation (AppleScript)** | Control other apps via AppleScript | Scripted attacks |

### TCC database

Permissions stored in `~/Library/Application Support/com.apple.TCC/TCC.db` (user) and `/Library/Application Support/com.apple.TCC/TCC.db` (system).

**Detection**: Direct TCC database modification (bypassing the consent UI) is a known attack technique. Monitor for `sqlite3` or other processes writing to `TCC.db`.

### TCC bypass techniques

| Technique | Mechanism | Detection signal |
|---|---|---|
| **TCC.db manipulation** | Direct SQLite modification | Process accessing TCC.db that isn't `tccd` |
| **FDA app abuse** | Inject into an app that already has FDA | Code injection into FDA-granted process |
| **MDM profile** | Deploy TCC profile via MDM | New configuration profile installation |
| **Mounting TCC.db** | Mount a modified TCC.db over the original | Mount operations targeting TCC paths |

---

## 3. Gatekeeper and notarisation

| Layer | What it does | Bypass detection |
|---|---|---|
| **Gatekeeper** | Blocks unsigned/unnotarised apps from running | `xattr -d com.apple.quarantine` removes quarantine flag |
| **Notarisation** | Apple scans app for malware before issuing a ticket | Unnotarised app execution (requires user override) |
| **Quarantine flag** | `com.apple.quarantine` extended attribute on downloaded files | Quarantine removal = Gatekeeper bypass |
| **Code signing** | Validates developer identity and code integrity | Unsigned or ad-hoc signed binaries |

**Detection signals**:
- `spctl` assessment failures in system logs
- Quarantine attribute removal (`xattr -d com.apple.quarantine`)
- Execution of unsigned binaries (no `CodeDirectory` in code signature)
- Ad-hoc signed binaries (`Signature=adhoc`) — legitimate for development, suspicious in production

---

## 4. Code signing

macOS enforces code signing more strictly than Windows:

| Signing level | What it means | Detection relevance |
|---|---|---|
| **Apple-signed** | Signed by Apple | System binaries. Modification = tampering. |
| **Developer ID** | Signed by identified developer | Third-party apps. Valid signature expected. |
| **Ad-hoc** | Self-signed, no identity | Development builds. Suspicious in production. |
| **Unsigned** | No signature | Highly suspicious. Blocked by default on modern macOS. |

### Hardened Runtime

Apps with Hardened Runtime enabled have additional protections:
- No code injection (DYLD_INSERT_LIBRARIES blocked)
- No debugging by non-Apple debuggers
- No unsigned memory execution

**Detection**: Processes without Hardened Runtime that inject into Hardened Runtime processes.

---

## 5. System Extensions vs Kernel Extensions

| Type | Location | Privilege | Detection relevance |
|---|---|---|---|
| **Kernel extensions (kexts)** | `/Library/Extensions/`, `/System/Library/Extensions/` | Kernel-level | Deprecated on Apple Silicon. New kext loading is extremely suspicious. |
| **System Extensions** | App bundle | User-space with kernel-like capabilities | Endpoint Security, Network Extension, Driver Extension frameworks |
| **Endpoint Security (ES)** | System Extension type | Process, file, network monitoring | EDR sensors use ES framework. ES client registration is privileged. |

**Detection**: New kernel extension loading (`kextload`), new System Extension activation, ES client registration from unexpected apps.

---

## 6. Persistence locations

| Location | Mechanism | Detection signal |
|---|---|---|
| `/Library/LaunchDaemons/` | System-wide, runs as root | New `.plist` file. Highest-privilege persistence. |
| `/Library/LaunchAgents/` | System-wide, runs as user | New `.plist` file. |
| `~/Library/LaunchAgents/` | Per-user | New `.plist` file. Most common malware persistence. |
| `/Library/StartupItems/` | Legacy startup | Deprecated but still functional. |
| Login Items | `~/Library/Application Support/com.apple.backgroundtaskmanagementagent/` | New login item registration. |
| `~/.zshrc`, `~/.bash_profile` | Shell profile | Login-triggered execution. |
| Cron jobs | `/var/at/tabs/`, `crontab -l` | Cron job creation. |
| Periodic scripts | `/etc/periodic/daily/`, `weekly/`, `monthly/` | New script in periodic directories. |
| At jobs | `/var/at/jobs/` | Scheduled execution. |
| Authorization plugins | `/Library/Security/SecurityAgentPlugins/` | Authentication-triggered execution. |
| Directory Services plugins | `/Library/DirectoryServices/PlugIns/` | Authentication-triggered execution. |
| Emond rules | `/etc/emond.d/rules/` | Event Monitor daemon rules. |
| Folder Actions | `~/Library/Scripts/Folder Action Scripts/` | Triggered when files added to folder. |

### LaunchDaemon/LaunchAgent plist structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "...">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.malware.persistence</string>
    <key>ProgramArguments</key>
    <array>
        <string>/path/to/malware</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
```

**Detection**: New plist files in LaunchDaemon/LaunchAgent directories. `ProgramArguments` pointing to unusual locations (not `/usr/`, `/System/`, `/Applications/`). `RunAtLoad` = `true` with `KeepAlive` = `true` = persistent auto-restart.

---

## 7. Keychain

macOS Keychain stores credentials, certificates, and secrets.

| Keychain | Location | Detection relevance |
|---|---|---|
| **Login keychain** | `~/Library/Keychains/login.keychain-db` | User credentials. Unlocked on login. |
| **System keychain** | `/Library/Keychains/System.keychain` | System-wide certificates and credentials. |
| **Local Items** | `~/Library/Keychains/` (UUID-named) | iCloud Keychain local cache. |

**Detection**: `security` command-line tool accessing keychain items (`security find-generic-password`, `security dump-keychain`). Keychain access from unexpected processes.

---

## 8. EDR telemetry on macOS

| Operation | Endpoint Security event | Sysmon for macOS | CrowdStrike | SentinelOne |
|---|---|---|---|---|
| Process execution | `ES_EVENT_TYPE_NOTIFY_EXEC` | EID 1 | `ProcessRollup2` | `Process Creation` |
| File creation | `ES_EVENT_TYPE_NOTIFY_CREATE` | EID 11 | `FileWritten` | `File Creation` |
| Network connection | `ES_EVENT_TYPE_NOTIFY_CONNECT` | EID 3 | `NetworkConnectIP4` | `IP Connect` |
| File modification | `ES_EVENT_TYPE_NOTIFY_WRITE` | — | `FileWritten` | `File Modification` |
| Kext load | `ES_EVENT_TYPE_NOTIFY_KEXTLOAD` | — | `DriverLoad` | — |
| TCC access | `ES_EVENT_TYPE_NOTIFY_TCC_CHECK` | — | — | — |

**Key gap**: macOS EDR coverage is generally less comprehensive than Windows. Process tree depth is full, but registry-equivalent (plist) monitoring, DLL-equivalent (dylib) loading, and script content capture vary significantly by vendor.

---

## 9. macOS-specific attack techniques

| Technique | Mechanism | Detection signal |
|---|---|---|
| **DYLD_INSERT_LIBRARIES** | Environment variable forces dylib loading | Process with `DYLD_INSERT_LIBRARIES` set (blocked by Hardened Runtime) |
| **Dylib hijacking** | Place malicious dylib in app's @rpath | Dylib loaded from unexpected path |
| **AppleScript abuse** | `osascript` executing AppleScript for automation | `osascript` spawning unexpected child processes |
| **JXA (JavaScript for Automation)** | JavaScript executed via `osascript -l JavaScript` | JXA execution from non-IDE context |
| **Installer package abuse** | `.pkg` with pre/post-install scripts | `installer` process spawning shell commands |
| **Profile installation** | MDM-style configuration profiles | New profile in `/Library/Managed Preferences/` |

---

## 10. Quality checklist

- [ ] Detection accounts for macOS-specific process model (launchd, XPC).
- [ ] TCC permissions considered (does the detection require FDA?).
- [ ] Code signing status checked (Apple-signed, Developer ID, ad-hoc, unsigned).
- [ ] Gatekeeper/quarantine bypass techniques covered.
- [ ] Persistence detection covers all macOS locations (LaunchDaemons, LaunchAgents, login items, shell profiles, cron, periodic, emond).
- [ ] Keychain access from unexpected processes monitored.
- [ ] Kernel extension loading flagged (deprecated on Apple Silicon).
- [ ] EDR coverage gaps on macOS documented (vs Windows parity).
- [ ] AppleScript/JXA execution from non-standard contexts detected.
- [ ] Container/VM detection considered (macOS VMs are increasingly common).
