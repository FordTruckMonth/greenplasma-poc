# GreenPlasma — CTFMON EoP Research POC

Windows privilege escalation research targeting the CTF/CTFMON object manager race condition. Two implementations — use **GreenPlasma.cpp** for the real technique; **JoeysCode.cpp** for generic section-race research against any target service.

---

## Which file to use

| File | Target | Status |
|---|---|---|
| `GreenPlasma.cpp` | `CTF.AsmListCache.FMPWinlogon{sesid}` (real CTFMON section) | Complete — use this |
| `JoeysCode.cpp` | `TargetServiceConfig` (placeholder — needs a real target) | Research stage |

**GreenPlasma.cpp** implements the full chain against a real Windows component and is ready to run. **JoeysCode.cpp** is a generic research harness; the section name `TargetServiceConfig` and the offset `0x48` need to be confirmed against your actual target service via reverse engineering.

---

## Prerequisites

- Windows 10/11 (non-Session 0 — must run as a logged-in user)
- MSVC toolchain (Visual Studio 2019+ or Build Tools)
- CMake 3.16+
- Run from an **elevated prompt** (local admin) — `SeDebugPrivilege` and `SeImpersonatePrivilege` are required for the token theft step

---

## Build

```cmd
cd greenplasma-poc
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

The output binary is `build\Release\GreenPlasma.exe`. Both source files share the same CMake project; to also build JoeysCode add a second target to `CMakeLists.txt`:

```cmake
add_executable(JoeysCode JoeysCode.cpp)
target_link_libraries(JoeysCode ntdll advapi32 shell32)
set_property(TARGET JoeysCode PROPERTY CXX_STANDARD 17)
```

---

## GreenPlasma.cpp

### What it does

1. **Symlink** — plants an NT object manager symbolic link in the current session namespace redirecting `CTF.AsmListCache.FMPWinlogon{sesid}` to `\BaseNamedObjects\CTFMON_DEAD` (or a path passed as `argv[1]`).
2. **Race** — fires a UAC elevation event via `ShellExecuteEx` runas, boosting the calling thread to `THREAD_PRIORITY_TIME_CRITICAL` and spinning with `YieldProcessor()` to widen the race window.
3. **Hijack** — once CTFMON creates the section through the symlink, opens it with `NtOpenSection` and maps a writable view.
4. **Token theft** — walks all processes with `CreateToolhelp32Snapshot`, finds the first SYSTEM-owned one, and duplicates its primary token using `SeDebugPrivilege`.
5. **Shell** — calls `CreateProcessWithTokenW` with the stolen token to spawn a SYSTEM `cmd.exe` on the interactive desktop.
6. **Policy** — optionally sets `DisableLockWorkstation` via a registry symlink chain to prevent the session locking while you work.

### Usage

```cmd
GreenPlasma.exe
```

Optional — redirect to a custom global section path:

```cmd
GreenPlasma.exe \BaseNamedObjects\MyCustomSection
```

### Expected output

```
[+] Symlink planted in session 3
[*] SYSTEM section mapped at 0x00000213ABCD0000 — writable view confirmed
[*] Section created — attempting SYSTEM token theft...
[+] Stolen SYSTEM token from PID 732 (winlogon.exe)
[+] SYSTEM shell spawned (PID 5120)
Section handle : 0x2c
Press any button to close section and exit
```

A new `cmd.exe` window will open running as SYSTEM. Press any key in the original window to release the section handle and clean up.

---

## JoeysCode.cpp

### What it does

Generic version of the same technique for testing against an arbitrary target service:

1. **Symlink** — redirects `\Sessions\{sesid}\BaseNamedObjects\TargetServiceConfig` to `\BaseNamedObjects\JoeyExploitSection` in the global namespace.
2. **Race thread** — dedicated background thread fires repeated `ShellExecuteEx` runas events at `THREAD_PRIORITY_TIME_CRITICAL`.
3. **Hijack** — polls `NtOpenSection` on the global target path; when the service creates the section, maps the same backing store directly and writes the poison flag at offset `0x48`.
4. **Validation** — reads the value at `0x48` before writing. If it is non-zero, prints a warning and skips the write to avoid corrupting the struct on a mismatched build.
5. **Token theft** — steals a SYSTEM primary token immediately on race win (no sleep — the service process must still be alive).
6. **Retrigger** — fires a final `ShellExecuteEx` runas to push the service back into the flag-reading code path.

### Adapting to a real target

Before using JoeysCode against a real service you need three things confirmed via WinDbg or IDA:

1. **Section name** — the name the service uses when calling `NtCreateSection` or `CreateFileMappingW`. Replace `TargetServiceConfig` in `linkPath`.
2. **Trigger** — what event causes the service to create or re-read the section. The current trigger (`ShellExecuteEx` runas on `conhost.exe`) is CTFMON-specific and may not apply.
3. **Flag offset** — the byte offset of the flag/field you want to overwrite. Replace `0x48`. The validation check will warn if the current value is unexpected, helping catch offset mismatches before they cause a crash.

### Usage

```cmd
JoeysCode.exe
```

### Expected output

```
[+] Symlink planted in session 3
[+] Flag written at 0x48 — service view poisoned
[+] Stolen SYSTEM token from PID 732 (winlogon.exe)
[+] SYSTEM shell spawned (PID 5136)
[*] Retrigger fired
```

---

## Troubleshooting

| Message | Cause | Fix |
|---|---|---|
| `Symlink creation failed` | Another instance is running, or running in Session 0 | Kill existing instance; do not run as a service |
| `[-] Could not obtain a SYSTEM token` | Missing `SeDebugPrivilege` | Run from an elevated prompt |
| `[-] CreateProcessWithTokenW failed` | Missing `SeImpersonatePrivilege` | Run from an elevated or service context |
| `[!] Unexpected value at 0x48` | Wrong Windows build or wrong target | Re-confirm offset in WinDbg; update hardcoded value |
| Shell opens but closes immediately | Desktop not set correctly | Verify `WinSta0\Default` is the active desktop |

---

## Credits

Original stripped POC: [Nightmare-Eclipse/GreenPlasma](https://github.com/Nightmare-Eclipse/GreenPlasma)
