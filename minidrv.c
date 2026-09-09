#include <ntddk.h>

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("MiniDriver: Unloaded\r\n");
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES objAttr;
    UNICODE_STRING keyPath, valueName;
    HANDLE hKey;
    ULONG disableStart = 4;

    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    DbgPrint("MiniDriver Loaded\r\n");

    RtlInitUnicodeString(&keyPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\iwillkillyou");
    InitializeObjectAttributes(&objAttr, &keyPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&hKey, KEY_WRITE, &objAttr);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("MiniDriver: ZwOpenKey fail, status:%08X\r\n", status);
        return status;
    }

    RtlInitUnicodeString(&valueName, L"Start");
    status = ZwSetValueKey(hKey, &valueName, 0, REG_DWORD, &disableStart, sizeof(ULONG));
    if (NT_SUCCESS(status))
    {
        DbgPrint("MiniDriver: Set Start=4 SUCCESS\r\n");
    }
    else
    {
        DbgPrint("MiniDriver: ZwSetValueKey fail, status:%08X\r\n", status);
    }

    ZwClose(hKey);
    return STATUS_SUCCESS;
}
