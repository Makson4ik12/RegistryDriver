#include <fltKernel.h>

#define IOCTL_UPDATE_RULES CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFICATOR_ON CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_NOTIFICATOR_OFF CTL_CODE(FILE_DEVICE_UNKNOWN, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_UPDATE_RULES_COUNT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

struct AccessRule {
	char path[150];
	int integrityLevel;
} accessRulesArray[150];

struct IoctlInt {
	int count;
} rulesCount;

int rule_pointer = 0;

UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\MyRegDriver");
UNICODE_STRING symbolicName = RTL_CONSTANT_STRING(L"\\DosDevices\\MyRegDriver");
PDEVICE_OBJECT DeviceObject = NULL;
LARGE_INTEGER registerCookie = { 0 };
PEX_CALLBACK_FUNCTION registryCallbackTable[50] = { 0 };


typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);
QUERY_INFO_PROCESS ZwQueryInformationProcess;


NTSTATUS GetProcessImageName(PEPROCESS eProcess, PUNICODE_STRING* ProcessImageName)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG returnedLength;
	HANDLE hProcess = NULL;

	PAGED_CODE();

	if (eProcess == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcess);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("MyRegDrivevr: ObOpenObjectByPointer Failed: %08x\n", status);
		return status;
	}

	if (ZwQueryInformationProcess == NULL)
	{
		UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"ZwQueryInformationProcess");

		ZwQueryInformationProcess =
			(QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);

		if (ZwQueryInformationProcess == NULL)
		{
			DbgPrint("MyRegDrivevr: Cannot resolve ZwQueryInformationProcess\n");
			status = STATUS_UNSUCCESSFUL;
			goto cleanUp;
		}
	}

	status = ZwQueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &returnedLength);

	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		DbgPrint("MyRegDrivevr: ZwQueryInformationProcess status = %x\n", status);
		goto cleanUp;
	}

	*ProcessImageName = (PUNICODE_STRING)ExAllocatePoolWithTag(NonPagedPoolNx, returnedLength, '2gat');

	if (ProcessImageName == NULL)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto cleanUp;
	}

	status = ZwQueryInformationProcess(hProcess,
		ProcessImageFileName,
		*ProcessImageName,
		returnedLength,
		&returnedLength);

	if (!NT_SUCCESS(status)) ExFreePoolWithTag(*ProcessImageName, '2gat');

cleanUp:

	ZwClose(hProcess);
	return status;
}


NTSTATUS CheckAccessToReg(PUNICODE_STRING regKeyName, PUNICODE_STRING processName) {
	NTSTATUS status = STATUS_SUCCESS;
	int processLevel = 3;
	int regLevel = 3;

	if ((regKeyName == NULL) || (processName == NULL)) {
		DbgPrint("MyRegFilter: Warning: detect null process");
		return status;
	}

	for (int i = 0; i < rulesCount.count; i++) {
		UNICODE_STRING rule;
		ANSI_STRING ansiString;

		RtlInitAnsiString(&ansiString, accessRulesArray[i].path);
		RtlAnsiStringToUnicodeString(&rule, &ansiString, TRUE);

		if (RtlCompareUnicodeString(&rule, regKeyName, FALSE) == 0) {
			regLevel = accessRulesArray[i].integrityLevel;
		} else if (RtlCompareUnicodeString(&rule, processName, FALSE) == 0) {
			processLevel = accessRulesArray[i].integrityLevel;
		}

		RtlFreeUnicodeString(&rule);
	}

	if (processLevel < regLevel) {
		status = STATUS_ACCESS_DENIED;
	}

	return status;
}


PCREATE_THREAD_NOTIFY_ROUTINE NotificatorCallback(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	NTSTATUS status;
	ULONG returnedLength;
	UNICODE_STRING logPath;
	HANDLE            fileHandle;
	IO_STATUS_BLOCK   iostatus;
	OBJECT_ATTRIBUTES oa;

	LARGE_INTEGER time, local_time;
	TIME_FIELDS tf;
	KeQuerySystemTime(&time);
	ExSystemTimeToLocalTime(&time, &local_time);
	RtlTimeToTimeFields(&local_time, &tf);

	WCHAR buf_time[10] = { 0 }, temp_buf[3] = { 0 };

	buf_time[1] = tf.Hour % 10 + '0';
	if (tf.Hour < 10)
		buf_time[0] = '0';
	else
	{
		tf.Hour /= 10;
		buf_time[0] = tf.Hour + '0';
	}
	buf_time[2] = ':';

	buf_time[4] = tf.Minute % 10 + '0';
	if (tf.Minute < 10)
		buf_time[3] = '0';
	else
	{
		tf.Minute /= 10;
		buf_time[3] = tf.Minute + '0';
	}
	buf_time[5] = ':';

	buf_time[7] = tf.Second % 10 + '0';
	if (tf.Second < 10)
		buf_time[6] = '0';
	else
	{
		tf.Second /= 10;
		buf_time[6] = tf.Second + '0';
	}
	buf_time[8] = ' ';


	int prc_pid = PtrToInt(ProcessId), pid_length = 0, tmp;
	WCHAR buf_prc_pid[10] = { 0 };
	tmp = prc_pid;
	for (; tmp; tmp /= 10, pid_length++);
	for (int i = 0; i < pid_length; i++)
	{
		buf_prc_pid[pid_length - 1 - i] = prc_pid % (10) + 48;
		prc_pid /= 10;
	}

	int thr_tid = PtrToInt(ThreadId), tid_length = 0;
	WCHAR buf_thr_tid[10] = { 0 };
	tmp = thr_tid;
	for (; tmp; tmp /= 10, tid_length++);
	for (int i = 0; i < tid_length; i++)
	{
		buf_thr_tid[tid_length - 1 - i] = thr_tid % (10) + 48;
		thr_tid /= 10;
	}


	WCHAR buffer[500] = { 0 };
	PEPROCESS pProcess = NULL;
	PUNICODE_STRING processName = NULL;
	status = PsLookupProcessByProcessId(ProcessId, &pProcess);
	GetProcessImageName(pProcess, &processName);

	if (!NT_SUCCESS(status))
	{
		return;
	}

	RtlInitUnicodeString(&logPath,
		L"\\??\\C:\\reglog.txt");

	InitializeObjectAttributes(&oa,
		&logPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	status = ZwCreateFile(&fileHandle,
		FILE_APPEND_DATA,
		&oa,
		&iostatus,
		0,
		FILE_ATTRIBUTE_NORMAL,
		0,
		FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT,
		NULL,
		0);

	if (status != STATUS_SUCCESS)
	{
		DbgPrint("MyRegDriver Notificator: log file cant be open(%wZ): 0x%X", logPath, status);
		ZwClose(fileHandle);
		return;
	}
	else
	{
		WCHAR* created = L" Thread created: ";
		WCHAR* deleted = L" Thread deleted: ";
		WCHAR* proc = L" process ";
		WCHAR* pid = L", PID ";
		WCHAR* tid = L", TID ";
		WCHAR* nullterminated = L"\n";

		RtlCopyMemory(buffer, processName->Buffer, processName->MaximumLength);

		int i = 0;
		for (; i < 500; i++)
			if (buffer[i] == '\0')
				break;

		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buf_time, 8 * 2, NULL, NULL);

		if (Create == TRUE)
			status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, created, 16 * 2, NULL, NULL);
		else
			status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, deleted, 16 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, proc, 9 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buffer, i * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, pid, 6 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buf_prc_pid, pid_length * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, tid, 6 * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, buf_thr_tid, tid_length * 2, NULL, NULL);
		status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &iostatus, nullterminated, 1 * 2, NULL, NULL);
		ZwClose(fileHandle);
	}
}


VOID Unload(PDRIVER_OBJECT DriverObject)
{
	PsRemoveCreateThreadNotifyRoutine(NotificatorCallback);
	IoDeleteSymbolicLink(&symbolicName);
	IoDeleteDevice(DeviceObject);
	CmUnRegisterCallback(registerCookie);
	DbgPrint("MyRegDrivevr: Driver unloaded successfully");
}


NTSTATUS DispatchCallback(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (irpsp->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		DbgPrint("MyRegDriver: Create request");
		break;
	}
	case IRP_MJ_CLOSE:
	{
		DbgPrint("MyRegDriver: Close request");
		break;
	}
	default:
	{
		status = STATUS_INVALID_PARAMETER;
		DbgPrint("MyRegDriver: Other request");
		break;
	}
	}

	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = status;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS RegisterAccessRule(const struct AccessRule* rule) {
	strncpy(accessRulesArray[rule_pointer].path, rule->path, strlen(rule->path) + 1);
    accessRulesArray[rule_pointer++].integrityLevel = rule->integrityLevel;
	DbgPrint("Rule %i successfully added: %s", rule_pointer - 1, accessRulesArray[rule_pointer - 1].path);

	if (rule_pointer == rulesCount.count) {
		rule_pointer = 0;
	}
    return STATUS_SUCCESS;
}


NTSTATUS IoctlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION irpsp = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (irpsp->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_UPDATE_RULES:
	{
		DbgPrint("MyRegDriver: IOCTL_UPDATE_RULES receive");

		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG inputBufferLength = irpsp->Parameters.DeviceIoControl.InputBufferLength;

		struct AccessRule* rule = (struct AccessRule*)(inputBuffer);
		
		if ((inputBufferLength % sizeof(struct AccessRule)) != 0) {
		    status = STATUS_INVALID_PARAMETER;
			DbgPrint("MyRegDriver: Error while getting IOCTL update");
		    break;
		}

		status = RegisterAccessRule(rule);
		
		if (!NT_SUCCESS(status)) {
			DbgPrint("MyRegDriver: Failed to register access rule (0x%X)\n", status);
		    break;
		}

		break;
	}

	case IOCTL_UPDATE_RULES_COUNT:
	{
		DbgPrint("MyRegDriver: IOCTL_UPDATE_RULES_COUNT receive");

		PVOID inputBuffer = Irp->AssociatedIrp.SystemBuffer;
		ULONG inputBufferLength = irpsp->Parameters.DeviceIoControl.InputBufferLength;

		struct IoctlInt* _r_count = (struct IoctlInt*)(inputBuffer);

		if ((inputBufferLength % sizeof(struct IoctlInt)) != 0) {
			status = STATUS_INVALID_PARAMETER;
			DbgPrint("MyRegDriver: Error while getting IOCTL update");
			break;
		}

		rulesCount.count = _r_count->count;
		DbgPrint("MyRegDriver: Rules count: %i", rulesCount.count);
		break;
	}

	case IOCTL_NOTIFICATOR_ON:
	{
		DbgPrint("MyRegDriver: IOCTL_NOTIFICATOR_ON receive");
		PsSetCreateThreadNotifyRoutine(NotificatorCallback);
		break;
	}

	case IOCTL_NOTIFICATOR_OFF:
	{
		DbgPrint("MyRegDriver: IOCTL_NOTIFICATOR_OFF receive");
		PsRemoveCreateThreadNotifyRoutine(NotificatorCallback);
		break;
	}

	default:
	{
		status = STATUS_INVALID_PARAMETER;
		break;
	}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}


NTSTATUS RegisterCallbackFunction(PVOID CallbackContext, PVOID Argument1, PVOID Argument2) {
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument2);

	REG_NOTIFY_CLASS Operation = (REG_NOTIFY_CLASS)(ULONG_PTR)Argument1;

	if (!registryCallbackTable[Operation])
	{
		return STATUS_SUCCESS;
	}

	return registryCallbackTable[Operation](CallbackContext, Argument1, Argument2);
}


NTSTATUS RfPreCreateKeyEx(PVOID CallbackContext, PVOID Argument1, PREG_CREATE_KEY_INFORMATION CallbackData) {
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	PUNICODE_STRING pLocalCompleteName = NULL;
	NTSTATUS status;
	PUNICODE_STRING processName = NULL;

	if (CallbackData->CompleteName->Length == 0 || *CallbackData->CompleteName->Buffer != OBJ_NAME_PATH_SEPARATOR)
	{
		PCUNICODE_STRING pRootObjectName;
		status = CmCallbackGetKeyObjectID(&registerCookie, CallbackData->RootObject, NULL, &pRootObjectName);

		if (NT_SUCCESS(status))
		{
			USHORT cbBuffer = pRootObjectName->Length;
			cbBuffer += sizeof(wchar_t);
			cbBuffer += CallbackData->CompleteName->Length;
			ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

			pLocalCompleteName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, cbUString, 'tlFR');
			if (pLocalCompleteName)
			{
				pLocalCompleteName->Length = 0;
				pLocalCompleteName->MaximumLength = cbBuffer;
				pLocalCompleteName->Buffer = (PWCH)((PCCH)pLocalCompleteName + sizeof(UNICODE_STRING));

				RtlCopyUnicodeString(pLocalCompleteName, pRootObjectName);
				RtlAppendUnicodeToString(pLocalCompleteName, L"\\");
				RtlAppendUnicodeStringToString(pLocalCompleteName, CallbackData->CompleteName);
			}

			GetProcessImageName(PsGetCurrentProcess(), &processName);

			DbgPrint("MyRegDriver: RfPreCreateKeyEx via %wZ : %wZ\n", processName, pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName);
		}
	}

	status = CheckAccessToReg(pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName, processName);

	if (status == STATUS_ACCESS_DENIED) {
		DbgPrint("MyRegDriver: Access denied to previous operation(RfPreCreateKeyEx)");
	}

	return status;
}


NTSTATUS RfPreOpenKeyEx(PVOID CallbackContext, PVOID Argument1, PREG_OPEN_KEY_INFORMATION CallbackData) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	PUNICODE_STRING pLocalCompleteName = NULL;
	PUNICODE_STRING processName = NULL;

	if (CallbackData->CompleteName->Length == 0 || *CallbackData->CompleteName->Buffer != OBJ_NAME_PATH_SEPARATOR)
	{
		PCUNICODE_STRING pRootObjectName;
		status = CmCallbackGetKeyObjectID(&registerCookie, CallbackData->RootObject, NULL, &pRootObjectName);

		if (NT_SUCCESS(status))
		{
			USHORT cbBuffer = pRootObjectName->Length;
			cbBuffer += sizeof(wchar_t);
			cbBuffer += CallbackData->CompleteName->Length;
			ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

			pLocalCompleteName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, cbUString, 'tlFR');
			if (pLocalCompleteName)
			{
				pLocalCompleteName->Length = 0;
				pLocalCompleteName->MaximumLength = cbBuffer;
				pLocalCompleteName->Buffer = (PWCH)((PCCH)pLocalCompleteName + sizeof(UNICODE_STRING));

				RtlCopyUnicodeString(pLocalCompleteName, pRootObjectName);
				RtlAppendUnicodeToString(pLocalCompleteName, L"\\");
				RtlAppendUnicodeStringToString(pLocalCompleteName, CallbackData->CompleteName);
			}

			GetProcessImageName(PsGetCurrentProcess(), &processName);

			DbgPrint("MyRegDriver: RfPreOpenKeyEx via %wZ : %wZ\n", processName, pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName);
		}
	}

	status = CheckAccessToReg(pLocalCompleteName ? pLocalCompleteName : CallbackData->CompleteName, processName);

	if (status == STATUS_ACCESS_DENIED) {
		DbgPrint("MyRegDriver: Access denied to previous operation(RfPreOpenKeyEx)");
	}

	return status;
}


NTSTATUS RfPreDeleteKeyEx(PVOID CallbackContext, PVOID Argument1, PREG_DELETE_KEY_INFORMATION CallbackData) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	PUNICODE_STRING pLocalCompleteName = NULL;
	PCUNICODE_STRING ObjectName = NULL;
	PUNICODE_STRING processName = NULL;
	
	if (NT_SUCCESS(CmCallbackGetKeyObjectID(&registerCookie, CallbackData->Object, NULL, &ObjectName))) {
		GetProcessImageName(PsGetCurrentProcess(), &processName);

		DbgPrint("MyRegDriver: RfPreDeleteKeyEx via %wZ : %wZ\n", processName, ObjectName);
	}

	status = CheckAccessToReg(ObjectName, processName);

	if (status == STATUS_ACCESS_DENIED) {
		DbgPrint("MyRegDriver: Access denied to previous operation(RfPreDeleteKeyEx)");
	}

	return status;
}


NTSTATUS RfPreSetValueKeyEx(PVOID CallbackContext, PVOID Argument1, PREG_SET_VALUE_KEY_INFORMATION CallbackData) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(CallbackContext);
	UNREFERENCED_PARAMETER(Argument1);
	PUNICODE_STRING pLocalCompleteName = NULL;
	PUNICODE_STRING processName = NULL;

	if (CallbackData->ValueName->Length == 0 || *CallbackData->ValueName->Buffer != OBJ_NAME_PATH_SEPARATOR)
	{
		PCUNICODE_STRING pRootObjectName;
		status = CmCallbackGetKeyObjectID(&registerCookie, CallbackData->Object, NULL, &pRootObjectName);

		if (NT_SUCCESS(status))
		{
			USHORT cbBuffer = pRootObjectName->Length;
			cbBuffer += sizeof(wchar_t);
			cbBuffer += CallbackData->ValueName->Length;
			ULONG cbUString = sizeof(UNICODE_STRING) + cbBuffer;

			pLocalCompleteName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, cbUString, 'tlFR');
			if (pLocalCompleteName)
			{
				pLocalCompleteName->Length = 0;
				pLocalCompleteName->MaximumLength = cbBuffer;
				pLocalCompleteName->Buffer = (PWCH)((PCCH)pLocalCompleteName + sizeof(UNICODE_STRING));

				RtlCopyUnicodeString(pLocalCompleteName, pRootObjectName);
				RtlAppendUnicodeToString(pLocalCompleteName, L"\\");
				RtlAppendUnicodeStringToString(pLocalCompleteName, CallbackData->ValueName);
			}
			GetProcessImageName(PsGetCurrentProcess(), &processName);

			DbgPrint("MyRegDriver: SetValueKeyEx via %wZ : %wZ\n", processName, pLocalCompleteName ? pLocalCompleteName : CallbackData->ValueName);
		}
	}

	status = CheckAccessToReg(pLocalCompleteName ? pLocalCompleteName : CallbackData->ValueName, processName);

	if (status == STATUS_ACCESS_DENIED) {
		DbgPrint("MyRegDriver: Access denied to previous operation(SetValueKeyEx)");
	}

	return status;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	DriverObject->DriverUnload = Unload;

	status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("MyRegDrivevr: Error while creating device\r\n");
		return status;
	}

	status = IoCreateSymbolicLink(&symbolicName, &deviceName);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("MyRegDrivevr: Error while creating symlink\r\n");
		IoDeleteDevice(DeviceObject);
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
		DriverObject->MajorFunction[i] = DispatchCallback;

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlHandler;

	DbgPrint("MyRegDrivevr: Driver loaded successfully\r\n");

	registryCallbackTable[RegNtPreCreateKeyEx] = (PEX_CALLBACK_FUNCTION) RfPreCreateKeyEx;
	registryCallbackTable[RegNtPreOpenKeyEx] = (PEX_CALLBACK_FUNCTION) RfPreOpenKeyEx;
	registryCallbackTable[RegNtPreDeleteKey] = (PEX_CALLBACK_FUNCTION) RfPreDeleteKeyEx;
	registryCallbackTable[RegNtPreSetValueKey] = (PEX_CALLBACK_FUNCTION) RfPreSetValueKeyEx;

	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"360000");
	status = CmRegisterCallbackEx(RegisterCallbackFunction, &altitude, &DeviceObject, NULL, &registerCookie, NULL);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("MyRegDrivevr: Error while register callback\r\n");
		return status;
	}
	return status;
}
