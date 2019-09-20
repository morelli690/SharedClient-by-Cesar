#include "shared.h"

VOID GetProcessInfo() {
	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer;

	buffer = ExAllocatePool(PagedPool, 1024 * 1024);

	if (!buffer) {
		DbgPrint("couldn't allocate memory \n");
		return;
	}

	DbgPrint("Process list allocated at address %p\n", buffer);

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

	status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrint("ZwQuerySystemInformation Failed : STATUS CODE : %X\n", status);
		ExFreePool(buffer);
		return;
	}

	UNICODE_STRING WantedImageName;

	RtlInitUnicodeString(&WantedImageName, L"dummy.exe");

	if (NT_SUCCESS(status)) {
		for (;;) {
			DbgPrint("\nProcess name: %ws | Process ID: %p\n", pInfo->ImageName.Buffer, pInfo->UniqueProcessId); // Display process information.
			if (RtlEqualUnicodeString(&pInfo->ImageName, &WantedImageName, TRUE)) {
				DbgPrint("dummy.exe has just started!\n");
				nutzId = (ULONG64)pInfo->UniqueProcessId;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}
	ExFreePool(buffer);
	return;
}

ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = (PPEB)PsGetProcessPeb(proc);

	if (!pPeb)
		return 0;

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0;
	}

	for (PLIST_ENTRY list = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
		list != &pLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PLDR_DATA_TABLE_ENTRY pEntry =
			CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&pEntry->BaseDllName, &module_name, TRUE) == 0) {
			ULONG64 baseAddr = (ULONG64)pEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}
	}

	KeUnstackDetachProcess(&state);
	return 0;
}

VOID ReadSharedMemory()
{
	if (sectionHandle == NULL || sectionHandle)
		return;

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	SIZE_T ulViewSize = 1024 * 10;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (ntStatus != STATUS_SUCCESS)
	{
		DbgPrint("ZwMapViewOfSection fail! Status: %X\n", ntStatus);
		ZwClose(sectionHandle);
		return;
	}
}

NTSTATUS CreateSharedMemory() {
	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrint("calling CreateSharedMemory...\n");

	Status = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("RtlCreateSecurityDescriptor failed : %X\n", Status);
		return Status;
	}

	DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) + RtlLengthSid(SeExports->SeWorldSid);
	Dacl = (PACL)ExAllocatePool(PagedPool, DaclLength);

	if (Dacl == NULL) {
		DbgPrint("ExAllocatePoolWithTag  failed  : %X\n", Status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	Status = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlCreateAcl  failed  : %X\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeWorldSid failed  : %X\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %X\n", Status);
		return Status;
	}

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlAddAccessAllowedAce SeLocalSystemSid failed  : %X\n", Status);
		return Status;
	}

	Status = RtlSetDaclSecurityDescriptor(&SecDescriptor,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrint("RtlSetDaclSecurityDescriptor failed  : %X\n", Status);
		return Status;
	}

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, SharedSectionName);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor);

	if (!NT_SUCCESS(Status)) {
		DbgPrint("last thing  has failed : %X\n", Status);
	}

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	Status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("ZwCreateSection failed: %X\n", Status);
		return Status;
	}

	SIZE_T ulViewSize = 1024 * 10;
	Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("ZwMapViewOfSection fail! Status: %X\n", Status);
		ZwClose(sectionHandle);
		return Status;
	}

	DbgPrint("CreateSharedMemory called finished \n");

	ExFreePool(Dacl);

	return Status;
}

NTSTATUS WriteKernelMemory(PEPROCESS ProcessOfTarget, ULONGLONG SourceAddress, ULONGLONG TargetAddress, SIZE_T Size, KM_WRITE_REQUEST* pdata)
{
	SIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("ProcessidOfSource : %u \n", pdata->ProcessidOfSource);

	PEPROCESS ProcessOfSource;
	status = PsLookupProcessByProcessId((HANDLE)pdata->ProcessidOfSource, &ProcessOfSource);
	if (NT_SUCCESS(status)) {
		DbgPrint("PsLookupProcessByProcessId has success ProcessOfSource address : %p \n", ProcessOfSource);
	}
	else {
		status = STATUS_ACCESS_DENIED;
		ObDereferenceObject(ProcessOfSource);
		DbgPrint("PsLookupProcessByProcessId Failed Error code : %X \n", status);
		return status;
	}

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)ProcessOfSource, &state);
	DbgPrint("Calling MmCopyVirtualMemory withtin the source context. \n");
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)SourceAddress, ProcessOfTarget, (PVOID)TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);


	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error Code... %x\n", status);
		DbgPrint("MmCopyVirtualMemory_Error =  PsGetCurrentProcess : %p \n", PsGetCurrentProcess());
		DbgPrint("SourceAddress : 0x%I64X ProcessOfTarget : 0x%I64X \n", SourceAddress, (ULONGLONG)ProcessOfTarget);
		DbgPrint("TargetAddress :  0x%I64X Size : 0x%zu\n", TargetAddress, Size);
		DbgPrint(" Bytes : 0x%zu \n", Bytes);
		return status;
	}
	else
	{
		DbgPrint("MmCopyVirtualMemory Success! %X\n", status);
		DbgPrint("Bytes : %zu \n", Bytes);
		return status;
	}
}

NTSTATUS ReadKernelMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {

	SIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)Process, &state);
	DbgPrint("we are inside the context memory... \n");
	DbgPrint("Calling MmCopyVirtualMemory... \n");
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)SourceAddress, Process, (PVOID)TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status))
	{
		DbgPrint("Error Code... %x\n", status);
		DbgPrint("__MmCopyVirtualMemory Error || Process : %p ||SourceAddress : %p || PsGetCurrentProcess() : %p || TargetAddress : %p || Size : %zu  Bytes : %zu \n", Process, SourceAddress, PsGetCurrentProcess, TargetAddress, Size, Bytes);
		return status;
	}
	else
	{
		DbgPrint("MmCopyVirtualMemory Success! %x\n", status);
		DbgPrint("Bytes Read : %zu \n", Bytes);
		return status;
	}
}

PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	if (g_KernelBase != NULL)
	{
		if (pSize)
			* pSize = g_KernelSize;
		return g_KernelBase;
	}

	RtlUnicodeStringInit(&routineName, L"NtOpenFile");

	checkPtr = MmGetSystemRoutineAddress(&routineName);
	if (checkPtr == NULL)
		return NULL;

	PVOID buffer;

	buffer = ExAllocatePoolWithTag(PagedPool, 1024 * 1024, 'hacK');
	if (!buffer) {
		DbgPrint("couldn't allocate memory \n");
		return NULL;
	}

	DbgPrint("Process list allocated at address %p\n", buffer);

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	DbgPrint("BlackBone: bytes size: %lu \n", bytes);
	status = ZwQuerySystemInformation(SystemModuleInformation, pInfo, 1024 * 1024, &bytes);
	DbgPrint("BlackBone: bytes size after: %lu \n", bytes);
	ExFreePoolWithTag(buffer, 'hacK');
	if (bytes == 0)
	{
		DbgPrint("BlackBone: Invalid SystemModuleInformation size\n");
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'enoN'); // 'ENON'
	if (pMods == 0)
	{
		DbgPrint("BlackBone: Invalid pMods SystemModuleInformation size\n");
		return NULL;
	}
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			DbgPrint("Name: %s ,Image Base: %p ,Size: %lu \n", pMod[i].FullPathName, pMod[i].ImageBase, pMod[i].ImageSize);

			if (checkPtr >= pMod[i].ImageBase &&
				checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
			{
				g_KernelBase = pMod[i].ImageBase;
				g_KernelSize = pMod[i].ImageSize;
				if (pSize)
					* pSize = g_KernelSize;
				break;
			}
		}
	}

	if (pMods)
		ExFreePoolWithTag(pMods, 'enoN'); // 'ENON'

	DbgPrint("g_KernelBase : %p\n", g_KernelBase);
	DbgPrint("g_KernelSize : %lu\n", g_KernelSize);

	return g_KernelBase;
}

static uintptr_t GetKernelAddress(const char* name, size_t& size) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, neededSize);

	if (!pModuleList) {
		DbgPrint("ExAllocatePoolWithTag failed(kernel addr)\n");
		return 0;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	ULONG i = 0;
	uintptr_t address = 0;

	for (i = 0; i < pModuleList->ulModuleCount; i++)
	{
		SYSTEM_MODULE mod = pModuleList->Modules[i];

		address = uintptr_t(pModuleList->Modules[i].Base);
		size = uintptr_t(pModuleList->Modules[i].Size);
		if (strstr(mod.ImageName, name) != NULL)
			break;
	}

	ExFreePool(pModuleList);

	return address;
}

NTSTATUS DriverLoop() {
	NTSTATUS Status = STATUS_SUCCESS;
	while (TRUE)
	{
		ReadSharedMemory();
		DbgPrint("running waiting for a command to execute.. Comand readed:  %s  .\n", (PCHAR)SharedSection);

		if (SharedSection != 0 && strcmp((PCHAR)SharedSection, "Stop") == 0) {
			DbgPrint("breaking out of the loop\n");
			break;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Write") == 0)
		{
			DbgPrint("Writing memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			KM_WRITE_REQUEST* WriteInput = (KM_WRITE_REQUEST*)SharedSection;
			PEPROCESS Process;

			Status = PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				DbgPrint("PsLookupProcessByProcessId has success! : %X \n", Status);
				DbgPrint("Writing memory.\n");
				WriteKernelMemory(Process, WriteInput->SourceAddress, WriteInput->TargetAddress, WriteInput->Size, WriteInput);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrint("PsLookupProcessByProcessId Failed Error code : %X \n", Status);
				return Status;
			}

			KeResetEvent(SharedEvent_dt);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Read") == 0) {
			DbgPrint("Read memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			KM_READ_REQUEST* ReadInput = (KM_READ_REQUEST*)SharedSection;
			void* ReadOutput = NULL;
			PEPROCESS Process;

			DbgPrint("ReadInput : %p PID : %u SourceAddress : 0x%I64X ReadOutput : %p Size : 0x%I64X \n", ReadInput, ReadInput->ProcessId, ReadInput->SourceAddress, ReadOutput, ReadInput->Size);
			DbgPrint("(Before mmcopyvirtualmemory) ReadOutput : %p \n", ReadOutput);

			Status = PsLookupProcessByProcessId((HANDLE)nutzId, &Process);
			if (NT_SUCCESS(Status)) {
				DbgPrint("PsLookupProcessByProcessId has success! : %X \n", Status);
				DbgPrint("ReadKernelMemory will be called now !.\n");
				ReadKernelMemory(Process, (PVOID)ReadInput->SourceAddress, &ReadOutput, ReadInput->Size);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrint("PsLookupProcessByProcessId Failed Error code : %X \n", Status);
				return Status;
			}

			ReadInput->Output = ReadOutput;

			ReadSharedMemory();
			if (0 == memcpy(SharedSection, ReadInput, sizeof(KM_READ_REQUEST))) {
				DbgPrint("memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "getBase") == 0) {
			DbgPrint("getBase loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();


			GET_USERMODULE_IN_PROCESS* getbase = (GET_USERMODULE_IN_PROCESS*)SharedSection;

			NTSTATUS status = STATUS_SUCCESS;

			status = PsLookupProcessByProcessId((HANDLE)getbase->pid, &TargetProcess);
			if (!NT_SUCCESS(status)) {
				DbgPrint("PsLookupProcessByProcessId failed\n");
			}
			else
			{
				DbgPrint("PsLookupProcessByProcessId Success!\n");
			}

			RtlInitUnicodeString(&DLLName, L"dummy.dll");
			getbase->BaseAddress = GetModuleBasex64(TargetProcess, DLLName);

			DbgPrint("getbase->BaseAddress is : 0x%I64X \n", getbase->BaseAddress);

			ReadSharedMemory();

			if (0 == memcpy(SharedSection, getbase, sizeof(GET_USERMODULE_IN_PROCESS))) {
				DbgPrint("memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "ClearPiDDBCacheTable") == 0) {
			DbgPrint("clean_piddb_cache started!");
			PRTL_AVL_TABLE PiDDBCacheTable;

			size_t size;
			uintptr_t ntoskrnlBase = GetKernelAddress("ntoskrnl.exe", size);

			DbgPrint("ntoskrnl.exe: %d\n", ntoskrnlBase);
			DbgPrint("ntoskrnl.exe size: %d\n", size);

			PiDDBCacheTable = (PRTL_AVL_TABLE)dereference(find_pattern<uintptr_t>((void*)ntoskrnlBase, size, "\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\x3d\x00\x00\x00\x00\x0f\x83", "xxx????x????x????xx"), 3);

			DbgPrint("PiDDBCacheTable: %d\n", PiDDBCacheTable);

			if (!PiDDBCacheTable) {
				DbgPrint("PiDDBCacheTable equals 0\n");
				return 0;
			}

			uintptr_t entry_address = uintptr_t(PiDDBCacheTable->BalancedRoot.RightChild) + sizeof(RTL_BALANCED_LINKS);
			DbgPrint("entry_address: %d\n", entry_address);

			PiDDBCacheEntry* entry = (PiDDBCacheEntry*)(entry_address);

			/*capcom.sys(drvmap) : 0x57CD1415 iqvw64e.sys(kdmapper) : 0x5284EAC3, also cpuz driver*/
			if (entry->TimeDateStamp == 0x57CD1415 || entry->TimeDateStamp == 0x5284EAC3) {
				entry->TimeDateStamp = 0x54EAC3;
				entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
			}

			ULONG count = 0;
			for (auto link = entry->List.Flink; link != entry->List.Blink; link = link->Flink, count++)
			{
				PiDDBCacheEntry* cache_entry = (PiDDBCacheEntry*)(link);

				DbgPrint("cache_entry count: %lu name: %wZ \t\t stamp: %x\n",
					count,
					cache_entry->DriverName,
					cache_entry->TimeDateStamp);

				if (cache_entry->TimeDateStamp == 0x57CD1415 || cache_entry->TimeDateStamp == 0x5284EAC3) {
					cache_entry->TimeDateStamp = 0x54EAC4 + count;
					cache_entry->DriverName = RTL_CONSTANT_STRING(L"monitor.sys");
				}
			}

			DbgPrint("clean_piddb_cache finished!");
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "ClearMMUnloadedDrivers") == 0) {
			DbgPrint("clean_uloaded_drivers started!\n");
			ULONG bytes = 0;
			auto status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

			if (!bytes)
				return 0;

			PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePool(NonPagedPool, bytes);

			status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

			if (!NT_SUCCESS(status)) {
				DbgPrint("ZwQuerySystemInformation failed(unloaded drivers)\n");
				ExFreePool(modules);
				return 0;
			}

			PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
			uintptr_t ntoskrnlBase = 0;
			size_t ntoskrnlSize = 0;

			ntoskrnlBase = GetKernelAddress("ntoskrnl.exe", ntoskrnlSize);

			ExFreePool(modules);

			if (ntoskrnlBase <= 0) {
				DbgPrint("get_kernel_address failed(unloaded drivers)\n");
				return 0;
			}

			// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3 + current signature address = MmUnloadedDrivers
			auto mmUnloadedDriversPtr = find_pattern<uintptr_t>((void*)ntoskrnlBase, ntoskrnlSize, "\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

			DbgPrint("mmUnloadedDriversPtr: %d\n", mmUnloadedDriversPtr);

			if (!mmUnloadedDriversPtr) {
				DbgPrint("mmUnloadedDriversPtr equals 0(unloaded drivers)\n");
				return 0;
			}

			uintptr_t mmUnloadedDrivers = dereference(mmUnloadedDriversPtr, 3);

			memset(*(uintptr_t**)mmUnloadedDrivers, 0, 0x7D0);

			DbgPrint("clean_uloaded_drivers finished!\n");

			return 1;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "TestWaitEventKernel") == 0) {
			LARGE_INTEGER Timeout2;
			Timeout2.QuadPart = RELATIVE(SECONDS(4 * 60));
			KeWaitForSingleObject(SharedEvent_ReadyRead, Executive, KernelMode, FALSE, &Timeout2);
			DbgPrint(" Event was setted. \n");
			KeResetEvent(SharedEvent_ReadyRead);
		}

		LARGE_INTEGER Timeout;
		Timeout.QuadPart = RELATIVE(SECONDS(1));
		KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
	}
	return Status;
}

NTSTATUS OpenEvents() {

	NTSTATUS status = STATUS_SUCCESS;

	RtlInitUnicodeString(&EventName_dt, L"\\BaseNamedObjects\\DataArrived");
	SharedEvent_dt = IoCreateNotificationEvent(&EventName_dt, &SharedEventHandle_dt);
	if (SharedEvent_dt == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&EventName_trigger, L"\\BaseNamedObjects\\trigger");
	SharedEvent_trigger = IoCreateNotificationEvent(&EventName_trigger, &SharedEventHandle_trigger);
	if (SharedEvent_trigger == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&EventName_ReadyRead, L"\\BaseNamedObjects\\ReadyRead");
	SharedEvent_ReadyRead = IoCreateNotificationEvent(&EventName_ReadyRead, &SharedEventHandle_ReadyRead);
	if (SharedEvent_ReadyRead == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pRegistryPath);

	GetProcessInfo();

	pDriverObject->DriverUnload = DriverUnload;

	DbgPrint("Driver loaded !!\n");

	if (NT_SUCCESS(CreateSharedMemory())) {
		if (NT_SUCCESS(OpenEvents())) {
			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			DriverLoop();
		}
		else
			DbgPrint("Shit Happens!\n");
	}

	DbgPrint("driver entry completed!\n");

	return status;
}

void DriverUnload(IN PDRIVER_OBJECT pDriverObject) {
	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);

	DbgPrint("Driver Unloading routine called! \n");
	UNREFERENCED_PARAMETER(pDriverObject);
}
