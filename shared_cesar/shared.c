#pragma component(browser, off, references)
//#include <ntifs.h> 
//#include <ntddk.h>         // various NT definitions
#include "main.h"
#include "loop.h"
#include "Structs.h"
#include <string.h>
#pragma component(browser, on, references)

#include "shared.h"


DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD SioctlUnloadDriver1;


#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlUnloadDriver1)
#endif // ALLOC_PRAGMA

#pragma region dummy.exe
ULONGLONG nutzId, ModuleBaseAddr;
PEPROCESS TargetProcess;
UNICODE_STRING DLLName;
HANDLE RUSHANDLE;
typedef struct _KERNEL_READ_REQUEST
{
	ULONG ProcessId;
	ULONG64 Address;
	ULONG64 Response;
	ULONG Size;

} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	ULONG ProcessId;

	ULONG Address;
	ULONG Value;
	ULONG Size;

} KERNEL_WRITE_REQUEST, * PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_ID_BASE_REQUEST
{
	ULONGLONG ProcessId;
	ULONGLONG Address;
} KERNEL_ID_BASE_REQUEST, * PKERNEL_ID_BASE_REQUEST;

typedef struct _KERNEL_ZW_VIRTUAL_QUERRY
{
	ULONG ProcessId;
	ULONG64 Address;
	ULONG64 Response;
	ULONG Size;

} KERNEL_ZW_VIRTUAL_QUERRY, * PKERNEL_ZW_VIRTUAL_QUERRY;

NTSTATUS NTAPI MmCopyVirtualMemory
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	return(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, (PSIZE_T)& Bytes));
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, (PSIZE_T)& Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}
NTSTATUS
ZwQuerySystemInformation(
	_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
	_Inout_ PVOID SystemInformation,
	_In_ ULONG SystemInformationLength,
	_Out_opt_  ULONG* ReturnLength);
VOID GetProcessInfo() {

	NTSTATUS status = STATUS_SUCCESS;
	PVOID buffer;

	buffer = ExAllocatePoolWithTag(PagedPool, 1024 * 1024, 'hacK');//mudar para nonpaged e ver se da bsod(23/08/2019)

	if (!buffer) {
		DbgPrintEx(0, 0, "couldn't allocate memory \n");
		return;
	}

	DbgPrintEx(0, 0, "Process list allocated at address %p\n", buffer);

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;


	status = ZwQuerySystemInformation(SystemProcessInformation, pInfo, 1024 * 1024, NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "ZwQuerySystemInformation Failed : STATUS CODE : %X\n", status);
		ExFreePoolWithTag(buffer, 'hacK');
		return;
	}

	UNICODE_STRING WantedImageName;

	RtlInitUnicodeString(&WantedImageName, L"dummy.exe");

	if (NT_SUCCESS(status)) {
		for (;;) {
			DbgPrintEx(0, 0, "\nProcess name: %ws | Process ID: %p\n", pInfo->ImageName.Buffer, pInfo->UniqueProcessId); // Display process information.
			if (RtlEqualUnicodeString(&pInfo->ImageName, &WantedImageName, TRUE)) {
				DbgPrintEx(0, 0, "dummy.exe has just started!\n");
				nutzId = (ULONG64)pInfo->UniqueProcessId;
				break;
			}
			else if (pInfo->NextEntryOffset)
				pInfo = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
			else
				break;
		}
	}
	ExFreePoolWithTag(buffer, 'hacK');
	return;
}

#pragma endregion

#pragma region GetModule

ULONG64 GetModuleBasex64(PEPROCESS proc, UNICODE_STRING module_name) {
	PPEB pPeb = (PPEB)PsGetProcessPeb(proc); // get Process PEB, function is unexported and undoc

	if (!pPeb) {
		return 0; // failed
	}

	KAPC_STATE state;

	KeStackAttachProcess(proc, &state);

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

	if (!pLdr) {
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	// loop the linked list
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
	return 0; // failed
}

#pragma endregion


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
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %X\n", ntStatus);
		ZwClose(sectionHandle);
		return;
	}
}

NTSTATUS CreateSharedMemory() {
	NTSTATUS Status = STATUS_SUCCESS;
	DbgPrintEx(0, 0, "calling CreateSharedMemory...\n");


	Status = RtlCreateSecurityDescriptor(&SecDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "RtlCreateSecurityDescriptor failed : %X\n", Status);
		return Status;
	}
	//DbgPrintEx(0, 0, "RtlCreateSecurityDescriptor was successfully created : %p\n", Status);
	DaclLength = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) * 3 + RtlLengthSid(SeExports->SeLocalSystemSid) + RtlLengthSid(SeExports->SeAliasAdminsSid) +
		RtlLengthSid(SeExports->SeWorldSid);
	Dacl = ExAllocatePoolWithTag(PagedPool, DaclLength, 'lcaD');

	if (Dacl == NULL) {
		DbgPrintEx(0, 0, "ExAllocatePoolWithTag  failed  : %X\n", Status);
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	//DbgPrintEx(0, 0, "ExAllocatePoolWithTag  succeed  : %p\n", Status);
	Status = RtlCreateAcl(Dacl, DaclLength, ACL_REVISION);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlCreateAcl  failed  : %X\n", Status);
		return Status;
	}
	//DbgPrintEx(0, 0, "RtlCreateAcl  succeed  : %p\n", Status);
	Status = RtlAddAccessAllowedAce(Dacl, ACL_REVISION, FILE_ALL_ACCESS, SeExports->SeWorldSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeWorldSid failed  : %X\n", Status);
		return Status;
	}
	//DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeWorldSid succeed  : %p\n", Status);

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeAliasAdminsSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeAliasAdminsSid failed  : %X\n", Status);
		return Status;
	}

	//DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeAliasAdminsSid succeed  : %X\n", Status);

	Status = RtlAddAccessAllowedAce(Dacl,
		ACL_REVISION,
		FILE_ALL_ACCESS,
		SeExports->SeLocalSystemSid);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid failed  : %X\n", Status);
		return Status;
	}

	//DbgPrintEx(0, 0, "RtlAddAccessAllowedAce SeLocalSystemSid succeed  : %X\n", Status);

	Status = RtlSetDaclSecurityDescriptor(&SecDescriptor,
		TRUE,
		Dacl,
		FALSE);

	if (!NT_SUCCESS(Status)) {
		ExFreePool(Dacl);
		DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor failed  : %X\n", Status);
		return Status;
	}

	//DbgPrintEx(0, 0, "RtlSetDaclSecurityDescriptor  succeed  : %X\n", Status);

	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING sectionName;
	RtlInitUnicodeString(&sectionName, SharedSectionName);
	InitializeObjectAttributes(&objAttr, &sectionName, OBJ_CASE_INSENSITIVE, NULL, &SecDescriptor);

	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "last thing  has failed : %X\n", Status);
	}
	//DbgPrintEx(0, 0, "last thing  was successfully created : %X\n", Status);
	//DbgPrintEx(0, 0, "Finished everything...\n");
	//DbgBreakPoint(); // dbg break point here..

	LARGE_INTEGER lMaxSize = { 0 };
	lMaxSize.HighPart = 0;
	lMaxSize.LowPart = 1024 * 10;
	Status = ZwCreateSection(&sectionHandle, SECTION_ALL_ACCESS, &objAttr, &lMaxSize, PAGE_READWRITE, SEC_COMMIT, NULL); // Create section with section handle, object attributes, and the size of shared mem struct
	if (!NT_SUCCESS(Status))
	{
		DbgPrintEx(0, 0, "ZwCreateSection failed: %X\n", Status);
		return Status;
	}
	//DbgPrintEx(0,0,"ZwCreateSection was successfully created: %p\n", Status);

	// my code starts from here xD
	SIZE_T ulViewSize = 1024 * 10;   // &sectionHandle before was here i guess i am correct 
	Status = ZwMapViewOfSection(sectionHandle, NtCurrentProcess(), &SharedSection, 0, ulViewSize, NULL, &ulViewSize, ViewShare, 0, PAGE_READWRITE | PAGE_NOCACHE);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "ZwMapViewOfSection fail! Status: %X\n", Status);
		ZwClose(sectionHandle);
		return Status;
	}

	//DbgPrintEx(0,0,"ZwMapViewOfSection was successfully created: %p\n", Status);

	DbgPrintEx(0, 0, "CreateSharedMemory called finished \n");

	ExFreePool(Dacl); // moved this from line : 274 to here 313 its maybe why its causing the error (would be better if i put this in unload driver)

	return Status;
}

NTSTATUS WriteKernelMemory(PEPROCESS ProcessOfTarget, ULONGLONG SourceAddress, ULONGLONG TargetAddress, SIZE_T Size, KM_WRITE_REQUEST* pdata)
{
	SIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;



	DbgPrintEx(0, 0, "ProcessidOfSource : %u \n", pdata->ProcessidOfSource);

	PEPROCESS ProcessOfSource;
	status = PsLookupProcessByProcessId((HANDLE)pdata->ProcessidOfSource, &ProcessOfSource);
	if (NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success ProcessOfSource address : %p \n", ProcessOfSource);
	}
	else {
		status = STATUS_ACCESS_DENIED;
		ObDereferenceObject(ProcessOfSource);
		DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %X \n", status);
		return status;
	}

	// attaching to my Source Process fixed the problem :D thanks to DARTHON
	// That won't work as you are attaching to the target process. You have to make sure you are in the context of the process that SourceAddress belongs to
	// so just attaching to my UM to get my UM PID AND USE IT TO ATTACH THAT'S IT .

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)ProcessOfSource, &state);
	DbgPrintEx(0, 0, "Calling MmCopyVirtualMemory withtin the source context. \n");
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)SourceAddress, ProcessOfTarget, (PVOID)TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);


	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Error Code... %x\n", status);
		//DbgPrintEx(0, 0,"SourceAddress : %p ProcessOfTarget : %p TargetAddress :  %p Size : %x 
	   //Bytes : 0x%I64X \n", SourceAddress, ProcessOfTarget, TargetAddress, Size, Bytes);
		DbgPrintEx(0, 0, "MmCopyVirtualMemory_Error =  PsGetCurrentProcess : %p \n", PsGetCurrentProcess());
		DbgPrintEx(0, 0, "SourceAddress : 0x%I64X ProcessOfTarget : 0x%I64X \n", SourceAddress, (ULONGLONG)ProcessOfTarget);
		DbgPrintEx(0, 0, "TargetAddress :  0x%I64X Size : 0x%zu\n", TargetAddress, Size);
		DbgPrintEx(0, 0, " Bytes : 0x%zu \n", Bytes);
		return status;
	}
	else
	{
		DbgPrintEx(0, 0, "MmCopyVirtualMemory Success! %X\n", status);
		DbgPrintEx(0, 0, "Bytes : %zu \n", Bytes);
		return status;
	}
}


NTSTATUS ReadKernelMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size) {

	SIZE_T Bytes;
	NTSTATUS status = STATUS_SUCCESS;

	KAPC_STATE state;
	KeStackAttachProcess((PKPROCESS)Process, &state);
	DbgPrintEx(0, 0, "we are inside the context memory... \n");
	DbgPrintEx(0, 0, "Calling MmCopyVirtualMemory... \n");
	status = MmCopyVirtualMemory(PsGetCurrentProcess(), (PVOID)SourceAddress, Process, (PVOID)TargetAddress, Size, KernelMode, &Bytes);
	KeUnstackDetachProcess(&state);

	if (!NT_SUCCESS(status))
	{
		DbgPrintEx(0, 0, "Error Code... %x\n", status);
		DbgPrintEx(0, 0, "__MmCopyVirtualMemory Error || Process : %p ||SourceAddress : %p || PsGetCurrentProcess() : %p || TargetAddress : %p || Size : %zu  Bytes : %zu \n", Process, SourceAddress, PsGetCurrentProcess, TargetAddress, Size, Bytes);
		return status;
	}
	else
	{
		DbgPrintEx(0, 0, "MmCopyVirtualMemory Success! %x\n", status);
		DbgPrintEx(0, 0, "Bytes Read : %zu \n", Bytes);
		return status;
	}
}

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;

PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	DbgPrintEx(0, 0, "Instr :0x%I64X \n", Instr);
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	DbgPrintEx(0, 0, "RipOffset :0x%ld \n", RipOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);
	DbgPrintEx(0, 0, "ResolvedAddr :0x%p\n", ResolvedAddr);
	return ResolvedAddr;
}


NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;

	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}


PVOID GetKernelBase(OUT PULONG pSize)
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG bytes = 0;
	PRTL_PROCESS_MODULES pMods = NULL;
	PVOID checkPtr = NULL;
	UNICODE_STRING routineName;

	// Already found
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

	// Protect from UserMode AV
	//if (bytes != 0)
	PVOID buffer;

	buffer = ExAllocatePoolWithTag(PagedPool, 1024 * 1024, 'hacK');
	if (!buffer) {
		DbgPrintEx(0, 0, "couldn't allocate memory \n");
		return NULL;
	}

	DbgPrintEx(0, 0, "Process list allocated at address %p\n", buffer);

	PSYSTEM_PROCESS_INFORMATION pInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;
	DbgPrintEx(0, 0, "BlackBone: bytes size: %lu \n", bytes);
	status = ZwQuerySystemInformation(SystemModuleInformation, pInfo, 1024 * 1024, &bytes);
	DbgPrintEx(0, 0, "BlackBone: bytes size after: %lu \n", bytes);
	ExFreePoolWithTag(buffer, 'hacK');
	if (bytes == 0)
	{
		DbgPrintEx(0, 0, "BlackBone: Invalid SystemModuleInformation size\n");
		return NULL;
	}

	pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'enoN'); // 'ENON'
	if (pMods == 0)
	{
		DbgPrintEx(0, 0, "BlackBone: Invalid pMods SystemModuleInformation size\n");
		return NULL;
	}
	RtlZeroMemory(pMods, bytes);

	status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

	if (NT_SUCCESS(status))
	{
		PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;

		for (ULONG i = 0; i < pMods->NumberOfModules; i++)
		{
			DbgPrintEx(0, 0, "Name: %s ,Image Base: %p ,Size: %lu \n", pMod[i].FullPathName, pMod[i].ImageBase, pMod[i].ImageSize);
			// System routine is inside module
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

	DbgPrintEx(0, 0, "g_KernelBase : %p\n", g_KernelBase);
	DbgPrintEx(0, 0, "g_KernelSize : %lu\n", g_KernelSize);

	return g_KernelBase;
}


NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound)
{
	ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	PVOID base = GetKernelBase(NULL);
	if (!base)
		return STATUS_NOT_FOUND;


	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status))
				* (PULONGLONG)ppFound = (ULONGLONG)ptr;
			//* (PULONG)ppFound = (ULONG)((PUCHAR)ptr - (PUCHAR)base);
			return status;
		}
	}

	return STATUS_NOT_FOUND;
}

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

// Mmunload shit, get it from frankoo if u want use.
NTSTATUS FindMmDriverData(VOID)
{


	return STATUS_SUCCESS;
}

BOOLEAN IsUnloadedDriverEntryEmpty(_In_ PMM_UNLOADED_DRIVER Entry)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(VOID)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry))
		{
			return FALSE;
		}
	}

	return TRUE;
}


NTSTATUS ClearUnloadedDriver(_In_ PUNICODE_STRING	DriverName, _In_ BOOLEAN	 AccquireResource)
{
	if (AccquireResource)
	{
		ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	}

	BOOLEAN Modified = FALSE;
	if (!IsMmUnloadedDriversFilled())

		for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (Modified)
			{
				//
				// Shift back all entries after modified one.
				//
				PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
				RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

				//
				// Zero last entry.
				//
				if (Index == MM_UNLOADED_DRIVERS_SIZE - 1)
				{
					RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
				}
			}
			else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
			{
				//
				// Erase driver entry.
				//
				//PVOID BufferPool = Entry->Name.Buffer;
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
				//ExFreePoolWithTag(BufferPool, 'TDmM');

				//
				// Because we are erasing last entry we want to set MmLastUnloadedDriver to 49
				// if list have been already filled.
				//
				///*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
				Modified = TRUE;
			}
		}

	if (Modified)
	{
		ULONG64 PreviousTime = 0;

		//
		// Make UnloadTime look right.
		//
		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry))
			{
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime)
			{
				//
				// Decrease by random value here maybe.
				//
				Entry->UnloadTime = PreviousTime - 100;
			}

			PreviousTime = Entry->UnloadTime;
		}

		//
		// Clear remaining entries.
		//
		ClearUnloadedDriver(DriverName, FALSE);
	}

	if (AccquireResource)
	{
		ExReleaseResourceLite(&PsLoadedModuleResource);
	}

	return Modified ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

BOOLEAN LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	//https://www.unknowncheats.me/forum/2396505-post27.html Yes, tested on Windows 10 (1709/1803/1809)
	//if you get bsod here, check sig with IDA pro, after use comands:
	// x nt!PiDDBLock
	// x nt!PiDDBCacheTable
	// In WinDbg64 to check if offsets are ok. Ok? XD
	UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\xE8\xCC\xCC\xCC\xCC\x4C\x8B\x8C\x24\xCC\xCC\xCC\xCC";//working in 1803/1809 11/09/2019
	UCHAR PiDTablePtr_sig[] = "\x48\x8D\x0D\xCC\xCC\xCC\xCC\x4C\x89\x35\xCC\xCC\xCC\xCC\x49\x8B\xE9";//working in 1803/1809 11/09/2019


	PULONG PiDDBLockPtr = NULL;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig, 0xCC, sizeof(PiDDBLockPtr_sig) - 1, (PVOID*)(&PiDDBLockPtr)))) {
		DbgPrintEx(0, 0, "Unable to find PiDDBLockPtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "Ok PiDDBLockPtr sig was found : 0x%p  \n", PiDDBLockPtr);

	RtlZeroMemory(PiDDBLockPtr_sig, sizeof(PiDDBLockPtr_sig) - 1);

	PULONG PiDTablePtr = NULL;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDTablePtr_sig, 0xCC, sizeof(PiDTablePtr_sig) - 1, (PVOID*)(&PiDTablePtr)))) {
		DbgPrintEx(0, 0, "Unable to find PiDTablePtr sig.\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "Ok PiDTablePtr sig was found : 0x%p  \n", PiDTablePtr);

	RtlZeroMemory(PiDTablePtr_sig, sizeof(PiDTablePtr_sig) - 1);

	PULONG RealPtrPIDLock = NULL;
	RealPtrPIDLock = PiDDBLockPtr;
	DbgPrintEx(0, 0, "RealPtrPIDLock :0x%p\n", RealPtrPIDLock);
	*lock = (PERESOURCE)ResolveRelativeAddress((PVOID)RealPtrPIDLock, (ULONG)3, (ULONG)7);

	PULONG RealPtrPIDTable = NULL;

	RealPtrPIDTable = PiDTablePtr;
	DbgPrintEx(0, 0, "RealPtrPIDTable :0x%p\n", RealPtrPIDTable);
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(RealPtrPIDTable, (ULONG)3, (ULONG)7));

	return TRUE;
}

NTSTATUS DriverLoop() {
	NTSTATUS Status = STATUS_SUCCESS;
	while (TRUE)
	{
		ReadSharedMemory();
		DbgPrintEx(0, 0, "running waiting for a command to execute.. Comand readed:  %s  .\n", (PCHAR)SharedSection);

		if (SharedSection != 0 && strcmp((PCHAR)SharedSection, "Stop") == 0) {
			DbgPrintEx(0, 0, "breaking out of the loop\n");
			break;
		}
		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Write") == 0)
		{
			DbgPrintEx(0, 0, "Writing memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();

			KM_WRITE_REQUEST* WriteInput = (KM_WRITE_REQUEST*)SharedSection;
			PEPROCESS Process;

			// DbgPrintEx(0, 0, "%p Pid %u SourcesAddress %p TargetAddress %p Size %x\n", WriteInput, WriteInput->ProcessId, WriteInput->SourceAddress, WriteInput->TargetAddress, WriteInput->Size);

			Status = PsLookupProcessByProcessId((HANDLE)WriteInput->ProcessId, &Process);
			if (NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success! : %X \n", Status);
				DbgPrintEx(0, 0, "Writing memory.\n");
				WriteKernelMemory(Process, WriteInput->SourceAddress, WriteInput->TargetAddress, WriteInput->Size, WriteInput);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %X \n", Status);
				return Status;
			}

			KeResetEvent(SharedEvent_dt);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Read") == 0) {
			DbgPrintEx(0, 0, "Read memory loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);


			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();


			KM_READ_REQUEST* ReadInput = (KM_READ_REQUEST*)SharedSection;
			void* ReadOutput = NULL;
			PEPROCESS Process;

			DbgPrintEx(0, 0, "ReadInput : %p PID : %u SourceAddress : 0x%I64X ReadOutput : %p Size : 0x%I64X \n", ReadInput, ReadInput->ProcessId, ReadInput->SourceAddress, ReadOutput, ReadInput->Size);
			DbgPrintEx(0, 0, "(Before mmcopyvirtualmemory) ReadOutput : %p \n", ReadOutput);

			Status = PsLookupProcessByProcessId((HANDLE)nutzId, &Process);//ReadInput->ProcessId
			if (NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId has success! : %X \n", Status);
				DbgPrintEx(0, 0, "ReadKernelMemory will be called now !.\n");
				ReadKernelMemory(Process, (PVOID)ReadInput->SourceAddress, &ReadOutput, ReadInput->Size);
			}
			else {
				Status = STATUS_ACCESS_DENIED;
				ObDereferenceObject(Process);
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Failed Error code : %X \n", Status);
				return Status;
			}

			ReadInput->Output = ReadOutput;

			ReadSharedMemory();
			if (0 == memcpy(SharedSection, ReadInput, sizeof(KM_READ_REQUEST))) {
				DbgPrintEx(0, 0, "memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
			KeSetEvent(SharedEvent_trigger, 0, FALSE);
			break;
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Clearmm") == 0) {
			DbgPrintEx(0, 0, "Clear Mmunloaded Drivers memory loop is running\n");

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);

			// should work fine
			FindMmDriverData();
			// we need to find MmLastUnloadedDriverInstr  pattern. newest one
			//	UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"Capcom.sys");
			//	ClearUnloadedDriver(&DriverName, TRUE);

			DbgPrintEx(0, 0, "MMunload cleared check with lm command\n");
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "getBase") == 0) {
			DbgPrintEx(0, 0, "getBase loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);
			ReadSharedMemory();


			GET_USERMODULE_IN_PROCESS* getbase = (GET_USERMODULE_IN_PROCESS*)SharedSection;

			NTSTATUS status = STATUS_SUCCESS;
			//PEPROCESS TargetProcess;
			status = PsLookupProcessByProcessId((HANDLE)getbase->pid, &TargetProcess);//getbase->pid
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId failed\n");
			}
			else
			{
				DbgPrintEx(0, 0, "PsLookupProcessByProcessId Success!\n");
			}

			RtlInitUnicodeString(&DLLName, L"dummy.dll");//can be .dll or .exe
			getbase->BaseAddress = GetModuleBasex64(TargetProcess, DLLName);


			DbgPrintEx(0, 0, "getbase->BaseAddress is : 0x%I64X \n", getbase->BaseAddress);

			ReadSharedMemory();

			if (0 == memcpy(SharedSection, getbase, sizeof(GET_USERMODULE_IN_PROCESS))) {
				DbgPrintEx(0, 0, "memcpy failed \n");
			}

			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}

		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Clearpid") == 0) {
			DbgPrintEx(0, 0, "Clearpid loop is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);


			PERESOURCE PiDDBLock = NULL;
			PRTL_AVL_TABLE PiDDBCacheTable = NULL;
			if (!LocatePiDDB(&PiDDBLock, &PiDDBCacheTable) && PiDDBLock == NULL && PiDDBCacheTable == NULL) {
				DbgPrintEx(0, 0, "LocatePiDDB() failed..\n");

				ReadSharedMemory();
				PCHAR TestString = "failed2clear";
				if (0 == memcpy(SharedSection, TestString, 12)) {
					DbgPrintEx(0, 0, "memcpy failed \n");
				}
				else
				{
					DbgPrintEx(0, 0, "Sent ClearPID_fail msg\n");
					KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
				}
				KeResetEvent(SharedEvent_ReadyRead);
				return STATUS_UNSUCCESSFUL;
			}
			else
			{
				DbgPrintEx(0, 0, "LocatePiDDB() SUCCESS!!!!!..\n");
				DbgPrintEx(0, 0, "PiDDBLock :%p \n", PiDDBLock);
				DbgPrintEx(0, 0, "PiDDBCacheTable :%p\n", PiDDBCacheTable);
				// build a lookup entry

				PIDCacheobj lookupEntry;
				/*capcom.sys(drvmap) : 0x57CD1415 iqvw64e.sys(kdmapper) : 0x5284EAC3, also cpuz driver*/
				// this should work :D
				UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"capcom.sys");//Capcom.sys
				// removed *DriverName no need for it
				lookupEntry.DriverName = DriverName;
				lookupEntry.TimeDateStamp = 0x57CD1415; // capcom TimeStamp. 

				// aquire the ddb lock
				if (PiDDBLock != 0)
					ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);
				else
					return STATUS_UNSUCCESSFUL;
				// search our entry in the table

				// maybe something will bsod here.
				PIDCacheobj* pFoundEntry = (PIDCacheobj*)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &lookupEntry);
				if (pFoundEntry == NULL)
				{
					DbgPrintEx(0, 0, "pFoundEntry == NULL\n");
					// release the ddb resource lock
					ExReleaseResourceLite(PiDDBLock);

				#pragma region deleteThis
					//delete this region is only for tests
					ReadSharedMemory();
					PCHAR pidstring = "ClearedPoDfake";
					if (0 == memcpy(SharedSection, pidstring, 14)) {
						DbgPrintEx(0, 0, "memcpy failed \n");
					}
					else
					{
						DbgPrintEx(0, 0, "Sent clearedpid fake msg\n");
						KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
					}
				#pragma endregion
				}
				else
				{
					DbgPrintEx(0, 0, "pFoundEntry Found!\n");
					// first, unlink from the list
					RemoveEntryList(&pFoundEntry->List);
					// then delete the element from the avl table
					RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);

					// release the ddb resource lock
					ExReleaseResourceLite(PiDDBLock);

					ReadSharedMemory();
					PCHAR pidstring = "ClearedPID";
					if (0 == memcpy(SharedSection, pidstring, 10)) {
						DbgPrintEx(0, 0, "memcpy failed \n");
					}
					else
					{
						DbgPrintEx(0, 0, "Sent clearedpid msg\n");
						KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
					}

				}
			}
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
			return STATUS_UNSUCCESSFUL;//delete this is only for tests.
		}
		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "Clearmm") == 0) {

			DbgPrintEx(0, 0, "Clearmm loop2 is running\n");

			KeSetEvent(SharedEvent_dt, 0, FALSE);

			LARGE_INTEGER Timeout;
			Timeout.QuadPart = RELATIVE(SECONDS(1));
			KeDelayExecutionThread(KernelMode, FALSE, &Timeout);


			FindMmDriverData();

			UNICODE_STRING DriverName = RTL_CONSTANT_STRING(L"Capcom.sys");//Capcom.sys
			if (!NT_SUCCESS(ClearUnloadedDriver(&DriverName, TRUE))) {
				DbgPrintEx(0, 0, "ClearUnloadedDriver failed.\n");
			}
			else
			{	// signal um here
				ReadSharedMemory();
				PCHAR TestString = "Cleared";
				if (0 == memcpy(SharedSection, TestString, 7)) {
					DbgPrintEx(0, 0, "memcpy failed \n");
				}
				else
				{
					DbgPrintEx(0, 0, "Sent Clear msg\n");
					KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
				}
				DbgPrintEx(0, 0, "ClearUnloadedDriver SUCCESS!.\n");
			}
			KeResetEvent(SharedEvent_dt);
			KeResetEvent(SharedEvent_ReadyRead);
		}
		while ((PCHAR)SharedSection != NULL && strcmp((PCHAR)SharedSection, "TestWaitEventKernel") == 0) {
			LARGE_INTEGER Timeout2;
			Timeout2.QuadPart = RELATIVE(SECONDS(4 * 60));//wait 4 minutes, because infinite would "block" you from unload driver.
			KeWaitForSingleObject(SharedEvent_ReadyRead, Executive, KernelMode, FALSE, &Timeout2);
			DbgPrintEx(0, 0, " Event was setted. \n");
			KeResetEvent(SharedEvent_ReadyRead);// you can reset this in user mode.
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
		DbgPrintEx(0, 0, "It didn't work lol !, %X \n", status);
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&EventName_trigger, L"\\BaseNamedObjects\\trigger");
	SharedEvent_trigger = IoCreateNotificationEvent(&EventName_trigger, &SharedEventHandle_trigger);
	if (SharedEvent_trigger == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol !, %X \n", status);
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&EventName_ReadyRead, L"\\BaseNamedObjects\\ReadyRead");
	SharedEvent_ReadyRead = IoCreateNotificationEvent(&EventName_ReadyRead, &SharedEventHandle_ReadyRead);
	if (SharedEvent_ReadyRead == NULL) {
		DbgPrintEx(0, 0, "It didn't work lol !, %X \n", status);
		return STATUS_UNSUCCESSFUL;
	}
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriverObject, IN PUNICODE_STRING pRegistryPath) {
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(pRegistryPath);
	GetProcessInfo();//grava no nutzId o id atual 
	pDriverObject->DriverUnload = driverUnload1;
	DbgPrintEx(0, 0, "Driver loaded !!\n");
	if (NT_SUCCESS(CreateSharedMemory())) {
		if (NT_SUCCESS(OpenEvents())) {
			//your driver was loaded successfully, send event to advise usermore!
			KeSetEvent(SharedEvent_ReadyRead, 0, FALSE);
			DriverLoop();
		}
		else
			DbgPrintEx(0, 0, "Shit Happens!\n");
	}
	DbgPrintEx(0, 0, "driver entry completed!\n");

	return status;
}

void driverUnload1(IN PDRIVER_OBJECT pDriverObject) {

	if (SharedSection)
		ZwUnmapViewOfSection(NtCurrentProcess(), SharedSection);

	if (sectionHandle)
		ZwClose(sectionHandle);

	DbgPrintEx(0, 0, "Driver Unloading routine called! \n");
	UNREFERENCED_PARAMETER(pDriverObject);
}
