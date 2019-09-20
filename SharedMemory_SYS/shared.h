#pragma once

#include <ntdef.h>
#include <ntifs.h>
#include <ntddk.h>
#include <windef.h>
#include <Ntstrsafe.h>
#include <ntddk.h> 
#include <string.h>

#define ABSOLUTE(wait) (wait)

#define RELATIVE(wait) (-(wait))

#define NANOSECONDS(nanos) \
(((signed __int64)(nanos)) / 100L)

#define MICROSECONDS(micros) \
(((signed __int64)(micros)) * NANOSECONDS(1000L))

#define MILLISECONDS(milli) \
(((signed __int64)(milli)) * MICROSECONDS(1000L))

#define SECONDS(seconds) \
(((signed __int64)(seconds)) * MILLISECONDS(1000L))

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        16
#define MM_UNLOADED_DRIVERS_SIZE 50

const WCHAR SharedSectionName[] = L"\\BaseNamedObjects\\SharedMem";

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD DriverUnload;

SECURITY_DESCRIPTOR SecDescriptor;
HANDLE sectionHandle;
PVOID	SharedSection = NULL;
ULONG DaclLength;
PACL Dacl;

HANDLE  SharedEventHandle_trigger = NULL;
PKEVENT SharedEvent_trigger = NULL;
UNICODE_STRING EventName_trigger;

HANDLE  SharedEventHandle_ReadyRead = NULL;
PKEVENT SharedEvent_ReadyRead = NULL;
UNICODE_STRING EventName_ReadyRead;

HANDLE  SharedEventHandle_dt = NULL;
PKEVENT SharedEvent_dt = NULL;
UNICODE_STRING EventName_dt;

ULONGLONG nutzId;
PEPROCESS TargetProcess;
UNICODE_STRING DLLName;

PVOID g_KernelBase = NULL;
ULONG g_KernelSize = 0;


extern NTKERNELAPI ERESOURCE PsLoadedModuleResource;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

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

typedef unsigned char BYTE;
typedef struct _SYSTEM_BASIC_INFORMATION {
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef unsigned long long QWORD;
typedef unsigned short WORD;

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,             // obsolete...delete
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

} SYSTEM_INFORMATION_CLASS;


typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported

typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	//    PVOID			LoadedImports;
	//    // seems they are exist only on XP !!! PVOID
	//    EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _KM_READ_REQUEST
{
	ULONG ProcessId;
	ULONGLONG SourceAddress;
	ULONGLONG Size;
	void* Output;

} KM_READ_REQUEST;

typedef struct _KM_WRITE_REQUEST
{
	ULONG ProcessId;
	ULONG ProcessidOfSource;
	ULONGLONG SourceAddress;
	ULONGLONG TargetAddress;
	ULONGLONG Size;

} KM_WRITE_REQUEST;

typedef struct _SYSTEM_MODULE   // Information Class 11
{
	ULONG_PTR Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION   // Information Class 11
{
	ULONG_PTR ulModuleCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _GET_USERMODULE_IN_PROCESS
{
	ULONG pid;
	ULONGLONG BaseAddress;
} GET_USERMODULE_IN_PROCESS;

typedef struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
}PIDCacheobj;

typedef struct _IMAGE_DATA_DIRECTORY
{
	ULONG VirtualAddress;
	ULONG Size;
} IMAGE_DATA_DIRECTORY, * PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64
{
	USHORT Magic;
	UCHAR MajorLinkerVersion;
	UCHAR MinorLinkerVersion;
	ULONG SizeOfCode;
	ULONG SizeOfInitializedData;
	ULONG SizeOfUninitializedData;
	ULONG AddressOfEntryPoint;
	ULONG BaseOfCode;
	ULONGLONG ImageBase;
	ULONG SectionAlignment;
	ULONG FileAlignment;
	USHORT MajorOperatingSystemVersion;
	USHORT MinorOperatingSystemVersion;
	USHORT MajorImageVersion;
	USHORT MinorImageVersion;
	USHORT MajorSubsystemVersion;
	USHORT MinorSubsystemVersion;
	ULONG Win32VersionValue;
	ULONG SizeOfImage;
	ULONG SizeOfHeaders;
	ULONG CheckSum;
	USHORT Subsystem;
	USHORT DllCharacteristics;
	ULONGLONG SizeOfStackReserve;
	ULONGLONG SizeOfStackCommit;
	ULONGLONG SizeOfHeapReserve;
	ULONGLONG SizeOfHeapCommit;
	ULONG LoaderFlags;
	ULONG NumberOfRvaAndSizes;
	struct _IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, * PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_FILE_HEADER // Size=20
{
	USHORT Machine;
	USHORT NumberOfSections;
	ULONG TimeDateStamp;
	ULONG PointerToSymbolTable;
	ULONG NumberOfSymbols;
	USHORT SizeOfOptionalHeader;
	USHORT Characteristics;
} IMAGE_FILE_HEADER, * PIMAGE_FILE_HEADER;

typedef struct _IMAGE_NT_HEADERS64
{
	ULONG Signature;
	struct _IMAGE_FILE_HEADER FileHeader;
	struct _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, * PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER
{
	UCHAR  Name[8];
	union
	{
		ULONG PhysicalAddress;
		ULONG VirtualSize;
	} Misc;
	ULONG VirtualAddress;
	ULONG SizeOfRawData;
	ULONG PointerToRawData;
	ULONG PointerToRelocations;
	ULONG PointerToLinenumbers;
	USHORT  NumberOfRelocations;
	USHORT  NumberOfLinenumbers;
	ULONG Characteristics;
} IMAGE_SECTION_HEADER, * PIMAGE_SECTION_HEADER;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

typedef struct _MM_UNLOADED_DRIVER
{
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

extern "C" {
	NTKERNELAPI PPEB NTAPI PsGetProcessPeb(IN PEPROCESS Process);

	NTSYSAPI PIMAGE_NT_HEADERS NTAPI RtlImageNtHeader(PVOID Base);

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
}

template <typename t = void*>
t find_pattern(void* start, size_t length, const char* pattern, const char* mask) {
	const auto data = static_cast<const char*>(start);
	const auto pattern_length = strlen(mask);

	for (size_t i = 0; i <= length - pattern_length; i++)
	{
		bool accumulative_found = true;

		for (size_t j = 0; j < pattern_length; j++)
		{
			if (!MmIsAddressValid(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(data) + i + j)))
			{
				accumulative_found = false;
				break;
			}

			if (data[i + j] != pattern[j] && mask[j] != '?')
			{
				accumulative_found = false;
				break;
			}
		}

		if (accumulative_found)
		{
			return (t)(reinterpret_cast<uintptr_t>(data) + i);
		}
	}

	return (t)nullptr;
}

uintptr_t dereference(uintptr_t address, unsigned int offset) {
	if (address == 0)
		return 0;

	return address + (int)((*(int*)(address + offset) + offset) + sizeof(int));
}