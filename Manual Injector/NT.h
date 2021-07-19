#pragma once

using PPVOID = void**;

struct UNICODE_STRING {
	WORD		Length;
	WORD		MaxLength;
	wchar_t*	szBuffer;
};

struct ANSI_STRING
{
	USHORT	Length;
	USHORT	MaxLength;
	char*	szBuffer;
};

struct UNICODE_STRING_BOUNDLE {
	UNICODE_STRING String;
	WCHAR Buffer[MAX_PATH];
};

struct CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
};

struct PEB {
	BOOLEAN                 InheritedAddressSpace;
	BOOLEAN                 ReadImageFileExecOptions;
	BOOLEAN                 BeingDebugged;
	BOOLEAN                 Spare;
	HANDLE                  Mutant;
	PVOID                   ImageBaseAddress;
	PVOID					LoaderData;
	PVOID					ProcessParameters;
	PVOID                   SubSystemData;
	PVOID                   ProcessHeap;
	PVOID                   FastPebLock;
	PVOID					FastPebLockRoutine;
	PVOID					FastPebUnlockRoutine;
	ULONG                   EnvironmentUpdateCount;
	PVOID					KernelCallbackTable;
	PVOID                   EventLogSection;
	PVOID                   EventLog;
	PVOID					FreeList;
	ULONG                   TlsExpansionCounter;
	PVOID                   TlsBitmap;
	ULONG                   TlsBitmapBits[0x2];
	PVOID                   ReadOnlySharedMemoryBase;
	PVOID                   ReadOnlySharedMemoryHeap;
	PPVOID                  ReadOnlyStaticServerData;
	PVOID                   AnsiCodePageData;
	PVOID                   OemCodePageData;
	PVOID                   UnicodeCaseTableData;
	ULONG                   NumberOfProcessors;
	ULONG                   NtGlobalFlag;
	BYTE                    Spare2[0x4];
	LARGE_INTEGER           CriticalSectionTimeout;
	ULONG                   HeapSegmentReserve;
	ULONG                   HeapSegmentCommit;
	ULONG                   HeapDeCommitTotalFreeThreshold;
	ULONG                   HeapDeCommitFreeBlockThreshold;
	ULONG                   NumberOfHeaps;
	ULONG                   MaximumNumberOfHeaps;
	PPVOID*					ProcessHeaps;
	PVOID                   GdiSharedHandleTable;
	PVOID                   ProcessStarterHelper;
	PVOID                   GdiDCAttributeList;
	PVOID                   LoaderLock;
	ULONG                   OSMajorVersion;
	ULONG                   OSMinorVersion;
	ULONG                   OSBuildNumber;
	ULONG                   OSPlatformId;
	ULONG                   ImageSubSystem;
	ULONG                   ImageSubSystemMajorVersion;
	ULONG                   ImageSubSystemMinorVersion;
	ULONG                   GdiHandleBuffer[0x22];
	ULONG                   PostProcessInitRoutine;
	ULONG                   TlsExpansionBitmap;
	BYTE                    TlsExpansionBitmapBits[0x80];
	ULONG                   SessionId;
};

struct TEB {
	NT_TIB                  Tib;
	PVOID                   EnvironmentPointer;
	CLIENT_ID               Cid;
	PVOID                   ActiveRpcInfo;
	PVOID                   ThreadLocalStoragePointer;
	PEB*                    Peb;
	ULONG                   LastErrorValue;
	ULONG                   CountOfOwnedCriticalSections;
	PVOID                   CsrClientThread;
	PVOID                   Win32ThreadInfo;
	ULONG                   Win32ClientInfo[0x1F];
	PVOID                   WOW32Reserved;
	ULONG                   CurrentLocale;
	ULONG                   FpSoftwareStatusRegister;
	PVOID                   SystemReserved1[0x36];
	PVOID                   Spare1;
	ULONG                   ExceptionCode;
	ULONG                   SpareBytes1[0x28];
	PVOID                   SystemReserved2[0xA];
	ULONG                   GdiRgn;
	ULONG                   GdiPen;
	ULONG                   GdiBrush;
	CLIENT_ID               RealClientId;
	PVOID                   GdiCachedProcessHandle;
	ULONG                   GdiClientPID;
	ULONG                   GdiClientTID;
	PVOID                   GdiThreadLocaleInfo;
	PVOID                   UserReserved[5];
	PVOID                   GlDispatchTable[0x118];
	ULONG                   GlReserved1[0x1A];
	PVOID                   GlReserved2;
	PVOID                   GlSectionInfo;
	PVOID                   GlSection;
	PVOID                   GlTable;
	PVOID                   GlCurrentRC;
	PVOID                   GlContext;
	NTSTATUS                LastStatusValue;
	UNICODE_STRING          StaticUnicodeString;
	WCHAR                   StaticUnicodeBuffer[0x105];
	PVOID                   DeallocationStack;
	PVOID                   TlsSlots[0x40];
	LIST_ENTRY              TlsLinks;
	PVOID                   Vdm;
	PVOID                   ReservedForNtRpc;
	PVOID                   DbgSsReserved[0x2];
	ULONG                   HardErrorDisabled;
	PVOID                   Instrumentation[0x10];
	PVOID                   WinSockData;
	ULONG                   GdiBatchCount;
	ULONG                   Spare2;
	ULONG                   Spare3;
	ULONG                   Spare4;
	PVOID                   ReservedForOle;
	ULONG                   WaitingOnLoaderLock;
	PVOID                   StackCommit;
	PVOID                   StackCommitMax;
	PVOID                   StackReserved;
};

using f_RtlAnsiStringToUnicodeString = NTSTATUS(__stdcall*)
(
	UNICODE_STRING* DestinationString,
	ANSI_STRING*	SourceString,
	BOOLEAN			AllocateDestinationString
	);

using f_LdrLoadDll = NTSTATUS(__stdcall*)
(
	wchar_t*		szOptPath,
	ULONG			ulFlags,
	UNICODE_STRING* pModuleFileName,
	HMODULE*		pOut
	);

using f_RtlAllocateHeap = PVOID(__stdcall*)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	SIZE_T	Size
	);

using f_RtlFreeHeap = BOOLEAN(__stdcall*)
(
	PVOID	HeapHandle,
	ULONG	Flags,
	PVOID	BaseAddress
	); 

using f_LdrGetProcedureAddress = NTSTATUS(__stdcall*)
(
	PVOID				BaseAddress,
	ANSI_STRING*		Name,
	ULONG				Ordinal,
	PVOID*				ProcedureAddress
	);

using f_memcpy = VOID(__cdecl*)
(
	PVOID		Destination,
	LPCVOID		Source,
	SIZE_T		Length
	);

using f_memset = VOID(__cdecl*)
(
	PVOID		Destination,
	int			Val,
	SIZE_T		Size
	);