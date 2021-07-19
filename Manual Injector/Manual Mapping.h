#pragma once

#define ReCa reinterpret_cast

#define NT_STUFF(name) f_##name name

#define INIT_NT_STUFF(nt,name) ReCa<f_##name>(GetProcAddress(nt, #name));

#ifdef _WIN64
#define RELOC_FLAG(info) ((info >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define IMAGE_MACHINE_CHECK(info) info == IMAGE_FILE_MACHINE_AMD64
#else
#define RELOC_FLAG(info) ((info >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define IMAGE_MACHINE_CHECK(info) info == IMAGE_FILE_MACHINE_I386
#endif

#define NT_FAIL(status) (status < 0)
#define NT_SUCCESS(status) (status >= 0)

struct NtStuff {
	NT_STUFF(LdrLoadDll);

	NT_STUFF(RtlAnsiStringToUnicodeString);
	NT_STUFF(LdrGetProcedureAddress);

	NT_STUFF(RtlAllocateHeap);
	NT_STUFF(RtlFreeHeap);

	NT_STUFF(memcpy);
	NT_STUFF(memset);

	PVOID ProcessHeap;
};

struct PdbInfo
{
	DWORD	Signature;
	GUID	Guid;
	DWORD	Age;
	char	PdbFileName[1];
};

struct InjectInfo {
	INT32		FailLine	= -1;
	NTSTATUS	NtStatus	= 0;
	UINT_PTR	ImageBase	= 0;
	BOOL		Success		= false;
};

struct InjectData {
	UINT_PTR	ImageBase;
	NtStuff		N;
	InjectInfo	Info;
};

HANDLE	DefaultStartRoutine(HANDLE handle, PVOID entry, PVOID params);
BOOL	DefaultWriteMemory(HANDLE handle, PVOID address, PVOID buffer, SIZE_T size);
BOOL	DefaultReadMemory(HANDLE handle, PVOID address, PVOID buffer, SIZE_T size);
PVOID	DefaultAllocMemory(HANDLE handle, PVOID address,SIZE_T size);
BOOL	DefaultFreeMemory(HANDLE handle, PVOID address, SIZE_T size);

struct InjectFuncProxy {
	std::function<HANDLE(HANDLE, PVOID, PVOID)>			StartRoutine	= DefaultStartRoutine;
	std::function<BOOL(HANDLE, PVOID, PVOID, SIZE_T)>	ReadMemory		= DefaultReadMemory;
	std::function<BOOL(HANDLE, PVOID, PVOID, SIZE_T)>	WriteMemory		= DefaultWriteMemory;
	std::function<PVOID(HANDLE, PVOID, SIZE_T)>			AllocMemory		= DefaultAllocMemory;
	std::function<BOOL(HANDLE, PVOID, SIZE_T)>			FreeMemory		= DefaultFreeMemory;
};

extern InjectFuncProxy DefaultInjectFuncs;

bool ManualInject(char* data, HANDLE handle, InjectInfo* info = nullptr, const InjectFuncProxy& f = DefaultInjectFuncs);