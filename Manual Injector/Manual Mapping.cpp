#include "include.h"
#include "Manual Mapping.h"

InjectFuncProxy DefaultInjectFuncs;

__forceinline TEB* GetTEB() {
#ifdef _WIN64
    return ReCa<TEB*>(__readgsqword(0x30));
#else
    return ReCa<TEB*>(__readfsdword(0x18));
#endif 
}

__forceinline PEB* GetPEB() {
    auto TEB = GetTEB();
    if (!TEB) {
        return nullptr;
    }
    return TEB->Peb;
}

__forceinline UINT32 _strlen(const char* szStr) {
    const char* c = szStr;
    while (*(c++)) {}
    return c - szStr - 1;
}

__forceinline bool _strcmp(const char* szStr1, const char* szStr2) {
    while (*szStr1 == *szStr2 &&
        *szStr1 &&
        *szStr2) {
        szStr1++;
        szStr2++;
    }
    return *szStr1 == *szStr2;
}

template <class T>
__forceinline void _delete(NtStuff* n, T* pObj)
{
    if (pObj)
    {
        n->RtlFreeHeap(n->ProcessHeap, NULL, pObj);
    }
}

template <class T>
__forceinline T* _new(NtStuff* n, SIZE_T Count = 1)
{
    return ReCa<T*>(n->RtlAllocateHeap(n->ProcessHeap, HEAP_ZERO_MEMORY, sizeof(T) * Count));
}

__forceinline HMODULE _LoadLibrary(InjectData *params, char* mod_name, InjectInfo* info) {
    auto n = &params->N;
    auto NameA = _new<ANSI_STRING>(n);
    auto NameW = _new<UNICODE_STRING>(n);

    if (!NameA || !NameW) {
        info->FailLine = __LINE__;
        _delete(n, NameA);
        _delete(n, NameW);
        return ReCa<HMODULE>(0);
    }

    auto Len = _strlen(mod_name);

    NameA->Length = Len;
    NameA->MaxLength = Len + 1;
    NameA->szBuffer = mod_name;

    NameW->Length = Len * sizeof(wchar_t);
    NameW->MaxLength = (Len + 1) * sizeof(wchar_t);
    NameW->szBuffer = _new<wchar_t>(n, NameW->MaxLength);

    info->NtStatus = n->RtlAnsiStringToUnicodeString(NameW, NameA, false);

    if (NT_FAIL(params->Info.NtStatus)) {
        info->FailLine = __LINE__;
        _delete(n, NameA);
        _delete(n, NameW->szBuffer);
        _delete(n, NameW);
        return ReCa<HMODULE>(0);
    }

    HMODULE hMod;
    
    info->NtStatus = n->LdrLoadDll(
        nullptr, 
        0,
        NameW,
        &hMod
    );

    _delete(n, NameA);
    _delete(n, NameW->szBuffer);
    _delete(n, NameW);

    if (NT_FAIL(info->NtStatus)) {
        info->FailLine = __LINE__;
        return ReCa<HMODULE>(0);
    }

    return hMod;
}

DWORD __declspec(code_seg(".m")) _Shellcode(InjectData* params) {
    auto    ImageBase       = params->ImageBase;
    auto    DosHeader       = ReCa<PIMAGE_DOS_HEADER>(ImageBase);
    auto    NTHeader        = ReCa<PIMAGE_NT_HEADERS>(ImageBase + DosHeader->e_lfanew);
    auto    FileHeader      = ReCa<PIMAGE_FILE_HEADER>(&NTHeader->FileHeader);
    auto    OptHeader       = ReCa<PIMAGE_OPTIONAL_HEADER>(&NTHeader->OptionalHeader);
    auto    DataDirectory   = ReCa<PIMAGE_DATA_DIRECTORY>(OptHeader->DataDirectory);
    auto    TEB             = GetTEB();
    auto    PEB             = GetPEB();
    auto    n               = &params->N;

    if (!PEB || !TEB) {
        return 0;
    }

    n->ProcessHeap = PEB->ProcessHeap;
    if (!n->ProcessHeap) {
        return 0;
    }

    auto    NTRet           = &params->Info.NtStatus;
    auto    ErrorPtr        = &params->Info;

    // Image relocation
    INT_PTR Delta = ImageBase - OptHeader->ImageBase;
    if (Delta != 0) {
        if (!DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) {
            ErrorPtr->FailLine = __LINE__;
            return 0;
        }

        auto RelocTable = ReCa<PIMAGE_BASE_RELOCATION>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            );

        while (RelocTable->VirtualAddress) {
            auto    RelocBase  = ImageBase + RelocTable->VirtualAddress;
            auto    TypeOffsets = ReCa<WORD*>(RelocTable + 1);
            auto    Count       = (RelocTable->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            for (UINT32 i = 0; i < Count; i++) {
                if (RELOC_FLAG(TypeOffsets[i])) {
                    auto PatchPtr = ReCa<UINT_PTR*>(
                        RelocBase + (TypeOffsets[i] & 0xFFF)
                        );
                    *PatchPtr += Delta;
                }
            }

            RelocTable = ReCa<PIMAGE_BASE_RELOCATION>(
                ReCa<UINT_PTR>(RelocTable) + RelocTable->SizeOfBlock
                );
        }
        OptHeader->ImageBase = ImageBase + Delta;
    }

    // Fix import table
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        auto ImportDesc = ReCa<PIMAGE_IMPORT_DESCRIPTOR>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            );

        while (ImportDesc && ImportDesc->Name) {
            auto        ModName = ReCa<char*>(ImageBase + ImportDesc->Name);
            HMODULE     ModHandle = _LoadLibrary(params, ModName, ErrorPtr);
            if (!ModHandle) {
                return 0;
            }

            auto Thunk = ReCa<IMAGE_THUNK_DATA*>(ImageBase + ImportDesc->OriginalFirstThunk);
            auto IAT   = ReCa<IMAGE_THUNK_DATA*>(ImageBase + ImportDesc->FirstThunk);

            if (!Thunk) {
                Thunk = IAT;
            }

            while (Thunk && Thunk->u1.AddressOfData) {
                UINT_PTR ProcAddress = 0;
                if (IMAGE_SNAP_BY_ORDINAL(Thunk->u1.Ordinal))
                {
                    *NTRet = n->LdrGetProcedureAddress(ReCa<PVOID>(ModHandle), nullptr, IMAGE_ORDINAL(Thunk->u1.Ordinal), ReCa<PVOID*>(&ProcAddress));
                }
                else
                {
                    auto pImport = ReCa<IMAGE_IMPORT_BY_NAME*>(ImageBase + (Thunk->u1.AddressOfData));
                    ANSI_STRING ProcNameA;
                    ProcNameA.Length      = _strlen(pImport->Name);
                    ProcNameA.MaxLength   = ProcNameA.Length + 1;
                    ProcNameA.szBuffer    = pImport->Name;
                    *NTRet = n->LdrGetProcedureAddress(ReCa<PVOID>(ModHandle), &ProcNameA, IMAGE_ORDINAL(Thunk->u1.Ordinal), ReCa<PVOID*>(&ProcAddress));
                }
                if (!ProcAddress || NT_FAIL(*NTRet))
                {
                    ErrorPtr->FailLine = __LINE__;
                    return 0;
                }
                IAT->u1.Function = ProcAddress;
                IAT++; Thunk++;
            }
            ImportDesc++;
        }
    }
    
    // Fix delay import table
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size) {
        PIMAGE_DELAYLOAD_DESCRIPTOR DelayImportDir = reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress
            );
        while (DelayImportDir->DllNameRVA) {
            auto    ModNameA    = ReCa<char*>(ImageBase + DelayImportDir->DllNameRVA);
            HMODULE ModHandle   = _LoadLibrary(params, ModNameA, ErrorPtr);
            if (!ModHandle) {
                return 0;
            }

            if (DelayImportDir->ModuleHandleRVA)
            {
                HMODULE* ModuleHandle = reinterpret_cast<HMODULE*>(ImageBase + DelayImportDir->ModuleHandleRVA);
                *ModuleHandle = ModHandle;
            }

            PIMAGE_THUNK_DATA IAT = reinterpret_cast<PIMAGE_THUNK_DATA>(ImageBase + DelayImportDir->ImportAddressTableRVA);
            PIMAGE_THUNK_DATA NameTable = reinterpret_cast<PIMAGE_THUNK_DATA>(ImageBase + DelayImportDir->ImportNameTableRVA);

            while(IAT->u1.Function) {
                UINT_PTR ProcAddress = 0;
                if (IMAGE_SNAP_BY_ORDINAL(NameTable->u1.Ordinal))
                {
                    *NTRet = n->LdrGetProcedureAddress(ReCa<PVOID>(ModHandle), nullptr, IMAGE_ORDINAL(NameTable->u1.Ordinal), ReCa<PVOID*>(&ProcAddress));
                }
                else
                {
                    auto Import = ReCa<IMAGE_IMPORT_BY_NAME*>(ImageBase + (NameTable->u1.AddressOfData));
                    ANSI_STRING ProcNameA;
                    ProcNameA.Length      = _strlen(Import->Name);
                    ProcNameA.MaxLength   = ProcNameA.Length + 1;
                    ProcNameA.szBuffer    = Import->Name;
                    *NTRet = n->LdrGetProcedureAddress(ReCa<PVOID>(ModHandle), &ProcNameA, IMAGE_ORDINAL(NameTable->u1.Ordinal), ReCa<PVOID*>(&ProcAddress));
                }
                if (!ProcAddress || NT_FAIL(*NTRet))
                {
                    ErrorPtr->FailLine = __LINE__;
                    return 0;
                }
                IAT->u1.Function = ProcAddress; 
                ++IAT, ++NameTable;
            }
            ++DelayImportDir;
        }
    }

    // TLS
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
        auto TlsDir = ReCa<PIMAGE_TLS_DIRECTORY>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
            );

        // ThreadLocalStoragePointer is PVOID[64], if not exists, alloc for it 
        auto TLSP = &TEB->ThreadLocalStoragePointer;

        if (!*TLSP) {
            *TLSP = _new<UINT_PTR>(n, 64);
        }

        if (!*TLSP) {
            ErrorPtr->FailLine = __LINE__;
            return 0;
        }

        // Alloc chunk and copy tls data
        auto DataSize   = TlsDir->EndAddressOfRawData - TlsDir->StartAddressOfRawData;
        auto TlsData    = _new<char>(n, DataSize + 1);

        if (!TlsData) {
            _delete(n, *TLSP);
            ErrorPtr->FailLine = __LINE__;
            return 0;
        }
        n->memcpy(TlsData, ReCa<PVOID>(TlsDir->StartAddressOfRawData), DataSize);

        // ThreadLocalStoragePointer[tls index] should pointr to tls data.

        auto Array  = ReCa<UINT_PTR*>(*TLSP);
        Array[0     = ReCa<UINT_PTR>(TlsData);

        // AddressOfIndex should pointer to tls index.
        auto IndexPtr = _new<UINT_PTR>(n);
        *IndexPtr = 0;
        auto OldIndexPtr = TlsDir->AddressOfIndex;
        TlsDir->AddressOfIndex = ReCa<UINT_PTR>(IndexPtr);

        // Call tls callbacks.
        auto* Callbacks = ReCa<PIMAGE_TLS_CALLBACK*>(TlsDir->AddressOfCallBacks);
        while(Callbacks && (*Callbacks))
        {
            (*(Callbacks++))(ReCa<LPVOID>(ImageBase), DLL_PROCESS_ATTACH, nullptr);
        }

        Array[0] = 0;
        TlsDir->AddressOfIndex = OldIndexPtr;
    }

    if (OptHeader->AddressOfEntryPoint)
    {
        auto DllMain = ReCa<BOOL(__stdcall*)(HINSTANCE, DWORD, void*)>(
            ImageBase + OptHeader->AddressOfEntryPoint
            );
        DllMain(ReCa<HINSTANCE>(ImageBase), DLL_PROCESS_ATTACH, nullptr);
    }

    // Start clear pe headers.
    // 
    // Clear relocation table
    {
        auto RelocTable = ReCa<PIMAGE_BASE_RELOCATION>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
            );

        while (RelocTable->VirtualAddress) {
            auto    Size = RelocTable->SizeOfBlock;
            n->memset(RelocTable, 0, Size);
            RelocTable = ReCa<PIMAGE_BASE_RELOCATION>(
                ReCa<UINT_PTR>(RelocTable) + Size
                );
        }
    }

    // Clear export entrys
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) {
        auto ExportDir = ReCa<PIMAGE_EXPORT_DIRECTORY>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
            );

        auto FunctionsRVAs  = ReCa<INT32*>(ImageBase + ExportDir->AddressOfFunctions);
        auto NamesRVAs      = ReCa<INT32*>(ImageBase + ExportDir->AddressOfNames);
        auto IndicesRVAs    = ReCa<INT16*>(ImageBase + ExportDir->AddressOfNameOrdinals);

        n->memset(FunctionsRVAs, 0, ExportDir->NumberOfFunctions * sizeof(INT32));
        n->memset(NamesRVAs, 0, ExportDir->NumberOfNames * sizeof(INT32));
        n->memset(IndicesRVAs, 0, ExportDir->NumberOfNames * sizeof(INT16));
        n->memset(ExportDir, 0, DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size);
    }

    // Clear import entrys
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress) {
        auto ImportDesc = ReCa<PIMAGE_IMPORT_DESCRIPTOR>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
            );
        n->memset(ImportDesc, 0, DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
    }

    // Clear debug informations
    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress) {
        auto DebugDir = ReCa<PIMAGE_DEBUG_DIRECTORY>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress
            );
        auto Count = DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size / sizeof(IMAGE_DEBUG_DIRECTORY);
        for (SIZE_T i = 0; i < Count; i++) {
            auto Entry = &DebugDir[i];
            auto DebugInfo = ReCa<PdbInfo*>(
                ImageBase + Entry->AddressOfRawData
                );

            auto NameSize = _strlen(DebugInfo->PdbFileName);
            n->memset(DebugInfo, 0, sizeof(PdbInfo) + NameSize);
            n->memset(Entry, 0, sizeof(IMAGE_DEBUG_DIRECTORY));
        }
    }


    if (DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress) {
        auto TlsDir = ReCa<PIMAGE_TLS_DIRECTORY>(
            ImageBase + DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
            );

        auto* pCallback = ReCa<PIMAGE_TLS_CALLBACK*>(TlsDir->AddressOfCallBacks);
        for (; pCallback && (*pCallback); ++pCallback)
        {
            *pCallback = nullptr;
        }

        TlsDir->AddressOfCallBacks = 0;
        TlsDir->AddressOfIndex = 0;
        TlsDir->EndAddressOfRawData = 0;
        TlsDir->SizeOfZeroFill = 0;
        TlsDir->StartAddressOfRawData = 0;
    }

    n->memset(ReCa<PVOID>(ImageBase), 0, 0x1000);
    params->Info.Success    = true;
    params->Info.ImageBase  = ImageBase;

    return 0;
}

void __declspec(code_seg(".m")) _Shellcode_End() {};

#pragma region Inject functions

HANDLE DefaultStartRoutine(HANDLE handle, PVOID entry, PVOID params) {
    return CreateRemoteThread(
        handle,
        nullptr,
        0,
        ReCa<LPTHREAD_START_ROUTINE>(entry),
        params,
        0,
        nullptr
    );
}

BOOL DefaultWriteMemory(HANDLE handle, PVOID address, PVOID buffer, SIZE_T size)
{
    return WriteProcessMemory(handle, address, buffer, size, nullptr);
}

BOOL DefaultReadMemory(HANDLE handle, PVOID address, PVOID buffer, SIZE_T size)
{
    return ReadProcessMemory(handle, address, buffer, size, nullptr);
}

PVOID DefaultAllocMemory(HANDLE handle, PVOID address, SIZE_T size)
{
    return VirtualAllocEx(handle, address, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

BOOL DefaultFreeMemory(HANDLE handle, PVOID address, SIZE_T size)
{
    return VirtualFreeEx(handle, address, 0, MEM_RELEASE);
}

#pragma endregion

bool ManualInject(char* data, HANDLE handle, InjectInfo* info, const InjectFuncProxy& f) {
 /*
                    |-------------------|
  RemoteDataPtr ->  |    Inject Data    | <- RemoteParamsPtr
                    |-------------------|
                    |     Shellcode     | <- RemoteCodePtr
                    |-------------------|
                         ...........
                    |-------------------|
  RemoteModPtr  ->  |    Image Data     |
                    |-------------------|
                         ...........
*/
    auto    DataBase        = ReCa<UINT_PTR>(data);
    auto    DosHeader       = ReCa<PIMAGE_DOS_HEADER>(DataBase);
    auto    NTHeader        = ReCa<PIMAGE_NT_HEADERS>(DataBase + DosHeader->e_lfanew);
    auto    FileHeader      = ReCa<PIMAGE_FILE_HEADER>(&NTHeader->FileHeader);
    auto    OptionHeader    = ReCa<PIMAGE_OPTIONAL_HEADER>(&NTHeader->OptionalHeader);
    auto    Sections        = ReCa<PIMAGE_SECTION_HEADER>(&NTHeader[1]);
    auto    DataDirectory   = ReCa<PIMAGE_DATA_DIRECTORY>(NTHeader->OptionalHeader.DataDirectory);

    auto    Shellcode       = ReCa<char*>(::_Shellcode);
    auto    ShellcodeSize   = ReCa<UINT_PTR>(_Shellcode_End) - ReCa<UINT_PTR>(_Shellcode);

    auto    AllocDataSize   = sizeof(InjectData) + ShellcodeSize;

    auto    RemoteDataPtr   = ReCa<UINT_PTR>(
        f.AllocMemory(handle, nullptr, AllocDataSize)
        );

    auto    RemoteModPtr    = ReCa<UINT_PTR>(
        f.AllocMemory(handle, nullptr, OptionHeader->SizeOfImage)
        );

    if (!RemoteDataPtr || !RemoteModPtr) {
        return false;
    }

    auto    RemoteParamsPtr = RemoteDataPtr;
    auto    RemoteCodePtr   = RemoteParamsPtr + sizeof(InjectData);

    InjectData  Params;
    HMODULE     NTDllHandle = GetModuleHandleA("ntdll.dll");

    if (!NTDllHandle) {
        return false;
    }

    Params.ImageBase                        = RemoteModPtr;
    Params.N.LdrLoadDll                     = INIT_NT_STUFF(NTDllHandle, LdrLoadDll);
    Params.N.RtlAnsiStringToUnicodeString   = INIT_NT_STUFF(NTDllHandle, RtlAnsiStringToUnicodeString);;
    Params.N.RtlAllocateHeap                = INIT_NT_STUFF(NTDllHandle, RtlAllocateHeap);
    Params.N.RtlFreeHeap                    = INIT_NT_STUFF(NTDllHandle, RtlFreeHeap);
    Params.N.memcpy                         = INIT_NT_STUFF(NTDllHandle, memcpy);
    Params.N.memset                         = INIT_NT_STUFF(NTDllHandle, memset);
    Params.N.LdrGetProcedureAddress         = INIT_NT_STUFF(NTDllHandle, LdrGetProcedureAddress);

    if (!(
        Params.N.LdrLoadDll && 
        Params.N.RtlAnsiStringToUnicodeString && 
        Params.N.RtlAllocateHeap && 
        Params.N.RtlFreeHeap && 
        Params.N.LdrGetProcedureAddress &&
        Params.N.memcpy &&
        Params.N.memset
        )) {
        f.FreeMemory(handle, reinterpret_cast<LPVOID>(RemoteDataPtr), 0);
        f.FreeMemory(handle, reinterpret_cast<LPVOID>(RemoteModPtr), 0);
        return false;
    }

    BOOL Result = true;

    Result &= f.WriteMemory(handle, ReCa<LPVOID>(RemoteParamsPtr), &Params, sizeof(InjectData));

    Result &= f.WriteMemory(handle, ReCa<LPVOID>(RemoteCodePtr), Shellcode, ShellcodeSize);

    Result &= f.WriteMemory(handle, ReCa<LPVOID>(RemoteModPtr), DosHeader, sizeof(IMAGE_DOS_HEADER));
    Result &= f.WriteMemory(handle, ReCa<LPVOID>(RemoteModPtr + DosHeader->e_lfanew), NTHeader, sizeof(IMAGE_NT_HEADERS));

    for (UINT32 i = 0; i < FileHeader->NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER Section = &Sections[i];
        Result &= f.WriteMemory(
            handle, 
            ReCa<LPVOID>(RemoteModPtr + Section->VirtualAddress),
            ReCa<LPVOID>(DataBase + Section->PointerToRawData),
            Section->SizeOfRawData
        );
    }

    //Must be all failed or all successed
    if (!Result) {
        f.FreeMemory(handle, ReCa<LPVOID>(RemoteDataPtr), 0);
        f.FreeMemory(handle, ReCa<LPVOID>(RemoteModPtr), 0);
        return false;
    }

    HANDLE hThread = f.StartRoutine(handle, ReCa<PVOID>(RemoteCodePtr), ReCa<PVOID>(RemoteParamsPtr));

    if (!hThread) {
        f.FreeMemory(handle, ReCa<LPVOID>(RemoteDataPtr), 0);
        f.FreeMemory(handle, ReCa<LPVOID>(RemoteModPtr), 0);
        return false;
    }

    auto WaitResult = WaitForSingleObject(hThread, 10000);
    CloseHandle(hThread);


    f.ReadMemory(handle, ReCa<PVOID>(RemoteParamsPtr), &Params, sizeof(InjectData));
    if (WaitResult != WAIT_TIMEOUT) {
        f.FreeMemory(handle, ReCa<LPVOID>(RemoteDataPtr), 0);
    }

    if (info) {
        *info = Params.Info;
    }

    return Params.Info.Success;
}
