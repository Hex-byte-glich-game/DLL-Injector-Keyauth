#pragma once
#include "Injections.h"
#include <Windows.h>
#include <iostream>
#include <string>

#pragma warning(disable : 6385)

// Define architecture
#ifdef _WIN64
#define CURRENT_ARCH IMAGE_FILE_MACHINE_AMD64
#else
#define CURRENT_ARCH IMAGE_FILE_MACHINE_I386
#endif


void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);

bool ManualMap(HANDLE hProc, const BYTE* pSrcData) { // Changed to const BYTE*
    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    BYTE* pTargetBase = nullptr;

    // Check for valid PE file
    const IMAGE_DOS_HEADER* pDosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(pSrcData);
    if (pDosHeader->e_magic != 0x5A4D) { // "MZ"
        std::cerr << "Invalid file" << std::endl;
        return false;
    }

    //pOldNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHeader->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;

    if (pOldFileHeader->Machine != CURRENT_ARCH) {
        std::cerr << "Invalid platform" << std::endl;
        return false;
    }

    std::cout << "File ok" << std::endl;

    // Allocate memory in the target process
    pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, pOldOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase) {
        std::cerr << "Target process memory allocation failed (ex) 0x" << std::hex << GetLastError() << std::endl;
        return false;
    }

    // Setup mapping data
    MANUAL_MAPPING_DATA data{ 0 };
    data.pLoadLibraryA = LoadLibraryA;
    data.pGetProcAddress = GetProcAddress;
    data.pbase = pTargetBase;

    // Write PE file header
    if (!WriteProcessMemory(hProc, pTargetBase, pSrcData, 0x1000, nullptr)) { // Only first 0x1000 bytes for the header
        std::cerr << "Can't write file header 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    // Write sections
    const IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData, nullptr)) {
                std::cerr << "Can't map sections: 0x" << std::hex << GetLastError() << std::endl;
                VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
                return false;
            }
        }
    }

    // Allocate memory for mapping data
    BYTE* MappingDataAlloc = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAPPING_DATA), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (!MappingDataAlloc) {
        std::cerr << "Target process mapping allocation failed (ex) 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, MappingDataAlloc, &data, sizeof(MANUAL_MAPPING_DATA), nullptr)) {
        std::cerr << "Can't write mapping 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    // Allocate memory for shellcode
    void* pShellcode = VirtualAllocEx(hProc, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pShellcode) {
        std::cerr << "Memory shellcode allocation failed (ex) 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        return false;
    }

    if (!WriteProcessMemory(hProc, pShellcode, Shellcode, 0x1000, nullptr)) {
        std::cerr << "Can't write shellcode 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    std::cout << "Data allocated" << std::endl;

    // Create remote thread to execute shellcode
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), MappingDataAlloc, 0, nullptr);
    if (!hThread) {
        std::cerr << "Thread creation failed 0x" << std::hex << GetLastError() << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }
    CloseHandle(hThread);

    std::cout << "Thread created at: " << std::hex << reinterpret_cast<uintptr_t>(pShellcode) << ", waiting for return..." << std::endl;

    // Check for DLL injection success
    HINSTANCE hCheck = NULL;
    while (!hCheck) {
        DWORD exitcode = 0;
        GetExitCodeProcess(hProc, &exitcode);
        if (exitcode != STILL_ACTIVE) {
            std::cerr << "Process crashed, exit code: " << exitcode << std::endl;
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }

        MANUAL_MAPPING_DATA data_checked{ 0 };
        ReadProcessMemory(hProc, MappingDataAlloc, &data_checked, sizeof(data_checked), nullptr);
        hCheck = data_checked.hMod;

        if (hCheck == (HINSTANCE)0x404040) {
            std::cerr << "Wrong mapping ptr" << std::endl;
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }
        else if (hCheck == (HINSTANCE)0x606060) {
            std::cerr << "Wrong directory base relocation" << std::endl;
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
            return false;
        }

        Sleep(10);
    }

    // Clear PE header
    BYTE emptyBuffer[0x1000] = { 0 };
    if (!WriteProcessMemory(hProc, pTargetBase, emptyBuffer, 0x1000, nullptr)) {
        std::cerr << "WARNING!: Can't clear HEADER" << std::endl;
    }

    // Clear specific sections
    BYTE* emptyBuffer2 = (BYTE*)malloc(1024 * 1024);
    if (emptyBuffer2 == nullptr) {
        std::cerr << "Unable to allocate memory" << std::endl;
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
        return false;
    }

    memset(emptyBuffer2, 0, 1024 * 1024);

    //const IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pOldNtHeader);
    for (UINT i = 0; i != pOldFileHeader->NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            if (strcmp((char*)pSectionHeader->Name, ".pdata") == 0 ||
                strcmp((char*)pSectionHeader->Name, ".rsrc") == 0 ||
                strcmp((char*)pSectionHeader->Name, ".reloc") == 0) {
                std::cout << "Processing " << pSectionHeader->Name << " removal" << std::endl;
                if (!WriteProcessMemory(hProc, pTargetBase + pSectionHeader->VirtualAddress, emptyBuffer2, pSectionHeader->SizeOfRawData, nullptr)) {
                    std::cerr << "Can't clear section " << pSectionHeader->Name << ": 0x" << std::hex << GetLastError() << std::endl;
                }
            }
        }
    }

    free(emptyBuffer2);
    VirtualFreeEx(hProc, pShellcode, 0, MEM_RELEASE);
    VirtualFreeEx(hProc, MappingDataAlloc, 0, MEM_RELEASE);

    Sleep(500);
    return true;
}

#define RELOC_FLAG32(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData)
{
	if (!pData)
		return;
	//Process base
	BYTE* pBase = reinterpret_cast<BYTE*>(pData);
	//Optional data
	auto* pOptionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + reinterpret_cast<IMAGE_DOS_HEADER*>(pData)->e_lfanew)->OptionalHeader;

	auto _LoadLibraryA = pData->pLoadLibraryA;
	auto _GetProcAddress = pData->pGetProcAddress;
	auto _DllMain = reinterpret_cast<f_DLL_ENTRY_POINT>(pBase + pOptionalHeader->AddressOfEntryPoint);

	BYTE* LocationDelta = pBase - pOptionalHeader->ImageBase;
	if (LocationDelta)
	{
		if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return;

		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG(*pRelativeInfo))
				{
					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + ((*pRelativeInfo) & 0xFFF));
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		while (pImportDescr->Name)
		{
			char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
			HINSTANCE hDll = _LoadLibraryA(szMod);

			ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
			ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

			if (!pThunkRef)
				pThunkRef = pFuncRef;

			for (; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
				}
				else
				{
					auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
					*pFuncRef = (ULONG_PTR)_GetProcAddress(hDll, pImport->Name);
				}
			}
			++pImportDescr;
		}
	}

	if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBase + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
		for (; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}
	//Execute dll main
	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	pData->hMod = reinterpret_cast<HINSTANCE>(pBase);
}