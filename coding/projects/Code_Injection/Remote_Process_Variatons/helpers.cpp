// author: reenz0h(twitter : @SEKTOR7net)

#include "PEstructs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "helpers.h"


HMODULE WINAPI hlpGetModuleHandle(LPCWSTR sModuleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB * ProcEnvBlk = (PEB *) __readfsdword(0x30);
#else
	PEB * ProcEnvBlk = (PEB *)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (sModuleName == NULL) 
		return (HMODULE) (ProcEnvBlk->ImageBaseAddress);

	PEB_LDR_DATA * Ldr = ProcEnvBlk->Ldr;
	LIST_ENTRY * ModuleList = NULL;
	
	ModuleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY *  pStartListEntry = ModuleList->Flink;

	for (LIST_ENTRY *  pListEntry  = pStartListEntry;  		// start from beginning of InMemoryOrderModuleList
					   pListEntry != ModuleList;	    	// walk all list entries
					   pListEntry  = pListEntry->Flink)	{
		
		// get current Data Table Entry
		LDR_DATA_TABLE_ENTRY * pEntry = (LDR_DATA_TABLE_ENTRY *) ((BYTE *) pListEntry - sizeof(LIST_ENTRY));

		// check if module is found and return its base address
		if (strcmp((const char *) pEntry->BaseDllName.Buffer, (const char *) sModuleName) == 0)
			return (HMODULE) pEntry->DllBase;
	}

	// otherwise:
	return NULL;

}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char * sProcName) {

	char * pBaseAddr = (char *) hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) pBaseAddr;
	IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY * pExportDataDir = (IMAGE_DATA_DIRECTORY *) (&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY * pExportDirAddr = (IMAGE_EXPORT_DIRECTORY *) (pBaseAddr + pExportDataDir->VirtualAddress);

	// resolve addresses to Export Address Table, table of function names and "table of ordinals"
	DWORD * pEAT = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD * pFuncNameTbl = (DWORD *) (pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD * pHintsTbl = (WORD *) (pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	// function address we're looking for
	void *pProcAddr = NULL;

	// resolve function by ordinal
	if (((DWORD_PTR)sProcName >> 16) == 0) {
		WORD ordinal = (WORD) sProcName & 0xFFFF;	// convert to WORD
		DWORD Base = pExportDirAddr->Base;			// first ordinal number

		// check if ordinal is not out of scope
		if (ordinal < Base || ordinal >= Base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		// get the function virtual address = RVA + BaseAddr
		pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[ordinal - Base]);
	}
	// resolve function by name
	else {
		// parse through table of function names
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char * sTmpFuncName = (char *) pBaseAddr + (DWORD_PTR) pFuncNameTbl[i];
	
			if (strcmp(sProcName, sTmpFuncName) == 0)	{
				// found, get the function virtual address = RVA + BaseAddr
				pProcAddr = (FARPROC) (pBaseAddr + (DWORD_PTR) pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	return (FARPROC) pProcAddr;
}