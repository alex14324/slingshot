#include "Injection.h"

DWORD InjectShellcode(LPVOID uBuffer, DWORD bufferLength, HMODULE * uHandle) {

	DWORD dwOldProtect = 0;

	if (!VirtualProtect(uBuffer, bufferLength, PAGE_EXECUTE_READWRITE, &dwOldProtect))
		return 0;

	sRDIPoint injection = (sRDIPoint)(uBuffer);
	if (uHandle)
		*uHandle = (HMODULE)injection(); //Execute sRDI and get back the new base address
	else
		(HMODULE)injection();

	return true;
}


///
// RDI helper functions
///

#pragma warning( push )
#pragma warning( disable : 4311)
#pragma warning( disable : 4302)

DWORD WINAPI GetImageSizeR(HANDLE hModule)
{
	UINT_PTR uiLibraryAddress = 0;

	if (hModule == NULL)
		return NULL;

	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		return ((PIMAGE_NT_HEADERS)pNtHeaders)->OptionalHeader.SizeOfImage;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return 0;
	}

	return 0;
}

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName)
{
	UINT_PTR uiLibraryAddress = 0;
	FARPROC fpResult = NULL;

	if (hModule == NULL)
		return NULL;

	uiLibraryAddress = (UINT_PTR)hModule;

	__try
	{
		UINT_PTR uiAddressArray = 0;
		UINT_PTR uiNameArray = 0;
		UINT_PTR uiNameOrdinals = 0;
		PIMAGE_NT_HEADERS pNtHeaders = NULL;
		PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;

		pNtHeaders = (PIMAGE_NT_HEADERS)(uiLibraryAddress + ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew);
		pDataDirectory = (PIMAGE_DATA_DIRECTORY)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(uiLibraryAddress + pDataDirectory->VirtualAddress);
		uiAddressArray = (uiLibraryAddress + pExportDirectory->AddressOfFunctions);
		uiNameArray = (uiLibraryAddress + pExportDirectory->AddressOfNames);
		uiNameOrdinals = (uiLibraryAddress + pExportDirectory->AddressOfNameOrdinals);

		if (((DWORD)lpProcName & 0xFFFF0000) == 0x00000000)
		{
			uiAddressArray += ((IMAGE_ORDINAL((DWORD)lpProcName) - pExportDirectory->Base) * sizeof(DWORD));
			fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
		}
		else
		{
			DWORD dwCounter = pExportDirectory->NumberOfNames;
			while (dwCounter--)
			{
				char * cpExportedFunctionName = (char *)(uiLibraryAddress + DEREF_32(uiNameArray));

				if (strcmp(cpExportedFunctionName, lpProcName) == 0)
				{
					uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));
					fpResult = (FARPROC)(uiLibraryAddress + DEREF_32(uiAddressArray));
					break;
				}

				uiNameArray += sizeof(DWORD);
				uiNameOrdinals += sizeof(WORD);
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		fpResult = NULL;
	}

	return fpResult;
}

#pragma warning( pop )