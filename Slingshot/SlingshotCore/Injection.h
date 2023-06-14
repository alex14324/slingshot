#pragma once

#include <windows.h>
#include <iostream>

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

typedef VOID(WINAPI * InjectionPoint)();
typedef UINT_PTR(WINAPI * sRDIPoint)();

FARPROC WINAPI GetProcAddressR(HANDLE hModule, LPCSTR lpProcName);
DWORD WINAPI GetImageSizeR(HANDLE hModule);
DWORD InjectShellcode(LPVOID uBuffer, DWORD bufferLength, HMODULE * uHandle);
