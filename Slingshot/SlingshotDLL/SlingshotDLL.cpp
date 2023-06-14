#pragma once

#include <SDKDDKVer.h>
#include <Windows.h>

#include "../SlingshotCore/Core.h"

#if defined(_DEBUG)
	#pragma comment (lib, "SlingshotCored.lib")
#else
	#pragma comment (lib, "SlingshotCore.lib")
#endif

// Holds the global variables for our thread
HANDLE hSSThread;
DWORD threadID;

// Function executed when the thread starts
DWORD WINAPI StartSS(LPVOID lpParam) {
	return StartSlingshot();
}


// Executed when the DLL is loaded (traditionally or through reflective injection)
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:

		DisableThreadLibraryCalls(hModule);
		hSSThread = CreateThread(NULL, 0, StartSS, NULL, 0, &threadID);

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

// This is so the the DLL can be started with rundll and still function properly
// It will wait for the thread to finish (SS Exiting)
extern "C" __declspec(dllexport) BOOL Load(LPVOID lpUserdata, DWORD nUserdataLen) 
{
	if (hSSThread) {
		WaitForSingleObject(hSSThread, INFINITE);
	}
	return TRUE;
};
