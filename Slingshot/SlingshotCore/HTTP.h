#pragma once

#include "Core.h"

#include <algorithm>
#include <WinInet.h>
#pragma comment(lib, "Wininet.lib")

DWORD PrepareHTTP(State & state);
BOOL PerformPOST(State & state, std::string &outboundData);
std::string PerformHTTPCallback(State & state, std::string &outboundData);

void RemoveSpecialCharacters(std::string &input);
void ResetSpecialCharacters(std::string &input);