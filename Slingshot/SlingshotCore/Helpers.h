#pragma once
#include <Windows.h>
#include <string>
#include <Psapi.h>
#include <TlHelp32.h>
#include <sstream>
#include <iomanip>

typedef BOOL(WINAPI * QUERYFULLPROCESSIMAGENAMEA)(HANDLE hProcess, DWORD dwFlags, LPSTR lpExeName, PDWORD lpdwSize);

// Get full image path for PID
static std::string GetProcessPath(DWORD pid)
{
	HANDLE hProcess = NULL;
	std::string returnString;
	char cpExePath[MAX_PATH] = { 0 };
	static QUERYFULLPROCESSIMAGENAMEA pQueryFullProcessImageNameA = NULL;

	do
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

		if (!hProcess) break;

		//FIRST, TRY GetModuleFileNameExA (WINDOWS 2000/XP/2003/VISTA/2008/7 BUT CANT GET X64 PROCESS PATHS FROM A WOW64 PROCESS)
		DWORD dwResult = GetModuleFileNameExA(hProcess, NULL, (char *)&cpExePath, MAX_PATH);

		if (dwResult > 0) { returnString = std::string(cpExePath); break; }

		//SECOND, TRY kernel32!QueryFullProcessImageNameA (WINDOWS VISTA/2008/7)
		if (dwResult == 0)
		{
			DWORD dwSize = 0;
			HANDLE hKernel = LoadLibraryA("kernel32");

			pQueryFullProcessImageNameA = (QUERYFULLPROCESSIMAGENAMEA)GetProcAddress((HMODULE)hKernel, "QueryFullProcessImageNameA");

			if (pQueryFullProcessImageNameA)
			{
				dwResult = pQueryFullProcessImageNameA(hProcess, 0, cpExePath, &dwSize);
				if (!dwResult) { returnString = std::string(cpExePath); break; }
				returnString = " ";
			}
		}
	} while (0);

	return returnString;
}

static wchar_t * utf8_to_wchar(const char *in)
{
	wchar_t *out;
	int len;

	if (in == NULL) {
		return NULL;
	}

	len = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, in, -1, NULL, 0);
	if (len <= 0) {
		return NULL;
	}

	out = (wchar_t *)calloc(len, sizeof(wchar_t));
	if (out == NULL) {
		return NULL;
	}

	if (MultiByteToWideChar(CP_UTF8, 0, in, -1, out, len) == 0) {
		free(out);
		out = NULL;
	}

	return out;
}

static char * wchar_to_utf8(const wchar_t *in)
{
	char *out;
	int len;

	if (in == NULL) {
		return NULL;
	}

	len = WideCharToMultiByte(CP_UTF8, 0, in, -1, NULL, 0, NULL, NULL);
	if (len <= 0) {
		return NULL;
	}

	out = (char *)calloc(len, sizeof(char));
	if (out == NULL) {
		return NULL;
	}

	if (WideCharToMultiByte(CP_UTF8, 0, in, -1, out, len, NULL, FALSE) == 0) {
		free(out);
		out = NULL;
	}

	return out;
}

// Convert process name to PID
static DWORD FindPid(std::string pName)
{
	DWORD tPid = 0;
	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			wchar_t * comp = utf8_to_wchar(pName.c_str());
			if (wcscmp((WCHAR *)&entry.szExeFile, comp) == 0)
			{
				tPid = entry.th32ProcessID;
				break;
			}
			free(comp);
		}
	}

	CloseHandle(snapshot);
	return tPid;
}

static void padString(std::string &str, const size_t num, const char paddingChar)
{
	if (num > str.size())
		str.append(num - str.size(), paddingChar);
}

static std::string padStringFromChar(LPSTR ch, const size_t num, const char paddingChar)
{
	std::string str = std::string(ch);
	if (num > str.size())
		str.append(num - str.size(), paddingChar);
	return str;
}

// Attempt to enable a specific SE Privilege
static DWORD EnablePrivilege(LPCTSTR name, HANDLE &hToken)
{
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	if (!LookupPrivilegeValue(NULL, name, &luid))
		return FALSE;

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) {
		int t = GetLastError();
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
		return FALSE;

	return TRUE;
}

// Get Process Architecture by PID
static std::string GetProcessArch(DWORD dwPid)
{
	HANDLE hProcess = NULL;
	SYSTEM_INFO SystemInfo = { 0 };
	BOOL bIsWow64 = FALSE;
	std::string strProcArch;

	do
	{
		GetNativeSystemInfo(&SystemInfo);
		switch (SystemInfo.wProcessorArchitecture)
		{
		case PROCESSOR_ARCHITECTURE_AMD64:
			strProcArch = "x64";
			break;
		case PROCESSOR_ARCHITECTURE_IA64:
			strProcArch = "IA64";
			break;
		case PROCESSOR_ARCHITECTURE_INTEL:
			strProcArch = "x86";
			break;
		default:
			strProcArch = "???";
			break;
		}

		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwPid);
		if (!hProcess)
		{
			hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, dwPid);
			if (!hProcess) { strProcArch = "  "; break; }
		}

		DWORD result = IsWow64Process(hProcess, &bIsWow64);

		if (bIsWow64 || result == 0)
		{
			strProcArch = "x86";
		}

	} while (0);

	if (hProcess) CloseHandle(hProcess);

	return strProcArch;
}

static DWORD SendTCPData(char *host, int port, char * data, DWORD dataLen)
{
	SOCKET TCPSock;
	sockaddr_in clientService;
	WSADATA wsaData;
	DWORD err = 0;

	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR)
		return FALSE;

	TCPSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (TCPSock == INVALID_SOCKET) {
		WSACleanup();
		return FALSE;
	}

	clientService.sin_family = AF_INET;
	clientService.sin_addr.s_addr = inet_addr(host);
	clientService.sin_port = htons(port);

	if (connect(TCPSock, (SOCKADDR *)&clientService, sizeof(clientService)) == SOCKET_ERROR) {
		WSACleanup();
		return FALSE;
	}

	if (dataLen > 0)
	{
		if (send(TCPSock, data, dataLen, 0) != dataLen) {
			WSACleanup();
			return FALSE;
		}

		if (send(TCPSock, "\r\n", 2, 0) != 2) {
			WSACleanup();
			return FALSE;
		}
	}

	closesocket(TCPSock);

	WSACleanup();

	return TRUE;
}

// Attempt to collect the domain\username associated with a process
static std::string GetProcessUsername(DWORD pid)
{
	DWORD dwResult = 0;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	TOKEN_USER * pUser = NULL;
	SID_NAME_USE peUse;
	DWORD dwUserLength = 0;
	DWORD dwDomainLength = 0;
	DWORD dwLength = 0;
	char cUser[512] = { 0 };
	char cDomain[512] = { 0 };
	std::string returnString = " ";

	do
	{
		hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
		if (!hProcess) break;

		if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) break;

		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwLength);

		pUser = (TOKEN_USER *)malloc(dwLength);
		if (!pUser) break;

		if (!GetTokenInformation(hToken, TokenUser, pUser, dwLength, &dwLength)) break;

		dwUserLength = sizeof(cUser);
		dwDomainLength = sizeof(cDomain);

		if (!LookupAccountSidA(NULL, pUser->User.Sid, cUser, &dwUserLength, cDomain, &dwDomainLength, &peUse)) break;

		// Make full name in DOMAIN\USERNAME format
		std::string username = std::string(cUser);
		std::string domain = std::string(cDomain);

		returnString = domain + "\\" + username;

	} while (0);

	if (pUser) free(pUser);
	if (hToken) CloseHandle(hToken);
	if (hProcess) CloseHandle(hProcess);

	return returnString;
}

// Format large numbers with commas
static std::string FormatLargeNumber(LONGLONG num)
{
	char b[32] = { 0 };
	_snprintf_s(b, 32, "%llu", num);
	std::string c;

	for (DWORD a = 0; a < strlen(b); a++)
	{
		c.insert(0, 1, b[strlen(b) - a - 1]);

		if ((a + 1) % 3 == 0 && a != (strlen(b) - 1))
		{
			c.insert(0, ",");
		}
	}
	return c;
}


static bool GetFileDetails(WIN32_FIND_DATAA data, std::string *output)
{
	SYSTEMTIME mytimestamp;
	LARGE_INTEGER filesize;
	std::stringstream ss;

	DWORD dircount = 0;
	DWORD filecount = 0;
	DWORD filetotal = 0;

	try {

		FileTimeToSystemTime(&data.ftLastWriteTime, &mytimestamp);

		ss << std::setfill('0') << std::setw(2) << mytimestamp.wMonth << "/" << std::setw(2) << mytimestamp.wDay << "/" << std::setw(2) << mytimestamp.wYear << "  ";
		ss << std::setfill('0') << std::setw(2) << mytimestamp.wHour << ":" << std::setw(2) << mytimestamp.wMinute << " " << std::setfill(' ');

		if (data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
		{
			ss << "  " << "<DIR>" << "\t\t" << std::setw(45) << std::left << data.cFileName << std::endl;
			dircount++;
		}
		else
		{
			filesize.LowPart = data.nFileSizeLow;
			filesize.HighPart = data.nFileSizeHigh;

			std::string c = FormatLargeNumber(filesize.QuadPart);

			if (c.length() < 5) ss << "  " << c.c_str() << "\t\t\t" << std::setw(45) << std::left << data.cFileName << std::endl;
			else if (c.length() < 12) ss << "  " << c.c_str() << "\t\t" << std::setw(45) << std::left << data.cFileName << std::endl;
			else ss << "  " << c.c_str() << "\t" << std::setw(45) << std::left << data.cFileName << std::endl;

			filetotal += (DWORD)filesize.QuadPart;
			filecount++;

		}

		output->append(ss.str());
		return TRUE;
	}
	catch (int e)
	{
		UNREFERENCED_PARAMETER(e);
		return FALSE;
	}
}

const char kBase64Alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";


static inline void a3_to_a4(unsigned char * a4, unsigned char * a3) {
	a4[0] = (a3[0] & 0xfc) >> 2;
	a4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
	a4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
	a4[3] = (a3[2] & 0x3f);
}

static inline void a4_to_a3(unsigned char * a3, unsigned char * a4) {
	a3[0] = (a4[0] << 2) + ((a4[1] & 0x30) >> 4);
	a3[1] = ((a4[1] & 0xf) << 4) + ((a4[2] & 0x3c) >> 2);
	a3[2] = ((a4[2] & 0x3) << 6) + a4[3];
}

static inline unsigned char b64_lookup(unsigned char c) {
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 71;
	if (c >= '0' && c <= '9') return c + 4;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return 255;
}

static int DecodedLength(const char *in, size_t in_length) {
	int numEq = 0;

	const char *in_end = in + in_length;
	while (*--in_end == '=') ++numEq;

	return ((6 * (int)in_length) / 8) - numEq;
}

static int DecodedLength(const std::string &in) {
	int numEq = 0;
	int n = (int)in.size();

	for (std::string::const_reverse_iterator it = in.rbegin(); *it == '='; ++it) {
		++numEq;
	}

	return ((6 * n) / 8) - numEq;
}

static int EncodedLength(int length) {
	return (length + 2 - ((length + 2) % 3)) / 3 * 4;
}

static int EncodedLength(const std::string &in) {
	return EncodedLength((int)in.length());
}

static void StripPadding(std::string *in) {
	while (!in->empty() && *(in->rbegin()) == '=') in->resize(in->size() - 1);
}

static bool Base64Encode(const std::string &in, std::string *out) {
	int i = 0, j = 0;
	size_t enc_len = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	out->resize(EncodedLength(in));

	int input_len = (int)in.size();
	std::string::const_iterator input = in.begin();

	while (input_len--) {
		a3[i++] = *(input++);
		if (i == 3) {
			a3_to_a4(a4, a3);

			for (i = 0; i < 4; i++) {
				(*out)[enc_len++] = kBase64Alphabet[a4[i]];
			}

			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 3; j++) {
			a3[j] = '\0';
		}

		a3_to_a4(a4, a3);

		for (j = 0; j < i + 1; j++) {
			(*out)[enc_len++] = kBase64Alphabet[a4[j]];
		}

		while ((i++ < 3)) {
			(*out)[enc_len++] = '=';
		}
	}

	return (enc_len == out->size());
}


static bool Base64Decode(const std::string &in, std::string *out) {
	int i = 0, j = 0;
	size_t dec_len = 0;
	unsigned char a3[3];
	unsigned char a4[4];

	int input_len = (int)in.size();
	std::string::const_iterator input = in.begin();

	out->resize(DecodedLength(in));

	while (input_len--) {
		if (*input == '=') {
			break;
		}

		a4[i++] = *(input++);
		if (i == 4) {
			for (i = 0; i <4; i++) {
				a4[i] = b64_lookup(a4[i]);
			}

			a4_to_a3(a3, a4);

			for (i = 0; i < 3; i++) {
				(*out)[dec_len++] = a3[i];
			}

			i = 0;
		}
	}

	if (i) {
		for (j = i; j < 4; j++) {
			a4[j] = '\0';
		}

		for (j = 0; j < 4; j++) {
			a4[j] = b64_lookup(a4[j]);
		}

		a4_to_a3(a3, a4);

		for (j = 0; j < i - 1; j++) {
			(*out)[dec_len++] = a3[j];
		}
	}

	return (dec_len == out->size());
}

static void swapints(int *array, int ndx1, int ndx2)
{
	int temp = array[ndx1];
	array[ndx1] = array[ndx2];
	array[ndx2] = temp;
}

static std::string RC4Crypt(std::string &inData, LPCSTR pszKey)
{
	LPSTR cipher;
	LPCSTR rawData = inData.data();
	int a, b, i = 0, j = 0, k;
	int sbox[256];
	int key[256];
	int keyLength = (int)strlen(pszKey);

	LPSTR newData = (LPSTR)malloc(inData.size());

	for (a = 0; a < 256; a++)
	{
		key[a] = pszKey[a % keyLength];
		sbox[a] = a;
	}

	for (a = 0, b = 0; a < 256; a++)
	{
		b = (b + sbox[a] + key[a]) % 256;
		swapints(sbox, a, b);
	}

	cipher = new char[inData.size() + 1];

	for (a = 0; a < (int)inData.size(); a++)
	{
		i = (i + 1) % 256;
		j = (j + sbox[i]) % 256;
		swapints(sbox, i, j);
		k = sbox[(sbox[i] + sbox[j]) % 256];

		char tmp = rawData[a] ^ k;
		newData[a] = tmp;
	}

	std::string outString = std::string(newData, inData.size());
	free(newData);

	return outString;
}