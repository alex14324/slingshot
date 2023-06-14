#pragma once
#include "Core.h"

#define CallbackDomain "http://localhost"
#define CallbackPort 1337

#define HTTP_FailSleep 10 * 1000
#define HTTP_MaxFails 10
#define HTTP_PSK "Dhga(81K1!392-!(43<KakjaiPA8$#ja"
#define HTTP_Timeout 45 * 1000
#define HTTP_PostPage "/submit.php"
#define HTTP_PostVar "id"
#define HTTP_GetPage "/index.php"
#define HTTP_GetVar "id"
#define HTTP_UserAgent "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko"

#define SMB_PSK "MKO)9ijnBHU*7ygvCFT^"
#define SMB_PipeName "DefSvcCore"
#define SMB_BufferSize 2048
#define SMB_MaxWrite 10240
#define SMB_ForwardTimeout 40
#define SMB_ReadTimeout 10
#define SMB_PeekTime 500
#define SMB_SpecialByte 0xFF

#define Shell_Timeout 15 * 1000