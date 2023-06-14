#include <stdio.h>
#include <tchar.h>

#include "../SlingshotCore/Core.h"

#if defined(_DEBUG)
	#pragma comment (lib, "SlingshotCored.lib")
#else
	#pragma comment (lib, "SlingshotCore.lib")
#endif

int main(int argc, char * argv[])
{
	return StartSlingshot();
}

