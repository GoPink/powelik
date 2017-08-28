#include <process.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <WinBase.h>
#include <string.h>
#include <winreg.h>
#include <tchar.h>

void killProcessByName(TCHAR filename[]) {
	HANDLE hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	PROCESSENTRY32 pEntry = { 0, };
	pEntry.dwSize = sizeof(pEntry);
	BOOL hRes = Process32First(hSnapShot, &pEntry);

	/* search process from list*/
	while (hRes)	{
		if (lstrcmp(pEntry.szExeFile, filename) == 0)		{
			HANDLE hpProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ParentProcessID);
			HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, (DWORD)pEntry.th32ProcessID);
 
			if (hpProcess != NULL && hProcess != NULL)			{
				TerminateProcess(hpProcess, 9);
				CloseHandle(hpProcess);

				TerminateProcess(hProcess, 9);				
				CloseHandle(hProcess);
			}
		}
		hRes = Process32Next(hSnapShot, &pEntry);
	}
	CloseHandle(hSnapShot);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) { 
	switch (ul_reason_for_call)	{
	case DLL_PROCESS_ATTACH:
		killProcessByName(L"rundll32.exe");
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}