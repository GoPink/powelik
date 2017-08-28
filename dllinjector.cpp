#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <stdio.h>

//Used to store injection parameter
typedef struct _injection {
	TCHAR szTargetProcess[MAX_PATH];
	TCHAR szDLL[MAX_PATH];
} INJECTION_PARA;

//Retrieves information about the specified process
typedef NTSTATUS(NTAPI *_NtQueryInformationProcess)(
	HANDLE ProcessHandle,
	DWORD ProcessInformationClass,
	PVOID ProcessInformation,
	DWORD ProcessInformationLength,
	PDWORD ReturnLength
	);

//Used to get Command Line
typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//Used to get PEB Address
typedef struct _PROCESS_BASIC_INFORMATION {
	LONG ExitStatus;
	PVOID PebBaseAddress;
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR ParentProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

UINT WINAPI ThreadProc(LPVOID pPara);
BOOL InjectDLL(DWORD dwPID, LPCTSTR szDLLPath);
PVOID GetPebAddress(HANDLE ProcessHandle);
int isMalCode(DWORD dwPID);
void changeRegValue();

int _tmain(int argc, TCHAR *argv[]) {
	TCHAR PATH[MAX_PATH] = { 0 };
	INJECTION_PARA *pPara = (INJECTION_PARA*)malloc(sizeof(INJECTION_PARA));
	HANDLE hThread = NULL; 
	LPDWORD ThreadID = NULL;

	/**************************************************************	
		Change relative path to absolute path
		Be carefull, dll_injector and dll file must be in same dir
	***************************************************************/
	GetCurrentDirectory(MAX_PATH, PATH);
	_tcscat(PATH, L"\\");
	_tcscat(PATH, argv[2]);
	_tcscpy(pPara->szTargetProcess, argv[1]);
	_tcscpy(pPara->szDLL, PATH);

	if (argc != 3) {
		_tprintf(L"USAGE : %s pid dll_path\n", argv[0]);
		return 1;
	}

	//make thread to inject dll into process using pPara
	if (hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)ThreadProc, pPara, NULL, ThreadID)) {
		//waiting thread terminate
		WaitForSingleObject(hThread, INFINITE);
		CloseHandle(hThread);
		_tprintf(L"Inject %s file into %s process\n", argv[2],argv[1]);
	}

	else
		_tprintf(L"Inject %s file into %s process\n failed", argv[2], argv[1]);

	return 0;
}

//Search specifed process including malcode
UINT WINAPI ThreadProc(LPVOID pPara) {
	INJECTION_PARA *pInject = (INJECTION_PARA*)pPara;
	bool findProcess = FALSE;

	while (!findProcess) {
		HANDLE hProcessSnap = NULL;
		PROCESSENTRY32 pe32 = { 0 };
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		if (hProcessSnap == INVALID_HANDLE_VALUE) return 0;

		pe32.dwSize = sizeof(PROCESSENTRY32);

		if (Process32First(hProcessSnap, &pe32)) {
			do {
				//compare process name from list to target process 
				if (lstrcmpi(pe32.szExeFile, pInject->szTargetProcess) == 0) {
					HANDLE hProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pe32.th32ProcessID);

					if (hProcess) { 
						if (isMalCode(pe32.th32ProcessID) == 1) {
							SuspendThread(hProcess);
							InjectDLL(pe32.th32ProcessID, pInject->szDLL);
							changeRegValue();
							findProcess = TRUE;
						}
					}
					CloseHandle(hProcess);
				}
			} while (Process32Next(hProcessSnap, &pe32));
		}
		CloseHandle(hProcessSnap);
		Sleep(500);
	}
	return 0;
}

/**************************************************************
	reter to reversecore.com
	Be carefull, process must load kernel32.dll 
	if not, couldn't inject dll
**************************************************************/
BOOL InjectDLL(DWORD dwPID, LPCTSTR szDLLPath) {
	HANDLE hProcess = NULL, hThread = NULL;
	HMODULE hMod = NULL;
	LPVOID pRemoteBuf = NULL;
	DWORD dwBufSize = (DWORD)(_tcslen(szDLLPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE pThreadProc = NULL;

	if (!(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID))) {
		_tprintf(L"Open Process(%d) failed !! [%d]\n", dwPID, GetLastError());
		return FALSE;
	}

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDLLPath, dwBufSize, NULL);

	hMod = GetModuleHandle(L"kernel32.dll");
	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");

	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, pRemoteBuf, 0, NULL);

	WaitForSingleObject(hThread, INFINITE);
	CloseHandle(hThread);
	CloseHandle(hProcess);
	return TRUE;
}

PVOID GetPebAddress(HANDLE ProcessHandle)
{
	_NtQueryInformationProcess NtQueryInformationProcess =
		(_NtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
	PROCESS_BASIC_INFORMATION pbi;

	NtQueryInformationProcess(ProcessHandle, 0, &pbi, sizeof(pbi), NULL);

	return pbi.PebBaseAddress;
}

/**************************************************************
	Get command line using PEB structure
	Search specifed signiture from command line
**************************************************************/
int isMalCode(DWORD dwPID)
{
	HANDLE processHandle;
	PVOID pebAddress;
	PVOID rtlUserProcParamsAddress;
	UNICODE_STRING commandLine;
	WCHAR *commandLineContents;
	WCHAR tmp[MAX_PATH] = { 0 };
	int flag = FALSE;

	if ((processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE,dwPID)) == 0) {
		printf("Could not open process!\n");
		flag = GetLastError();
		return flag;
	}

	pebAddress = GetPebAddress(processHandle);

	/* get the address of ProcessParameters */
	if (!ReadProcessMemory(processHandle, (PCHAR)pebAddress + 0x10,	&rtlUserProcParamsAddress, sizeof(PVOID), NULL))	{
		printf("Could not read the address of ProcessParameters!\n");
		flag = GetLastError();
		return flag;
	}

	/* read the CommandLine UNICODE_STRING structure */
	if (!ReadProcessMemory(processHandle, (PCHAR)rtlUserProcParamsAddress + 0x40,&commandLine, sizeof(commandLine), NULL))	{
		printf("Could not read CommandLine!\n");
		flag = GetLastError();
		return flag;
	}

	/* allocate memory to hold the command line */
	commandLineContents = (WCHAR *)malloc(commandLine.Length);

	/* read the command line */
	if (!ReadProcessMemory(processHandle, commandLine.Buffer,commandLineContents, commandLine.Length, NULL))	{
		printf("Could not read the command line string!\n");
		flag = GetLastError();
		return flag;
	}

	/* the length specifier is in characters, but commandLine.Length is in bytes */
	/* a WCHAR is 2 bytes */
	_tcsnccpy(tmp, commandLineContents, commandLine.Length / 2);

	//find signiture
	if ((_tcsstr(tmp, L"javascript")) != NULL) {
		_tprintf(L"find!!!\n");
		CloseHandle(processHandle);
		free(commandLineContents);
		flag = TRUE;
		return flag;
	}

	CloseHandle(processHandle);
	free(commandLineContents);
	return flag;
}

/**************************************************************
	Requirement : Admin right
	Change Run registry value
**************************************************************/
void changeRegValue() {
	HKEY h_key = NULL;
	TCHAR value[MAX_PATH] = { L"test" };
	int ret = RegOpenKey(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run", &h_key);

	if (ret == ERROR_SUCCESS) _tprintf(L"Open Success\n");

	ret = RegSetValue(h_key, NULL, REG_SZ, value, 0);

	if (ret == ERROR_SUCCESS) _tprintf(L"set Success\n");
	else _tprintf(L"error # : %d\n", ret);
}