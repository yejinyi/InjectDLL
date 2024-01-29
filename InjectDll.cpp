#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

#pragma warning(disable:4996)


BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath);
DWORD ProcesstoPid(char* Processname);
BOOL EnableDebugPrivilege();


// 查找指定进程的PID(Process ID)
DWORD ProcesstoPid(char* Processname)
{
	HANDLE hProcessSnap = NULL;
	PROCESSENTRY32 pe32 = { 0 };
	DWORD ProcessId = 0;

	// 打开进程快照
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,           // 在快照中包含系统中所有进程
		0);												                  // 0 表示快照当前进程

	if (hProcessSnap == (HANDLE)-1)
	{
		printf("CreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}

	pe32.dwSize = sizeof(PROCESSENTRY32);


	// 开始枚举进程
	if (Process32First(hProcessSnap,              // 进程快照
		&pe32))                                   // 指向PROCESSENTRY32结构的指针 。它包含可执行文件名、进程标识符、父进程的进程标识符等进程信息。
	{
		do
		{
			if (!stricmp(Processname, pe32.szExeFile))       // 判断是否和提供的进程名相等，是，返回进程的 ID
			{
				printf("pe32.szExeFile = %s\n", pe32.szExeFile);          // 未运行
				ProcessId = pe32.th32ProcessID;
				break;
			}

		} while (Process32Next(hProcessSnap, &pe32));             // 继续枚举进程
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	return ProcessId;
}

// 本函数用于提升权限，提升到 SE_DEBUG_NAME
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;

	// 打开当前进程失败
	if (!OpenProcessToken(GetCurrentProcess(),           // 打开其访问令牌的进程句柄
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,             // 指定访问令牌的请求访问类型
		&hToken))                                        // 指向句柄的指针，该句柄标识函数返回时新打开的访问令牌
	{
		return FALSE;
	}

	// 查看当前权限
	LookupPrivilegeValue(NULL,          // 指定了空字符串，则该函数将尝试在本地系统上查找特权名称
		SE_DEBUG_NAME,                  // 字符串指定权限的名称
		&tkp.Privileges[0].Luid);       // 指向一个变量的指针，该变量接收 LUID      
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;     // 指示启用特权，通过设置 SE_PRIVILEGE_ENABLED 来启用特权，程序可以在需要时拥有执行特权操作的能力。
	// 调整权限
	AdjustTokenPrivileges(hToken,       // 访问令牌的句柄，其中包含要修改的权限
		FALSE,                          // 指定函数是否禁用令牌的所有特权，这里的FALSE代表根据 NewState 参数指向的信息修改权限
		&tkp,                           // 指向 TOKEN_PRIVILEGES 结构的指针，该结构指定特权数组及其属性
		0,                              // 指定 PreviousState 参数指向的缓冲区的大小（以字节为单位）
		(PTOKEN_PRIVILEGES)NULL,        // 指向函数用 TOKEN_PRIVILEGES 结构填充的缓冲区的指针，这个指针中包好函数修改的任何特权的先前状态
		0);
	return TRUE;
}

// 注入函数
BOOL WINAPI InjectDllToProcess(DWORD dwTargetPid, LPCTSTR DllPath)
{
	HANDLE hProc = NULL;

	// 打开现有的本地进程对象
	hProc = OpenProcess(PROCESS_ALL_ACCESS,      // 权限设置，这里对进程对象的所有可能的访问权限
		FALSE,									 // FALSE,代表进程不会继承此句柄
		dwTargetPid);                            // 要打开的本地进程的标识符
	if (hProc == NULL)
	{
		printf("[-] OpenProcess Failed.\n");
		return FALSE;
	}

	LPTSTR psLibFileRemote = NULL;

	// 使用VirtualAllocEx 函数在远程进程的内存地址空间分配 DLL 文件名缓冲
	psLibFileRemote = (LPTSTR)VirtualAllocEx(hProc,
		NULL,
		lstrlen(DllPath) + 1,
		MEM_COMMIT,
		PAGE_READWRITE);

	if (psLibFileRemote == NULL)
	{
		printf("[-] VirtualAllocEx Failed.\n");
		return FALSE;
	}

	// 使用WriteProcessMemory 函数将 DLL 的路径名复制到远程的内存空间
	if (WriteProcessMemory(hProc,         // 要修改进程的句柄。句柄必须具有对进程的 PROCESS_VM_WRITE 和 PROCESS_VM_OPERATION 访问权限
		psLibFileRemote,                  // 指向将数据写入到的指定进程中基址的指针
		(void*)DllPath,                   // 指向缓冲区的指针，该缓冲区包含要写入指定进程的地址空间中的数据
		lstrlen(DllPath) + 1,             // 要写入指定进程的字节数
		NULL) == 0)                       // 指向变量的指针，该变量接收传输到指定进程的字节数。
	{
		printf("[-] WriteProcessMemory Failed.\n");
		return FALSE;
	}

	// 计算LoadLibraryA的入口地址
	PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(
		GetModuleHandleA("Kernel32"),       // 包含函数或变量的 DLL 模块的句柄
		"LoadLibraryA");                    // 函数或变量名称，或函数的序号值

	if (pfnStartAddr == NULL)
	{
		printf("[-] GetProcAddress Failed.\n");
		return FALSE;
	}

	// pfnStartAddr 地址就是LoadLibraryA 的入口地址
	// 创建在另一个进程的虚拟地址空间中运行的线程
	HANDLE hThread = CreateRemoteThread(hProc,        // 要在其中创建线程的进程句柄
		NULL,                                         // NULL,代表线程将获取默认安全描述符
		0,                                            // 堆栈的初始化大小，0 代表新线程将使用可执行文件的默认大小
		pfnStartAddr,                                 // 指向 LPTHREAD_START_ROUTINE, 线程执行的应用程序定义函数的指针，表示远程进程中线程的起始地址
		psLibFileRemote,                              // 指向要传递给线程函数的变量指针
		0,                                            // 线程创建标志，0标识线程在创建后立即运行
		NULL);                                        // 指向接收线程标识符的变量的指针，NULL 代表不返回线程标识符
	if (hThread == NULL)
	{
		printf("[-] CreateRemoteThread Failed. ErrCode = %d\n", GetLastError());
		return FALSE;
	}

	printf("[*] Inject Successfull.\n");
	return TRUE;

}


int main()
{
#ifdef _WIN64
	char szProcName[MAX_PATH] = "HostProc64.exe";
	char szDllPath[MAX_PATH] = "D:\\study\\杂项代码\\InjectDll\\InjectDll\\MsgDll64.dll";
#else
	char szProcName[MAX_PATH] = "HostProc.exe";
	char szDllPath[MAX_PATH] = "D:\\study\\杂项代码\\InjectDll\\InjectDll\\MsgDll.dll";
#endif // _WIN64

	DWORD dwPid = ProcesstoPid(szProcName);
	printf("dwPid = %d", dwPid);

	EnableDebugPrivilege();
	InjectDllToProcess(dwPid, (LPCTSTR)szDllPath);

	system("pause");
	return 0;
}



