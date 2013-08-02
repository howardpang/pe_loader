#include <Windows.h>
#include <winternl.h>
#include <tchar.h>
#include "HLoadlibrary.h"
#include "../testdll/test.h"

typedef int (*TestAddFunc)(int, int);
typedef void (*TestMessageboxFunc)();

PWSTR mgTestDllName = L"test.dll";
#define InsertTailList(le,e)    do { PLIST_ENTRY b = (le)->Blink; (e)->Flink = (le); (e)->Blink = b; b->Flink = (e); (le)->Blink = (e); } while (0)

typedef struct _LDR_MODULE
{
	LIST_ENTRY              InLoadOrderModuleList;
	LIST_ENTRY              InMemoryOrderModuleList;
	LIST_ENTRY              InInitializationOrderModuleList;
	PVOID                   BaseAddress;
	PVOID                   EntryPoint;
	ULONG                   SizeOfImage;
	UNICODE_STRING          FullDllName;
	UNICODE_STRING          BaseDllName;
	ULONG                   Flags;
	SHORT                   LoadCount;
	SHORT                   TlsIndex;
	LIST_ENTRY              HashTableEntry;
	ULONG                   TimeDateStamp;
} LDR_MODULE, *PLDR_MODULE;

typedef struct _LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
	PVOID EntryPoint;
	PVOID Reserved3;
	UNICODE_STRING FullDllName;
	BYTE Reserved4[8];
	PVOID Reserved5[3];
	union {
		ULONG CheckSum;
		PVOID Reserved6;
	};
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

/*
typedef struct _LIST_ENTRY {
	struct _LIST_ENTRY *Flink;
	struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
*/

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE           Reserved1[16];
	PVOID          Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
	BYTE       Reserved1[8];
	PVOID      Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;



typedef struct _MYPEB {
	BYTE                          Reserved1[2];
	BYTE                          BeingDebugged;
	BYTE                          Reserved2[1];
	PVOID                         Reserved3[2];
	PPEB_LDR_DATA                 Ldr;
	PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
	BYTE                          Reserved4[104];
	PVOID                         Reserved5[52];
	PVOID PostProcessInitRoutine;
	BYTE                          Reserved6[128];
	PVOID                         Reserved7[1];
	ULONG                         SessionId;
} MYPEB, *PMYPEB;

typedef   NTSTATUS (__stdcall *NtQueryInformationProcessProc) ( IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInformationLength, OUT PULONG ReturnLength OPTIONAL );

void MyListModule(PLIST_ENTRY entry, UINT offset)
{
	PLIST_ENTRY mark = entry;
	PLDR_MODULE pModule;
	 do
	{
		pModule= (PLDR_MODULE)((BYTE*)entry - offset);
		wprintf(L"%s\n", pModule->FullDllName.Buffer);
		entry = entry->Blink;
	}while(mark != entry);
}

void ListProcessModule()
{
	HANDLE hProcess = ::GetCurrentProcess();
	PEB peb = {0};
	PROCESS_BASIC_INFORMATION pbi = {0};
	pbi.UniqueProcessId = ::GetCurrentProcessId();
	//pbi.PebBaseAddress = &peb;
	ULONG ret = 0;
	NTSTATUS result;

	HMODULE hNtdll = ::LoadLibrary(_T("Ntdll.dll"));
	NtQueryInformationProcessProc pNtQueryInformationProcessProc = NULL;
	if (hNtdll != NULL)
	{
		pNtQueryInformationProcessProc = (NtQueryInformationProcessProc)::GetProcAddress(hNtdll, "ZwQueryInformationProcess");
	}
	if(pNtQueryInformationProcessProc != NULL)
	{
		result = pNtQueryInformationProcessProc(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
	}
	PMYPEB myPEB = (PMYPEB)pbi.PebBaseAddress;
	
	//ReadProcessMemory(hProcess, myPEB->ProcessParameters->CommandLine.Buffer, path, myPEB->ProcessParameters->CommandLine.Length, &s);
	PLDR_DATA_TABLE_ENTRY pldr = (PLDR_DATA_TABLE_ENTRY)(myPEB->Ldr->InMemoryOrderModuleList.Blink);
	PLDR_MODULE pLm =(PLDR_MODULE)((BYTE*)pldr - sizeof(LIST_ENTRY)); 
	MyListModule(pLm->InLoadOrderModuleList.Blink, 0);
}

int _tmain(int argc, _TCHAR* argv[])
{
	CHLoadlibrary ml;
	ml.Loadlibrary(_T("test.dll"));
	TestAddFunc testAdd = (TestAddFunc)ml.GetProcess(_T("test_dll_add"));
	TestMessageboxFunc testMb = (TestMessageboxFunc)ml.GetProcess(_T("test_dll_messagebox"));
	HMODULE testModule = ml.GetMoudule();

	testMb();

	printf("test Add return :%d\n", testAdd(1, 2));

	/*  
	//for update peb info
	int value = 0xffffffd7;
	HMODULE hm = ::LoadLibrary(_T("testdll.dll"));
	
	HANDLE hProcess = ::GetCurrentProcess();
	PEB peb = {0};
	PROCESS_BASIC_INFORMATION pbi = {0};
	pbi.UniqueProcessId = ::GetCurrentProcessId();
	//pbi.PebBaseAddress = &peb;
	ULONG ret = 0;
	NTSTATUS result;

	HMODULE hNtdll = ::LoadLibrary(_T("Ntdll.dll"));
	NtQueryInformationProcessProc pNtQueryInformationProcessProc = NULL;
	if (hNtdll != NULL)
	{
		pNtQueryInformationProcessProc = (NtQueryInformationProcessProc)::GetProcAddress(hNtdll, "ZwQueryInformationProcess");
	}
	if(pNtQueryInformationProcessProc != NULL)
	{
		result = pNtQueryInformationProcessProc(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &ret);
	}
	PMYPEB myPEB = (PMYPEB)pbi.PebBaseAddress;
	
	WCHAR path[MAX_PATH];
	SIZE_T s = 0;
	//ReadProcessMemory(hProcess, myPEB->ProcessParameters->CommandLine.Buffer, path, myPEB->ProcessParameters->CommandLine.Length, &s);
	PLDR_DATA_TABLE_ENTRY pldr = (PLDR_DATA_TABLE_ENTRY)(myPEB->Ldr->InMemoryOrderModuleList.Blink);
	PLDR_MODULE pLm =(PLDR_MODULE)((BYTE*)pldr - sizeof(LIST_ENTRY)); 

	PLDR_MODULE pMLm = (PLDR_MODULE)::HeapAlloc( GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LDR_MODULE));
	memcpy(pMLm, pLm, sizeof(LDR_MODULE));

	int len = (wcslen(mgTestDllName) + 1) * sizeof(WCHAR);
	PWSTR pName =(PWSTR)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
	memcpy(pName, mgTestDllName, len);
	len = (wcslen(mgTestDllPath) + 1) * sizeof(WCHAR);
	PWSTR pPath = (PWSTR)::HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, len);
	memcpy(pPath, mgTestDllPath, len);

	pMLm->BaseAddress = (PVOID)testModule;
	pMLm->EntryPoint = NULL;
	pMLm->BaseDllName.Buffer = pName;
	pMLm->BaseDllName.Length = wcslen(pName) * sizeof(WCHAR);
	pMLm->BaseDllName.MaximumLength = pMLm->BaseDllName.Length + sizeof(WCHAR);
	pMLm->FullDllName.Buffer = pPath;
	pMLm->FullDllName.Length = wcslen(pPath) * sizeof(WCHAR);
	pMLm->FullDllName.MaximumLength = pMLm->FullDllName.Length + sizeof(WCHAR);

	printf("############InLoadOrderModuleList############\n");
	MyListModule(pLm->InLoadOrderModuleList.Flink, 0);
	printf("############InMemoryOrderModuleList############\n");
	MyListModule(pLm->InMemoryOrderModuleList.Flink, sizeof(LIST_ENTRY));
	printf("############InInitializationOrderModuleList############\n");
	MyListModule(pLm->InInitializationOrderModuleList.Flink, 2 * sizeof(LIST_ENTRY));

	InsertTailList(&pLm->InLoadOrderModuleList, &pMLm->InLoadOrderModuleList);
	InsertTailList(&pLm->InInitializationOrderModuleList, &pMLm->InInitializationOrderModuleList);
	InsertTailList(&pLm->InMemoryOrderModuleList, &pMLm->InMemoryOrderModuleList);
	::LoadLibrary(_T("testdll.dll"));
	HMODULE testModule2 = ::LoadLibrary(mgTestDllPath);
	ListProcessModule();

	*/
	system("pause");

	return 0;
}
