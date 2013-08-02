#include <wchar.h>
#include "HLoadlibrary.h"

void MutilBye2Unicode(const char* in, int inLen, WCHAR* out, int outLen)
{
	int len = wcslen(out);
	wmemset(out, 0, outLen);
	::MultiByteToWideChar(CP_ACP, 0, in, inLen, out, outLen);
}

CHLoadlibrary::CHLoadlibrary()
: mFile(INVALID_HANDLE_VALUE)
, mFileMap(NULL)
, mpFileMem(NULL)
, mpExeMem(NULL)
{

}

CHLoadlibrary::~CHLoadlibrary()
{
	FreeLibrary();
}

UINT CHLoadlibrary::Loadlibrary( LPCWSTR path )
{
	mFile = ::CreateFile(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
					NULL, OPEN_EXISTING, FILE_ATTRIBUTE_ARCHIVE, NULL);
	if (mFile == INVALID_HANDLE_VALUE)
	{
		return 1;
	}
	mFileMap = ::CreateFileMapping(mFile, NULL, PAGE_READONLY, 0, 0, NULL);
	if(mFileMap == NULL)
	{
		return 2;
	}
	mpFileMem = ::MapViewOfFile(mFileMap, FILE_MAP_READ, 0, 0, 0);
	if (mpFileMem == NULL)
	{
		return 3;
	}
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)mpFileMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)mpFileMem + pImaggeDosHeader->e_lfanew);
	mpExeMem = ::VirtualAlloc(0, pImageNtHeader->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (mpExeMem == NULL)
	{
		return 4;
	}
	CopyData2Mem(mpExeMem, mpFileMem);
	Relocate();
	LoadDependentDll();
	return 0;
}

void CHLoadlibrary::FreeLibrary()
{
	if (mpExeMem != NULL)
	{
		::VirtualFree(mpExeMem, 0, MEM_RELEASE);
		mpExeMem = NULL;
	}
	if (mpFileMem != NULL)
	{
		::UnmapViewOfFile(mpFileMem);
		mpFileMem = NULL;
	}
	if (mFileMap != NULL)
	{
		::CloseHandle(mFileMap);
		mFileMap = NULL;
	}
	if (mFile != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(mFile);
		mFile = INVALID_HANDLE_VALUE;
	}
	for(std::vector<HMODULE>::iterator it = mDependentModule.begin(); it != mDependentModule.end(); ++it)
	{
		::FreeLibrary(*it);
	}
	mDependentModule.clear();
}

void* CHLoadlibrary::GetProcess( LPCWSTR name )
{
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)mpExeMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)mpExeMem + pImaggeDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mpExeMem + (pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress));
	int numberOfNames = pExportDirectory->NumberOfNames;
	char* pName = NULL;
	WCHAR temp[MAX_PATH];
	DWORD* pAddressOfFuncs = (DWORD*)((BYTE*)mpExeMem + pExportDirectory->AddressOfFunctions);
	DWORD* pAddressOfFuncsName = (DWORD*)((BYTE*)mpExeMem + pExportDirectory->AddressOfNames);
	WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)mpExeMem + pExportDirectory->AddressOfNameOrdinals);
	for (int i = 0; i < numberOfNames; i++)
	{
		pName = (char*)((BYTE*)mpExeMem + (*pAddressOfFuncsName));
		MutilBye2Unicode(pName, strlen(pName), temp, MAX_PATH);
		if (::CompareStringOrdinal(temp, -1, name, -1, false) == CSTR_EQUAL)
		{
			return (void*)((BYTE*)mpExeMem + pAddressOfFuncs[pAddressOfNameOrdinals[i]]);
		}
		pAddressOfFuncsName++;
	}
	return NULL;
}

DWORD CHLoadlibrary::RVA2Offset( LPVOID pFileMem, DWORD rva )
{
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)pFileMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileMem + pImaggeDosHeader->e_lfanew);
	UINT32 numberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pImageNtHeader + sizeof(IMAGE_NT_HEADERS));
	DWORD rvaOfSectionStart;
	DWORD rvaOfSectionEnd;
	while(numberOfSections > 0)
	{
		rvaOfSectionStart = pImageSectionHeader->VirtualAddress;
		rvaOfSectionEnd = rvaOfSectionStart + pImageSectionHeader->Misc.VirtualSize;
		if (rva >= rvaOfSectionStart && rva < rvaOfSectionEnd)
		{
			return pImageSectionHeader->PointerToRawData + (rva - rvaOfSectionStart);
		}
		pImageSectionHeader++;
		numberOfSections--;
	}
	return 0;
}

UINT CHLoadlibrary::CopyData2Mem( LPVOID pExeMem , LPVOID pFileMem)
{
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)pFileMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)pFileMem + pImaggeDosHeader->e_lfanew);
	UINT32 numberOfSections = pImageNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pImageSectionHeader = (PIMAGE_SECTION_HEADER)((BYTE*)pImageNtHeader + sizeof(IMAGE_NT_HEADERS));
	DWORD sizeOfHeaders = sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS) + numberOfSections * sizeof(IMAGE_SECTION_HEADER);
	memcpy(pExeMem, pFileMem, sizeOfHeaders);
	while(numberOfSections > 0)
	{
		if (pImageSectionHeader->PointerToRawData > 0)
		{
			memcpy((void*)((DWORD)pExeMem + pImageSectionHeader->VirtualAddress), (void*)((DWORD)pFileMem + pImageSectionHeader->PointerToRawData), pImageSectionHeader->Misc.VirtualSize);
		}
		pImageSectionHeader++;
		numberOfSections--;
	}
	return 0;
}

UINT CHLoadlibrary::Relocate()
{
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)mpExeMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)mpExeMem + pImaggeDosHeader->e_lfanew);
	PIMAGE_BASE_RELOCATION pBaseRelocation = (PIMAGE_BASE_RELOCATION)((BYTE*)mpExeMem + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	int numberofRelocation; 
	WORD* pRvaOfRelocation;
	DWORD* pRelocation;
	while(pBaseRelocation->VirtualAddress)
	{
		numberofRelocation = (pBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
		pRvaOfRelocation = (WORD*)(pBaseRelocation + 1);
		int temp = 0;
		while(numberofRelocation > 0)
		{
			if (((*pRvaOfRelocation) & 0xf000) == 0x3000)
			{
				pRelocation =(DWORD*)((DWORD)mpExeMem + ((*pRvaOfRelocation & 0x0fff) + pBaseRelocation->VirtualAddress));
				(*pRelocation) = ((INT32)mpExeMem - (INT32)(pImageNtHeader->OptionalHeader.ImageBase)) + (*pRelocation);
			}
			pRvaOfRelocation++;
			numberofRelocation--;
			temp++;
		}
		pBaseRelocation = (PIMAGE_BASE_RELOCATION)pRvaOfRelocation;
	}
	return 0;
}

UINT CHLoadlibrary::LoadDependentDll()
{
	PIMAGE_DOS_HEADER pImaggeDosHeader = (PIMAGE_DOS_HEADER)mpExeMem;
	PIMAGE_NT_HEADERS pImageNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)mpExeMem + pImaggeDosHeader->e_lfanew);
	PIMAGE_IMPORT_DESCRIPTOR pImportDesriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)mpExeMem + pImageNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	PIMAGE_THUNK_DATA pChunkData;
	char* pName = NULL;
	WCHAR temp[MAX_PATH];
	HMODULE dependentModule = NULL;
	PIMAGE_IMPORT_BY_NAME pImportByName;
	while(pImportDesriptor->FirstThunk || pImportDesriptor->Name || pImportDesriptor->OriginalFirstThunk
		|| pImportDesriptor->TimeDateStamp)
	{
		pName = (char*)((BYTE*)mpExeMem + pImportDesriptor->Name);
		MutilBye2Unicode(pName, strlen(pName), temp, MAX_PATH);
		dependentModule = ::LoadLibrary(temp);
		if (dependentModule != NULL)
		{
			mDependentModule.push_back(dependentModule);
		}
		pChunkData = (PIMAGE_THUNK_DATA)((BYTE*)mpExeMem + pImportDesriptor->FirstThunk);
		while((pChunkData->u1.Ordinal) && dependentModule != NULL)
		{
			if (pChunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
			{
				int ordinal = LOWORD(pChunkData->u1.Ordinal);
				pChunkData->u1.Function = (DWORD)::GetProcAddress(dependentModule, MAKEINTRESOURCEA(ordinal));
			}
			else
			{
				pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)mpExeMem + pChunkData->u1.AddressOfData);
				pName = (char*)(pImportByName->Name);
				pChunkData->u1.Function = (DWORD)::GetProcAddress(dependentModule, pName);
			}
			pChunkData++;
		}
		pImportDesriptor++;
	}
	return 0;
}

HMODULE CHLoadlibrary::GetMoudule()
{
	return (HMODULE)mpExeMem;
}