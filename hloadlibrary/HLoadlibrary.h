#ifndef __H_LOAD_LIBRARY_H__
#define __H_LOAD_LIBRARY_H__

#include <Windows.h>
#include <vector>

class CHLoadlibrary
{
public:
	CHLoadlibrary();
	~CHLoadlibrary();
	UINT Loadlibrary(LPCWSTR path);
	void FreeLibrary();
	void* GetProcess(LPCWSTR name);
	HMODULE GetMoudule();
private:
	static DWORD RVA2Offset(LPVOID pFileMem, DWORD rva);
	UINT Relocate();
	UINT LoadDependentDll();
	UINT CopyData2Mem(LPVOID pFileMem, LPVOID pExeMem);
	HANDLE mFile;
	HANDLE mFileMap;
	LPVOID mpFileMem;
	LPVOID mpExeMem;
	std::vector<HMODULE> mDependentModule;
};

#endif