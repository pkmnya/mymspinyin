#include <iostream>
#include <windows.h>
#include <string>
#include <tlhelp32.h>
#include <filesystem>

DWORD GetProcessIdByName(const std::wstring& processName) {
	DWORD pid = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}

	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnap, &pe)) {
		do {
			if (processName.compare(pe.szExeFile) == 0) {
				pid = pe.th32ProcessID;
				break;
			}
		} while (Process32Next(hSnap, &pe));
	}

	CloseHandle(hSnap);
	return pid;
}

int wmain(int argc, wchar_t* argv[]) {
	std::wstring dllName = L"mymspinyin.dll";
	std::wstring targetProcess = L"ctfmon.exe";

	std::filesystem::path dllPath = std::filesystem::absolute(dllName);
	std::wstring dllPathStr = dllPath.wstring();

	if (!std::filesystem::exists(dllPath)) {
#ifdef _DEBUG
		std::wcout << L"Error: Cannot find DLL: " << dllPathStr << std::endl;
		system("pause");
#endif
		return 1;
	}

	DWORD pid = GetProcessIdByName(targetProcess);
	if (pid == 0) {
#ifdef _DEBUG
		std::wcout << L"Error: Target process not found: " << targetProcess << std::endl;
		system("pause");
#endif
		return 1;
	}

#ifdef _DEBUG
	std::wcout << L"Target process: " << targetProcess << L" (PID: " << pid << L")" << std::endl;
	std::wcout << L"Injecting DLL: " << dllPathStr << "\r\n" << std::endl;
#endif

	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) {
#ifdef _DEBUG
		std::wcout << L"Error: OpenProcess failed. GLE = " << GetLastError() << std::endl;
		system("pause");
#endif
		return 1;
	}

	size_t dllPathSize = (dllPathStr.length() + 1) * sizeof(wchar_t);
	LPVOID pRemotePath = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemotePath == NULL) {
#ifdef _DEBUG
		std::wcout << L"Error: VirtualAllocEx failed. GLE = " << GetLastError() << std::endl;
#endif
		CloseHandle(hProcess);
#ifdef _DEBUG
		system("pause");
#endif
		return 1;
	}

	if (!WriteProcessMemory(hProcess, pRemotePath, dllPathStr.c_str(), dllPathSize, NULL)) {
#ifdef _DEBUG
		std::wcout << L"Error: WriteProcessMemory failed. GLE = " << GetLastError() << std::endl;
#endif
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
#ifdef _DEBUG
		system("pause");
#endif
		return 1;
	}

	LPVOID pLoadLibraryW = (LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
#ifdef _DEBUG
		std::wcout << L"Error: GetProcAddress for LoadLibraryW failed. GLE = " << GetLastError() << std::endl;
#endif
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
#ifdef _DEBUG
		system("pause");
#endif
		return 1;
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemotePath, 0, NULL);
	if (hThread == NULL) {
#ifdef _DEBUG
		std::wcout << L"Error: CreateRemoteThread failed. GLE = " << GetLastError() << std::endl;
#endif
		VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
#ifdef _DEBUG
		system("pause");
#endif
		return 1;
	}

#ifdef _DEBUG
	std::wcout << L"Injection thread created. Waiting for thread to finish..." << std::endl;
#endif
	WaitForSingleObject(hThread, INFINITE);

	DWORD exitCode = 0;
	GetExitCodeThread(hThread, &exitCode);

#ifdef _DEBUG
	if (exitCode == 0) {
		std::wcout << L"Error: Remote thread exited with code 0 (LoadLibrary failed)." << std::endl;
	}
	else {
		std::wcout << L"Injection successful! Remote module handle: 0x" << std::hex << exitCode << std::endl;
	}
#endif

	VirtualFreeEx(hProcess, pRemotePath, 0, MEM_RELEASE);
	CloseHandle(hThread);
	CloseHandle(hProcess);

#ifdef _DEBUG
	system("pause");
#endif
	return 0;
}