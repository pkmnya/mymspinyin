// 我只是受够了狗石搜狗输入法的卡顿 广告 高占用 隐私打包 但是微软拼音真是一大坨 又没有什么其他好使的拼音输入法了

#include <windows.h>
#include <stdio.h>
#include <string>
#include <vector>
#include <Psapi.h>
#include "MinHook.h"
#include <thread>

#include <imm.h>
#pragma comment(lib, "Imm32.lib")

//避免链接debug库 确保release编译
//目前已知的BUG: 在chrome浏览器url处使用 alt+shift 切换到中文时 输入会阻塞 , 原因不明, 输入任意数字或切换为英语模式后恢复正常

// 是否开启调试控制台
//#define TESTCONSOLE 1


typedef HRESULT(WINAPI* FnInputMethodProxy_Activate)(void* This, DWORD dwReserved);
typedef HRESULT(WINAPI* FnOnConversionModeSet)(void* This, DWORD mode);

FnInputMethodProxy_Activate Original_Activate = NULL;
FnOnConversionModeSet Original_OnConversionModeSet = NULL;

char* G_ConversionModePtr = NULL; //该指针捕获 微软拼音 是中文还是英文
int* G_InputModePtr = NULL; // 该指针捕获 当前语言是 美国还是中国

DWORD_PTR pOnConversionModeSet = 0;
DWORD_PTR pActivate = 0;
DWORD_PTR pGetActiveInputProfile = 0;

HANDLE g_hMutex = NULL;
HWINEVENTHOOK g_hWinEventHook = NULL;

#if TESTCONSOLE
// 仅当 TESTCONSOLE 为真 (非零) 时编译以下代码块

void OpenDebugConsole() {
	if (GetConsoleWindow() != NULL) return;

	AllocConsole();
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	SetConsoleTitle(L"CTFMON Hook Debug Console");
	printf("--- Debug Console Initialized ---\n");
}

void PrintDebug(const char* format, ...) {
	if (GetConsoleWindow() == NULL) return;

	char buffer[1024];
	va_list args;
	va_start(args, format);
	vsnprintf(buffer, sizeof(buffer), format, args);
	va_end(args);

	printf("[HookDLL] %s\n", buffer);
}

#else

#define OpenDebugConsole() ((void)0)
#define PrintDebug(...) ((void)0)

#endif // TESTCONSOLE

std::vector<BYTE> HexToBytes(const char* hex) {
	std::vector<BYTE> bytes;
	size_t len = strlen(hex);
	for (size_t i = 0; i < len; i += 2) {
		if (i + 1 >= len) break;
		if (hex[i] == '?' && hex[i + 1] == '?') {
			bytes.push_back(0xCC);
		}
		else {
			char byteString[3] = { hex[i], hex[i + 1], 0 };
			bytes.push_back((BYTE)strtol(byteString, NULL, 16));
		}
	}
	return bytes;
}

void* AOBScan(const char* pattern, DWORD_PTR moduleBase, DWORD moduleSize) {
	std::vector<BYTE> patternBytes = HexToBytes(pattern);
	const BYTE* scanStart = (const BYTE*)moduleBase;
	const size_t patternSize = patternBytes.size();

	if (patternSize == 0) return NULL;

	PrintDebug("AOBScan: Starting search for pattern %s (Size: %zu) in range 0x%p - 0x%p",
		pattern, patternSize, (void*)moduleBase, (void*)(moduleBase + moduleSize));

	for (DWORD i = 0; i <= moduleSize - patternSize; ++i) {
		bool found = true;
		for (size_t j = 0; j < patternSize; ++j) {
			if (patternBytes[j] != 0xCC) {
				if (scanStart[i + j] != patternBytes[j]) {
					found = false;
					break;
				}
			}
		}
		if (found) {
			void* foundAddr = (void*)(scanStart + i);
			PrintDebug("AOBScan: Found fuzzy match at address 0x%p", foundAddr);
			return foundAddr;
		}
	}

	PrintDebug("AOBScan: Pattern not found.");
	return NULL;
}

static bool Hook_OnConversionModeSet_CanRemove = false;

// 可以考虑主动触发获取一下 没想好在哪
HRESULT WINAPI Hook_OnConversionModeSet(void* This, DWORD mode) {
	HRESULT result = Original_OnConversionModeSet(This, mode);
	if (G_ConversionModePtr) return result;

	PrintDebug("Hook_OnConversionModeSet: Execution entered. RCX (This) = 0x%p, Mode (EDX) = %u.", This, mode);
	PrintDebug("Hook_OnConversionModeSet: Original function returned HRESULT: 0x%X.", result);
	G_ConversionModePtr = (char*)((DWORD_PTR)This + 0xC8);
	PrintDebug("Hook_OnConversionModeSet: G_ConversionModePtr captured at 0x%p.", G_ConversionModePtr);

	Hook_OnConversionModeSet_CanRemove = true;

	return result;
}

DWORD WINAPI Hook_OnConversionModeSet_RemoveThread() {
	while (true) {
		if (Hook_OnConversionModeSet_CanRemove) {
			PrintDebug("HookThread Monitor: Detach flag set and pointer acquired. Starting SAFE hook removal.");

			MH_STATUS status_disable = MH_DisableHook((LPVOID)pOnConversionModeSet);
			if (status_disable != MH_OK && status_disable != MH_ERROR_DISABLED) {
				PrintDebug("HookThread Monitor: Error - Failed to disable hook. MH_STATUS = %d.", status_disable);
			}

			MH_STATUS status_remove = MH_RemoveHook((LPVOID)pOnConversionModeSet);
			if (status_remove != MH_OK) {
				PrintDebug("HookThread Monitor: WARNING - Failed to remove hook. Status: %d", status_remove);
			}

			PrintDebug("HookThread Monitor: OnConversionModeSet Hook removed successfully.");
			break;
		}
		Sleep(100);
	}
	PrintDebug("HookThread: Monitor loop finished. Thread exiting successfully.");
	return 0;
}

HRESULT WINAPI Hook_Activate(void* This, DWORD dwReserved) {
	HRESULT result = Original_Activate(This, dwReserved);

	if (dwReserved == 0) {
		PrintDebug("Hook_Activate: dwReserved is 0 (Deactivate call). Skipping logic.");
		return result;
	}

	//输入法语言判断
	const int chinese = 2052;
	const int english = 1033;
	if (G_InputModePtr)
	{
		PrintDebug("Object Count Variable Address (G_InputModePtr): 0x%p Value: %u", (void*)G_InputModePtr, *G_InputModePtr);
		if (*G_InputModePtr != chinese) return result;
	}

	//放在语言判定后面防止不触发 并不是基于性能优化 而是等待反应时间
	static INT64 lastruntime = 0;
	INT64 currenttime = GetTickCount64();
	if (currenttime < lastruntime + 100) return result;
	lastruntime = currenttime;

	//上面已经判断了只有输入法是中文才继续执行
	//这里判断拼音是中文还是英文

	PrintDebug("==================================================");
	PrintDebug("Hook_Activate: Execution entered. This = 0x%p, dwReserved = %u", This, dwReserved);

	if (G_ConversionModePtr) {
		char currentMode = *G_ConversionModePtr;
		PrintDebug("Hook_Activate: Read mode from 0x%p. Value = %d.", G_ConversionModePtr, (int)currentMode);

		if (currentMode != 1)
		{
			PrintDebug("Hook_Activate: Mode is English (0). Simulating SHIFT press...");
			PrintDebug("--------------------------------------------------");

			// 不知道为什么会显示同步balbalbalba
			/*
			HWND hwnd = GetForegroundWindow();
			if (hwnd) {
				HWND ime_hwnd = ImmGetDefaultIMEWnd(hwnd);

				if (ime_hwnd) {
					PrintDebug("Hook_Activate: Found HWND 0x%p, IME HWND 0x%p. Sending WM_IME_CONTROL.", hwnd, ime_hwnd);


					const int IMC_SETCONVERSIONMODE = 0x0002;
					SendMessageW(
						ime_hwnd,
						WM_IME_CONTROL,
						IMC_SETCONVERSIONMODE,
						1025 // 对应中文模式
					);

					PrintDebug("Hook_Activate: WM_IME_CONTROL (Chinese Mode) message sent.");

				}
				else {
					PrintDebug("Hook_Activate: Warning - ImmGetDefaultIMEWnd failed (No IME window).");
				}
			}
			else {
				PrintDebug("Hook_Activate: Warning - GetForegroundWindow failed (No foreground window).");
			}

			*/

			INPUT inputs[2] = { 0 };
			inputs[0].type = INPUT_KEYBOARD;
			inputs[0].ki.wVk = VK_SHIFT;
			inputs[0].ki.dwFlags = 0;
			inputs[1].type = INPUT_KEYBOARD;
			inputs[1].ki.wVk = VK_SHIFT;
			inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
			SendInput(2, inputs, sizeof(INPUT));



			PrintDebug("Hook_Activate: SHIFT press simulated.");
		}
		else {
			PrintDebug("Hook_Activate: Mode is already Chinese (1). No action needed.");
		}
	}
	else {
		PrintDebug("Hook_Activate: Warning - G_ConversionModePtr is NULL. Waiting for OnConversionModeSet trigger.");
	}

	PrintDebug("Hook_Activate: Original function returned HRESULT: 0x%X. Execution finished.", result);

	return result;
}


BOOL SetupHooks() {
	PrintDebug("SetupHooks: Starting hook setup.");

	HMODULE hMods[1024];
	DWORD cbNeeded;

	// AOB
	DWORD_PTR g_InputServiceBase = 0;
	DWORD g_InputServiceSize = 0;
	DWORD_PTR g_ChsPinyinBase = 0;
	DWORD g_ChsPinyinSize = 0;

	if (EnumProcessModules(GetCurrentProcess(), hMods, sizeof(hMods), &cbNeeded)) {
		PrintDebug("SetupHooks: Enumerating process modules...");
		for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
			WCHAR szModName[MAX_PATH];
			if (GetModuleFileNameExW(GetCurrentProcess(), hMods[i], szModName, sizeof(szModName) / sizeof(WCHAR))) {
				std::wstring ws(szModName);
				if (ws.find(L"InputService.dll") != std::wstring::npos) {
					MODULEINFO mi;
					if (GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi))) {
						g_InputServiceBase = (DWORD_PTR)mi.lpBaseOfDll;
						g_InputServiceSize = mi.SizeOfImage;
						PrintDebug("SetupHooks: Found InputService.dll at 0x%p, Size: 0x%X.", (void*)g_InputServiceBase, g_InputServiceSize);
					}
					break;
				}
				/*
				if (ws.find(L"ChsPinyinDS.dll") != std::wstring::npos) {
					MODULEINFO mi;
					if (GetModuleInformation(GetCurrentProcess(), hMods[i], &mi, sizeof(mi))) {
						g_ChsPinyinBase = (DWORD_PTR)mi.lpBaseOfDll;
						g_ChsPinyinSize = mi.SizeOfImage;
						PrintDebug("SetupHooks: Found ChsPinyinDS.dll at 0x%p, Size: 0x%X.", (void*)g_ChsPinyinBase, g_ChsPinyinSize);
					}
				}
				if (g_InputServiceBase && g_ChsPinyinBase) break;*/
			}
		}
	}

	PrintDebug("SetupHooks: Starting AOB Scans...");

	pOnConversionModeSet = (DWORD_PTR)AOBScan("ff81800000008bc2", g_InputServiceBase, g_InputServiceSize);
	pActivate = (DWORD_PTR)AOBScan("48895c2408574883ec208bda488bf985d2741e", g_InputServiceBase, g_InputServiceSize);
	//pDecrementObjectCount = (DWORD_PTR)AOBScan("83c8fff00fc105????????ffc8", g_ChsPinyinBase, g_ChsPinyinSize);
	pGetActiveInputProfile = (DWORD_PTR)AOBScan("0f2805????????33c00f11020f28", g_InputServiceBase, g_InputServiceSize);


	if (!pOnConversionModeSet || !pActivate || !pGetActiveInputProfile) {
		PrintDebug("SetupHooks: Error - One or more AOB scans failed.");
		PrintDebug("SetupHooks: pOnConversionModeSet = 0x%p", (void*)pOnConversionModeSet);
		PrintDebug("SetupHooks: pActivate = 0x%p", (void*)pActivate);
		PrintDebug("SetupHooks: pGetActiveInputProfile = 0x%p", (void*)pGetActiveInputProfile);
		return FALSE;
	}
	PrintDebug("SetupHooks: All AOB scans successful.");

	if (MH_Initialize() != MH_OK) {
		PrintDebug("SetupHooks: Error - MH_Initialize failed.");
		return FALSE;
	}
	PrintDebug("SetupHooks: MinHook initialized.");

	if (MH_CreateHook((LPVOID)pOnConversionModeSet, &Hook_OnConversionModeSet,
		reinterpret_cast<LPVOID*>(&Original_OnConversionModeSet)) != MH_OK) {
		PrintDebug("SetupHooks: Error - MH_CreateHook for OnConversionModeSet failed.");
		return FALSE;
	}
	PrintDebug("SetupHooks: Hook created for OnConversionModeSet.");

	if (MH_CreateHook((LPVOID)pActivate, &Hook_Activate,
		reinterpret_cast<LPVOID*>(&Original_Activate)) != MH_OK) {
		PrintDebug("SetupHooks: Error - MH_CreateHook for InputMethodProxy_Activate failed.");
		return FALSE;
	}
	PrintDebug("SetupHooks: Hook created for Activate.");

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
		PrintDebug("SetupHooks: Error - MH_EnableHook(MH_ALL_HOOKS) failed.");
		return FALSE;
	}

	PrintDebug("SetupHooks: All hooks enabled successfully. Waiting for triggers...");

	{
		int offsets = *(int*)(pGetActiveInputProfile + 0xF);
		PrintDebug("SetupHooks: Calculated offsets for G_InputModePtr: 0x%p", offsets);
		G_InputModePtr = (int*)(pGetActiveInputProfile + 0x13 + offsets);
		PrintDebug("SetupHooks: G_InputModePtr set to address 0x%p", (void*)G_InputModePtr);
	}

	return TRUE;
}

DWORD WINAPI HookThread(LPVOID lpParam) {
	PrintDebug("HookThread: Thread started. Calling SetupHooks...");

	if (!SetupHooks()) {
		PrintDebug("HookThread: SetupHooks failed. Thread exiting.");
	}
	else {
		PrintDebug("HookThread: SetupHooks successful. Thread will now idle.");
	}

	Hook_OnConversionModeSet_RemoveThread();

	return 0;
}



void CALLBACK WinEventProc(
	HWINEVENTHOOK hWinEventHook,
	DWORD event,
	HWND hwnd,
	LONG idObject,
	LONG idChild,
	DWORD dwEventThread,
	DWORD dwmsEventTime
) {
	PrintDebug("WinEventProc: Event received. HWND: 0x%p, idObject: %ld, idChild: %ld", hwnd, idObject, idChild);

	//去掉应用检查 每次切换焦点都触发
	/*
	static HWND lastHwnd = NULL;
	if (lastHwnd == hwnd) return;
	lastHwnd = hwnd;
	*/

	static INT64 lastruntime = 0;
	INT64 currenttime = GetTickCount64();
	if (currenttime < lastruntime + 100) return;
	lastruntime = currenttime;

	// 这里不直接用指针,因为指针获取的是实时的值, 切换窗口后输入法未切换到目标窗口并获取信息时就被这里取值了,而GetKeyboardLayout获取到没有被初始化的输入法的值
	DWORD dwThreadId = GetWindowThreadProcessId(hwnd, NULL);
	HKL hCurrentHkl = GetKeyboardLayout(dwThreadId);
	const HKL TARGET_HKL = (HKL)0x0000000004090409;
	PrintDebug("指针获取到的值: 0x%x 当前窗口HKL: 0x%p", *G_InputModePtr, (void*)hCurrentHkl);

	if (hCurrentHkl != TARGET_HKL)
	{
		// 旧的方式
		/*
		INPUT inputs[4] = { 0 };
		inputs[0].type = INPUT_KEYBOARD;
		inputs[0].ki.wVk = VK_LMENU;
		inputs[0].ki.dwFlags = 0;
		inputs[1].type = INPUT_KEYBOARD;
		inputs[1].ki.wVk = VK_LSHIFT;
		inputs[1].ki.dwFlags = 0;
		inputs[2].type = INPUT_KEYBOARD;
		inputs[2].ki.wVk = VK_LSHIFT;
		inputs[2].ki.dwFlags = KEYEVENTF_KEYUP;
		inputs[3].type = INPUT_KEYBOARD;
		inputs[3].ki.wVk = VK_LMENU;
		inputs[3].ki.dwFlags = KEYEVENTF_KEYUP;
		SendInput(ARRAYSIZE(inputs), inputs, sizeof(INPUT));
		*/

		//使用线程发送会出现切换混乱的问题
		//std::thread([]() {
			HWND hwnd = GetForegroundWindow();
			if (hwnd) {PostMessage(hwnd, WM_INPUTLANGCHANGEREQUEST, 0, (LPARAM)TARGET_HKL);}
			PrintDebug("PageDown Action -> EN-US (Cached HKL)");
		//	}).detach();
		


	}
}

DWORD WINAPI HookWinEventThread(_In_ LPVOID lpParameter) {
	HMODULE hModule = static_cast<HMODULE>(lpParameter);

	PrintDebug("HookWinEventThread: Thread started. HMODULE: 0x%p", hModule);

	HRESULT hr = CoInitialize(NULL);
	if (FAILED(hr)) {
		PrintDebug("HookWinEventThread: CoInitialize failed! HRESULT: 0x%x. Exiting thread.", hr);
		return 1;
	}

	g_hWinEventHook = SetWinEventHook(
		EVENT_OBJECT_FOCUS, // 监听焦点获取事件
		EVENT_OBJECT_FOCUS,
		NULL,               // hmodWinEventProc: 在 OUTOFCONTEXT 模式下为 NULL
		WinEventProc,       // 钩子回调函数
		0,                  // idProcess: 0 = 所有进程
		0,                  // idThread: 0 = 所有线程
		WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
	);

	if (g_hWinEventHook == NULL) {
		PrintDebug("HookWinEventThread: SetWinEventHook failed! Error: %u. Exiting thread.", GetLastError());
		CoUninitialize();
		return 1;
	}

	PrintDebug("HookWinEventThread: WinEventHook installed successfully.");

	MSG msg;
	while (GetMessageW(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessageW(&msg);
	}

	PrintDebug("HookWinEventThread: Message loop exited.");

	if (g_hWinEventHook != NULL) {
		UnhookWinEvent(g_hWinEventHook);
		g_hWinEventHook = NULL;
		CoUninitialize();
	}


	PrintDebug("HookWinEventThread: Thread finished.");
	return 0;

}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		g_hMutex = CreateMutexA(NULL, TRUE, "MyCtfmonHookMutex_12345_ABC");
		if (GetLastError() == ERROR_ALREADY_EXISTS) {
			if (g_hMutex) CloseHandle(g_hMutex);
			return FALSE;
		}

		DisableThreadLibraryCalls(hModule);

		OpenDebugConsole();

		HANDLE hThread = CreateThread(NULL, 0, HookThread, hModule, 0, NULL);
		if (hThread) CloseHandle(hThread);

		HANDLE hThread2 = CreateThread(NULL, 0, HookWinEventThread, hModule, 0, NULL);
		if (hThread2) CloseHandle(hThread2);
	}
	break;

	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		PrintDebug("DllMain: DLL_PROCESS_DETACH received. Uninitializing hooks...");
		if (MH_DisableHook(MH_ALL_HOOKS) == MH_OK) {
			MH_Uninitialize();
			PrintDebug("DllMain: MinHook uninitialized.");
		}

		if (g_hMutex) {
			ReleaseMutex(g_hMutex);
			CloseHandle(g_hMutex);
		}

		if (g_hWinEventHook != NULL)
		{
			UnhookWinEvent(g_hWinEventHook);
			g_hWinEventHook = NULL;
			CoUninitialize();
		}

		break;
	}
	return TRUE;
}