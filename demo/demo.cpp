/*
	yapi demo

	Copyright (c) 2010-2018 <http://ez8.co> <orca.zhang@yahoo.com>
	This library is released under the MIT License.

	Please see LICENSE file or visit https://github.com/ez8-co/yapi for details.
*/
#include "stdafx.h"
#include "../yapi.hpp"

#include <TlHelp32.h>

using namespace yapi;

DWORD64 WINAPI GetModuleHandleDw64(HANDLE hProcess, const TCHAR* moduleName);

#if 0
typedef DWORD64(WINAPI* FUNC)(DWORD64, DWORD64, DWORD64, DWORD64, DWORD64, DWORD64, DWORD64, DWORD64, DWORD64, DWORD64);
struct Param1 {
	DWORD64 ret;
	FUNC func;
	DWORD64 arg1;
	DWORD64 arg2;
	DWORD64 arg3;
	DWORD64 arg4;
	DWORD64 arg5;
	DWORD64 arg6;
	DWORD64 arg7;
	DWORD64 arg8;
	DWORD64 arg9;
	DWORD64 arg10;
};

__declspec(noinline) DWORD WINAPI Delegator(Param1* param)
{
	return param ? (param->ret ? (param->ret = param->func(param->arg1, param->arg2, param->arg3, param->arg4, param->arg5, param->arg6, param->arg7, param->arg8, param->arg9, param->arg10))
		: (param->func(param->arg1, param->arg2, param->arg3, param->arg4, param->arg5, param->arg6, param->arg7, param->arg8, param->arg9, param->arg10))) : 0;
}
#endif

int main()
{
#if 0
	Param1 param1;
	Delegator(&param1);
#endif

#if 0
	// bellow shows how to use like windows API
	X64Call RtlCreateUserThread("RtlCreateUserThread");
	if (!RtlCreateUserThread) return 0;
	X64Call LdrUnloadDll("LdrUnloadDll");
	if (!LdrUnloadDll) return 0;

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	if (Process32First(hSnapshot, &pe32)) {
		do {
			// _tprintf_s(_T("%s [%u]\n"), pe32.szExeFile, pe32.th32ProcessID);
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
			BOOL isRemoteWow64 = FALSE;
			IsWow64Process(hProcess, &isRemoteWow64);
			if (!isRemoteWow64) {
				DWORD64 wow64DllBaseAddr = GetModuleHandle64(hProcess, _T("x64.dll"));
				if (wow64DllBaseAddr) {
					DWORD64 ret = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, NULL, LdrUnloadDll, wow64DllBaseAddr, NULL, NULL);
				}
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
#endif

#if 0
	typedef int (NTAPI *RTL_ADJUST_PRIVILEGE)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
	RTL_ADJUST_PRIVILEGE RtlAdjustPrivilege = (RTL_ADJUST_PRIVILEGE)GetProcAddress(detail::hNtDll, "RtlAdjustPrivilege");
	RtlAdjustPrivilege(20, 1, 0, NULL);
#endif

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_tcsicmp(pe32.szExeFile, _T("explorer.exe")))
				continue;
			HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

#if 1

			YAPICall MessageBoxA(hProcess, _T("user32.dll"), "MessageBoxA");
			MessageBoxA(NULL, "MessageBoxA : Hello World!", "From ez8.co", MB_OK);

			YAPI(hProcess, _T("user32.dll"), MessageBoxW)
				(NULL, L"MessageBoxW: Hello World!", L"From ez8.co", MB_OK);

			YAPICall GetCurrentProcessId(hProcess, _T("kernel32.dll"), "GetCurrentProcessId");
			DWORD pid = GetCurrentProcessId();

#else

			DWORD64 user32Dll = GetModuleHandle64(hProcess, _T("user32.dll"));
			if(!user32Dll) continue;

			// sample show you how to solve CreateRemoteThread + GetExitCodeThread return partial (4/8 bytes) result problem under x64
			// method 1:
			DWORD64 user32Dll2 = GetModuleHandleDw64(hProcess, _T("user32.dll"));

			// method 2:
			YAPICall GetModuleHandle(hProcess, _T("kernel32.dll"), sizeof(TCHAR) == sizeof(char) ? "GetModuleHandleA" : "GetModuleHandleW");
			DWORD64 user32Dll1 = GetModuleHandle.Dw64()(_T("user32.dll"));

			/*
				DWORD WINAPI MessageBoxDelegator(MessageBoxParam* param)
			01042340 85 C9                test        ecx,ecx  
			01042342 74 11                je          MessageBoxDelegator+15h (01042355h)  
			01042344 FF 71 20             push        dword ptr [ecx+20h]  
			01042347 8B 01                mov         eax,dword ptr [ecx]  
			01042349 FF 71 10             push        dword ptr [ecx+10h]  
			0104234c FF 71 18             push        dword ptr [ecx+18h]  
			0104234F FF 71 08             push        dword ptr [ecx+8]  
			01042352 FF D0                call        eax  
			   120: }
			01042354 C3                   ret  
			   119: 	return param ? (param->MessageBoxA((HWND)param->hWnd, (LPCSTR)param->lpText, (LPCSTR)param->lpCaption, param->uType)) : 0;
			01042355 33 C0                xor         eax,eax  
			   120: }
			01042357 C3                   ret
			*/
			/*
				DWORD WINAPI MessageBoxDelegator(MessageBoxParam* param)
				{
			00007FF69EAA1080 48 8B C1             mov         rax,rcx  
					return param ? (param->MessageBoxA(param->hWnd, param->lpCaption, param->lpText, param->uType)) : 0;
			00007FF69EAA1083 48 85 C9             test        rcx,rcx  
			00007FF69EAA1086 74 13                je          MessageBoxDelegator+1Bh (07FF69EAA109Bh)  
			00007FF69EAA1088 44 8B 49 20          mov         r9d,dword ptr [rcx+20h]  
			00007FF69EAA108C 4C 8B 41 10          mov         r8,qword ptr [rcx+10h]  
			00007FF69EAA1090 48 8B 51 18          mov         rdx,qword ptr [rcx+18h]  
			00007FF69EAA1094 48 8B 49 08          mov         rcx,qword ptr [rcx+8]  
			00007FF69EAA1098 48 FF 20             jmp         qword ptr [rax]  
			00007FF69EAA109B 33 C0                xor         eax,eax  
				}
			00007FF69EAA109D C3                   ret 
			*/
			const unsigned char shellcode_x86[] = { 0x85, 0xc9, 0x74, 0x11, 0xff, 0x71, 0x20, 0x8b, 0x01, 0xff, 0x71, 0x10, 0xff, 0x71, 0x18, 0xff, 
													0x71, 0x08, 0xff, 0xd0, 0xc3, 0x33, 0xc0, 0xc3 };
			const unsigned char shellcode[] = { 0x48, 0x8b, 0xc1, 0x48, 0x85, 0xc9, 0x74, 0x13, 0x44, 0x8b, 0x49, 0x20, 0x4c, 0x8b, 0x41, 0x10, 
												0x48, 0x8b, 0x51, 0x18, 0x48, 0x8b, 0x49, 0x08, 0x48, 0xff, 0x20, 0x33, 0xc0, 0xc3 };

			struct MessageBoxParam {
				DWORD64 MessageBoxA;
				DWORD64 hWnd;
				DWORD64 lpCaption;
				DWORD64 lpText;
				DWORD64 uType;
			} param = { NULL, NULL, NULL, NULL, MB_OK };

			const TCHAR* szCaption = _T("From ez8.co");
			const TCHAR* szText = _T("Hello World!");

#ifdef UNICODE
			param.MessageBoxA = GetProcAddress64(hProcess, user32Dll, "MessageBoxW");
#else
			param.MessageBoxA = GetProcAddress64(hProcess, user32Dll, "MessageBoxA");
#endif

			if(!param.MessageBoxA) continue;

			RemoteWriter caption(hProcess, szCaption, (lstrlen(szCaption) + 1) * sizeof(TCHAR));
			if (!(param.lpCaption = caption)) continue;

			RemoteWriter text(hProcess, szText, (lstrlen(szText) + 1) * sizeof(TCHAR));
			if (!(param.lpText = text)) continue;

			RemoteWriter p(hProcess, &param, sizeof(param));
			if (!p) continue;

			RemoteWriter sc(hProcess, detail::is64BitOS ? shellcode : shellcode_x86, (detail::is64BitOS ? sizeof(shellcode) : sizeof(shellcode_x86)) + 1, PAGE_EXECUTE_READWRITE);
			if (!sc) continue;
			sc.SetDontRelese();

			HANDLE hThread = CreateRemoteThread64(hProcess, NULL, 0, sc, p, 0, NULL);
			WaitForSingleObject(hThread, 1000);
			CloseHandle(hThread);
#endif
		} while (Process32Next(hSnapshot, &pe32));
	}

    return 0;
}

DWORD64 WINAPI GetModuleHandleDw64(HANDLE hProcess, const TCHAR* moduleName)
{
	RemoteWriter modName(hProcess, moduleName, (lstrlen(moduleName) + 1) * sizeof(TCHAR));
	if (!modName) return NULL;

	DWORD64 hKernel32 = GetModuleHandle64(hProcess, _T("kernel32.dll"));
	struct Param {
		DWORD64 func;
		DWORD64 arg;
		DWORD64 result;
	} param = { GetProcAddress64(hProcess, hKernel32,
#ifdef UNICODE
		"GetModuleHandleW"
#else
		"GetModuleHandleA"
#endif // !UNICODE
	), modName, NULL };
	if (!param.func) return NULL;

	RemoteWriter p(hProcess, &param, sizeof(param));
	if (!p) return NULL;

	const unsigned char shellcode_x86[] = { 0x56, 0x8b, 0xf1, 0x85, 0xf6, 0x74, 0x0e, 0xff, 0x76, 0x08, 0x8b, 0x06, 0xff, 0xd0, 0x99, 0x89,
		0x46, 0x10, 0x89, 0x56, 0x14, 0x33, 0xc0, 0x5e, 0xc3 };
	const unsigned char shellcode[] = { 0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xc9, 0x74, 0x0a, 0x48, 0x8b,
		0x49, 0x08, 0xff, 0x13, 0x48, 0x89, 0x43, 0x10, 0x33, 0xc0, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3 };
	/*
	DWORD WINAPI helpler(ParamX* param) {
	00B62320 56                   push        esi
	00B62321 8B F1                mov         esi,ecx
	22:     if (param) param->result = param->func((LPCSTR)param->arg);
	00B62323 85 F6                test        esi,esi
	00B62325 74 0E                je          helpler+15h (0B62335h)
	00B62327 FF 76 08             push        dword ptr [esi+8]
	00B6232A 8B 06                mov         eax,dword ptr [esi]
	00B6232C FF D0                call        eax
	00B6232E 99                   cdq
	00B6232F 89 46 10             mov         dword ptr [esi+10h],eax
	00B62332 89 56 14             mov         dword ptr [esi+14h],edx
	23:     return 0;
	00B62335 33 C0                xor         eax,eax
	00B62337 5E                   pop         esi
	24: }
	00B62338 C3                   ret
	*/
	/*
	DWORD WINAPI helpler(Param* param) {
	00007FF7E0E81080 40 53                push        rbx
	00007FF7E0E81082 48 83 EC 20          sub         rsp,20h
	00007FF7E0E81086 48 8B D9             mov         rbx,rcx
	91:             if(param) param->result = param->func(param->arg);
	00007FF7E0E81089 48 85 C9             test        rcx,rcx
	00007FF7E0E8108C 74 0A                je          helpler+18h (07FF7E0E81098h)
	00007FF7E0E8108E 48 8B 49 08          mov         rcx,qword ptr [rcx+8]
	00007FF7E0E81092 FF 13                call        qword ptr [rbx]
	00007FF7E0E81094 48 89 43 10          mov         qword ptr [rbx+10h],rax
	92:             return 0;
	00007FF7E0E81098 33 C0                xor         eax,eax
	93:         }
	00007FF7E0E8109A 48 83 C4 20          add         rsp,20h
	00007FF7E0E8109E 5B                   pop         rbx
	00007FF7E0E8109F C3                   ret
	*/
	RemoteWriter sc(hProcess, detail::is64BitOS ? shellcode : shellcode_x86, (detail::is64BitOS ? sizeof(shellcode) : sizeof(shellcode_x86)) + 1, PAGE_EXECUTE_READWRITE);
	if (!sc) return NULL;

	HANDLE hThread = CreateRemoteThread64(hProcess, NULL, 100, sc, p, 0, NULL);
	if (!hThread) return FALSE;
	WaitForSingleObject(hThread, 1000);
	CloseHandle(hThread);

	ReadProcessMemory64(hProcess, p, &param, sizeof(param), NULL);
	return param.result;
}
