# yapi -- Yet Another Process Injector
A fusion library that reduce differences between x64, wow64 and x86 processes according to [Mr.Rewolf's article](http://blog.rewolf.pl/blog/?p=102).

**Keywords: header-only, dll-free, any-callee, any-caller, any-win-os, local-like**

[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/ez8-co/yapi/blob/master/LICENSE)

# Wiki

- **Wow64**: Windows-on-Windows 64-bit, which 32-bit process works in.

# Features

- Cross x86 & x64 injection **without any external dll or even lib**:
    - x86 injector -> x86 process @ x86 OS
    - wow64 injector -> wow64 process @ x64 OS
    - wow64 injector -> x64 process @ x64 OS
    - x64 injector -> wow64 process @ x64 OS
    - x64 injector -> x64 process @ x64 OS

- In-process call x64 functions / APIs for Wow64 process

- Local-like remote call of target process
    - Remote call multi-param (more than one) WINAPI of target process
    - Remote call WINAPI that return 64-bit result of target process

# How to use

- API List:

    |  API Name       |   x86 Equivalent   | Notes         |
    |---------------|------------------------|---------------|
    | GetNtDll64           |                         |       |
    | GetModuleHandle64    | GetModuleHandle         | 2 params overload version |
    | GetProcAddress64     | GetProcAddress          | 3 params overload version |
    | SetLastError64       | SetLastError            |       |
    | VirtualQueryEx64     | VirtualQueryEx          |       |
    | VirtualAllocEx64     | VirtualAllocEx          |       |
    | VirtualFreeEx64      | VirtualFreeEx           |       |
    | VirtualProtectEx64   | VirtualProtectEx        |       |
    | ReadProcessMemory64  | ReadProcessMemory       |       |
    | WriteProcessMemory64 | WriteProcessMemory      |       |
    | LoadLibrary64        | LoadLibrary             |       |
    | CreateRemoteThread64 | CreateRemoteThread      |       |

- Class List:

    |  Class Name       |   x86 Support   | x64 Support         |
    |---------------|------------------------|---------------|
    | X64Call           |  | :white_check_mark: |
    | ProcessWriter    | :white_check_mark: | :white_check_mark: |
    | YAPICall     | :white_check_mark: | :white_check_mark: |

- `X64Call` example (Unload dll at `dllBaseAddr` in remote process)

    ```cpp
        X64Call RtlCreateUserThread("RtlCreateUserThread");
        // Validate RtlCreateUserThread
        if (!RtlCreateUserThread) return 0;

        X64Call LdrUnloadDll("LdrUnloadDll");
        // Validate LdrUnloadDll
        if (!LdrUnloadDll) return 0;

        // => local-like call
        DWORD64 ret = RtlCreateUserThread(hProcess, NULL, FALSE, 0, 0, NULL, LdrUnloadDll, dllBaseAddr, NULL, NULL);
    ```

    - Available constructors: specified module is allowed (`ntdll.dll` as default)
    
    ```cpp
        X64Call(const char* funcName);
        X64Call(DWORD64 module, const char* funcName);
    ```

- `YAPICall` example (`MessageBox` in remote process)

    ```cpp
        YAPICall MessageBoxA(hProcess, _T("user32.dll"), "MessageBoxA");

        // => local-like call
        MessageBoxA(NULL, "MessageBoxA : Hello World!", "From ez8.co", MB_OK);

        YAPI(hProcess, _T("user32.dll"), MessageBoxW)
            (NULL, L"MessageBoxW: Hello World!", L"From ez8.co", MB_OK);

        YAPICall GetCurrentProcessId(hProcess, _T("kernel32.dll"), "GetCurrentProcessId");

        // => local-like call
        DWORD pid = GetCurrentProcessId();
        _tprintf(_T("Result: %d\n"), pid);
    ```

    - Available constructors: specified module or module name is allowed (`ntdll.dll` as default). **NOTICE: If failed to fetch x64 module, will automatically fetch 32-bit modules in wow64 process under x64 OS**.

    ```cpp
        YAPICall(HANDLE hProcess, const char* funcName);
        YAPICall(HANDLE hProcess, DWORD64 moudle, const char* funcName);
        YAPICall(HANDLE hProcess, const TCHAR* modName, const char* funcName);
    ```

- 64-bit result example (`GetModuleHandle` of `user32.dll` under x64)

    ```cpp
        YAPICall GetModuleHandle(hProcess, _T("kernel32.dll"), sizeof(TCHAR) == sizeof(char) ? "GetModuleHandleA" : "GetModuleHandleW");
        DWORD64 user32Dll = GetModuleHandle.Dw64()(_T("user32.dll"));
    ```

- `Timeout` example (`GetCurrentProcessId` in 300ms)

    ```cpp
        YAPICall GetCurrentProcessId(hProcess, _T("kernel32.dll"), "GetCurrentProcessId");
        DWORD pid = GetCurrentProcessId.Timeout(300)();
    ```

# Inside principle

- Nomal x64->x64, x86->x86 injection:
  - Use `CreateRemoteThread` / `RtlCreateUserThread`
  - You can change other methods by yourself.
  - FYR: [fdiskyou/injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings)

- Multi-param WINAPI:
  - Pack function address and params in one structure and use shell code to execute in remote process.
  - See `X86/X64Delegator_disassemble` for details in [disassemble directory](https://github.com/ez8-co/yapi/tree/master/disassemble).

- x64 call for wow64 process:
  - Switch to x64 mode
  - See [references](#references) for details.

- x64 process inject to wow64 process:
  - **Use trampoline:**
    - `CreateRemoteThread`(x64): x64 shell code with x86 mode switch (1 arg: function->x86 shell code with one param, param->packed x86 structure) -> pass packed structure (x86 real to call function address and params) to x86 shell code -> pass params to real function.
  - **NOTICE: function address should be valid in target process, and but not source injector.**

- 64-bit result:
  - Add a `DWORD64` result field to package.
  - Obtain result if needed.
  - `ReadProcessMemory` after remote thread finished.

# Compatibility

- Operating systems that have been tested are shown in table below.

    | Operating System      |   Notes  |
    |-----------------------|----------|
    | Windows 10            | Tested on 64-bit, should also work on 32-bit |
    | Windows 8             | Should work on both 64-bit and 32-bit |
    | Windows 7             | Should work on both 64-bit and 32-bit |
    | Windows XP            | Should work on both 64-bit and 32-bit |

# References

- [Mixing x86 with x64 code](http://blog.rewolf.pl/blog/?p=102) @rewolf

# Roadmap

- Finish shell codes that more than 6 arguments for `YAPICall`.
- Support to fetch specified bit module for `YAPICall` (32-bit or 64-bit).

# Misc

- Please feel free to use yapi.
- Looking forward to your suggestions.

