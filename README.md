# YAPI -- Yet Another Process Injector
A fusion injector that reduce differences between x64, wow64 and x86 processes according to [Mr.Rewolf's article](http://blog.rewolf.pl/blog/?p=102).

**Keywords: HEADER-ONLY, DLL-FREE, ANY-CALLEE, ANY-CALLER, ANY-WIN-OS, LOCAL-LIKE**

[![license](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat)](https://github.com/ez8-co/yapi/blob/master/LICENSE)
[![Mentioned in Awesome Go](https://awesome.re/mentioned-badge.svg)](https://github.com/ExpLife0011/awesome-windows-kernel-security-development#inject-technique-ring3)

# Wiki

- **Wow64**: Windows-on-Windows 64-bit, which 32-bit process works in.

# Features

- Cross x86 & x64 injection **without any external \*.dll or even \*.lib**:
    - x86 injector -> x86 process @ 32-bit OS
    - wow64 injector -> wow64 process @ 64-bit OS
    - wow64 injector -> x64 process @ 64-bit OS
    - x64 injector -> wow64 process @ 64-bit OS
    - x64 injector -> x64 process @ 64-bit OS

- In-process call x64 functions / APIs for Wow64 process

- Local-like remote call of target process
    - Remote call multi-params (more than one) windows API of target process
    - Remote call windows API that return 64-bit result of target process

# How to use

- `X64Call` example (Unload dll in remote process)

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

    - Available constructors:

      - Specified module is allowed (`ntdll.dll` as default)
    
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
    ```

    - Available constructors:

      - Specified module or module name is allowed (`ntdll.dll` as default).
      
      - **NOTICE: If failed to fetch 64-bit module, will automatically fetch 32-bit modules in wow64 process under 64-bit OS**.

        ```cpp
        YAPICall(HANDLE hProcess, const char* funcName);

        YAPICall(HANDLE hProcess, DWORD64 moudle, const char* funcName);

        YAPICall(HANDLE hProcess, const TCHAR* modName, const char* funcName);
        ```

- 64-bit result example (`GetModuleHandle` of `user32.dll` under 64-bit OS)

    ```cpp
        YAPICall GetModuleHandle(hProcess, _T("kernel32.dll"), sizeof(TCHAR) == sizeof(char) ? "GetModuleHandleA" : "GetModuleHandleW");
        DWORD64 user32Dll = GetModuleHandle.Dw64()(_T("user32.dll"));
    ```

- `Timeout` example (`GetCurrentProcessId` in 300ms)

    ```cpp
        YAPICall GetCurrentProcessId(hProcess, _T("kernel32.dll"), "GetCurrentProcessId");
        DWORD pid = GetCurrentProcessId.Timeout(300)();
    ```

- `Timeout` & 64-bit result example (`GetModuleHandle` in 300ms)

    ```cpp
        DWORD64 user32Dll = GetModuleHandle.Dw64().Timeout(300)(_T("user32.dll"));
    ```

- **Popular `LoadLibrary` example**

    ```cpp
        YAPICall LoadLibraryA(hProcess, _T("kernel32.dll"), "LoadLibraryA");
        DWORD64 x86Dll = LoadLibraryA("D:\\x86.dll");
        DWORD64 x64Dll = LoadLibraryA.Dw64()("D:\\x64.dll");
        _tprintf(_T("X86: %I64x\nX64: %I64x\n"), x86Dll, x64Dll);
    ```

- API List:

    |  API Name       |   x86 Equivalent   | Notes         |
    |---------------|------------------------|---------------|
    | GetNtDll64           |                         |       |
    | GetModuleHandle64    | GetModuleHandle         | overloaded version |
    | GetProcAddress64     | GetProcAddress          | overloaded version |
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

    |  Class Name       |   32-bit OS Support   | 64-bit OS Compatiblity         |
    |---------------|------------------------|---------------|
    | X64Call           | :white_check_mark: | NOT READY NOW |
    | ProcessWriter    | :white_check_mark: | :white_check_mark: |
    | YAPICall     | :white_check_mark: | :white_check_mark: |

# Inside principle

- Nomal x64->x64, x86->x86 injection:
  - Use `CreateRemoteThread` / `RtlCreateUserThread`
  - You can change other methods by yourself.
  - FYR: [fdiskyou/injectAllTheThings](https://github.com/fdiskyou/injectAllTheThings)

- Multi-params windows API:
  - Pack function address and params in one structure and use shell code to execute in remote process.
  - See `X86/X64Delegator_disassemble` for details in [disassemble directory](https://github.com/ez8-co/yapi/tree/master/disas).

- x64 call for wow64 process:
  - Switch to x64 mode
  - See [references](#references) for details.

- x64 process inject to wow64 process:
  - **Use trampoline:**
    - `CreateRemoteThread`(x64): x64 shell code with x86 mode switch (1 arg: function->x86 shell code with one param, param->packed x86 structure) -> pass packed structure (x86 real to call function address and params) to x86 shell code -> pass params to real function.
  - **NOTICE: function address(target module) should be valid in target process, but not needed in source injector.**

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
    | Windows 7             | Tested on 64-bit, should also work on 32-bit |
    | Windows Vista         | Should work on both 64-bit and 32-bit |
    | Windows XP            | Should work on both 64-bit and 32-bit |

# References

- [Mixing x86 with x64 code](http://blog.rewolf.pl/blog/?p=102) @rewolf

# Roadmap

- More simple impl of `X64Call`.
- 64-bit OS compatible support of `X64Call`.
- Finish shell codes that more than 6 arguments for `YAPICall`.
- Support to fetch specified bit module for `YAPICall` (32-bit or 64-bit).
- Same function call (mirror call) automatically in remote process.
- Self-defined function call in remote process.
- IAT/inline hook in remote process.
- Support other 7 optional inject methods.



## Sponsors

Support this project by becoming a sponsor. Your logo will show up here with a link to your website. [[Become a sponsor](https://opencollective.com/yapi#sponsor)]

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/justnonamenoname">
        <img src="https://avatars.githubusercontent.com/u/23149612?v=4" width="64px;" alt=""/>
        <br />
        <b>][Noname][</b>
        <br />
      </a>
    </td>
  </tr>
</table>
<a href="https://opencollective.com/yapi/sponsor/0/website" target="_blank"><img src="https://opencollective.com/yapi/sponsor/0/avatar.svg"></a>
<a href="https://opencollective.com/yapi/sponsor/1/website" target="_blank"><img src="https://opencollective.com/yapi/sponsor/1/avatar.svg"></a>
<a href="https://opencollective.com/yapi/sponsor/2/website" target="_blank"><img src="https://opencollective.com/yapi/sponsor/2/avatar.svg"></a>
<a href="https://opencollective.com/yapi/sponsor/3/website" target="_blank"><img src="https://opencollective.com/yapi/sponsor/3/avatar.svg"></a>

## Contributors

This project exists thanks to all the people who contribute.

Please give us a 💖 star 💖 to support us. Thank you.

And thank you to all our backers! 🙏

<a href="https://opencollective.com/yapi/backer/0/website?requireActive=false" target="_blank"><img src="https://opencollective.com/yapi/backer/0/avatar.svg?requireActive=false"></a>
<a href="https://opencollective.com/yapi/backer/1/website?requireActive=false" target="_blank"><img src="https://opencollective.com/yapi/backer/1/avatar.svg?requireActive=false"></a>
<a href="https://opencollective.com/yapi/backer/2/website?requireActive=false" target="_blank"><img src="https://opencollective.com/yapi/backer/2/avatar.svg?requireActive=false"></a>
<a href="https://opencollective.com/yapi/backer/3/website?requireActive=false" target="_blank"><img src="https://opencollective.com/yapi/backer/3/avatar.svg?requireActive=false"></a>
<a href="https://opencollective.com/yapi#backers" target="_blank"><img src="https://opencollective.com/yapi/contributors.svg?width=890" /></a>

# Misc

- Please feel free to use yapi.
- Looking forward to your suggestions.
