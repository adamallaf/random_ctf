# Extract embedded pck from an ELF
#   1. get pck section size and offset
#   ```
#   $ readelf -S godot_game.elf
#   section [ 3] pck offset: 0x043d8a38 size: 0x0145e328                                                                                                                                                          
#   ```
#   2. extract with dd 
#   ```
#   $ dd if=godot_game.elf of=game.pck bs=1 skip=71141944 count=21357352
#   ```
#
# Godot engine source code (tag 4.2) analysis
#
# Save Pack File
# godot/editor/export/editor_export_platform.cpp::EditorExportPlatform::save_pack()  L1505
# godot/core/io/file_access_pack.h::PackedData::struct PackedFile (L62)
# godot/core/io/pck_packer.cpp::PCKPacker::flush()  L184
#
# Linux binary is patched in:
# godot/platform/linuxbsd/export/export_plugin.cpp::EditorExportPlatformLinuxBSD::fixup_embedded_pck()  L291
# 
# Encrypted data structure:
# godot/core/io/file_access_encrypted.cpp::FileAccessEncrypted::_close()  L123
# hash 16, size 8, iv 16, data
#
# End of PCK file looks like the hex dump below
# 0145e310: 0000 0000 0000 0000 0000 0000 1ce3 4501  ..............E.
# 0145e320: 0000 0000 4744 5043                      ....GDPC
# the data end is marked by end offset (uint64) at 0x0145e31c with offset value(same as the offset) and MAGIC GDPC (uint32)
# seek(current_pos - 0x0145e31c - 8): should equals 0
# The code responsible for validating it can be found in:
# godot/core/io/file_access_pack.cpp::PackedSourcePCK::try_open_pack()  L130
#
import binascii
import struct

PACK_HEADER_MAGIC = 0x43504447  # GDPC
ENCRYPTED_HEADER_MAGIC = 0x43454447  # GDEC

with open('game.pck', 'rb') as pack:
    # godot/core/io/pck_packer.cpp::PCKPacker::pck_start()
    # godot/core/io/file_access_pack.cpp::PackedSourcePCK::try_open_pack()  L199
    magic_bytes = struct.unpack('<I', pack.read(4))[0]
    assert magic_bytes == PACK_HEADER_MAGIC
    format_version = struct.unpack('<I', pack.read(4))[0]
    version_major = struct.unpack('<I', pack.read(4))[0]
    version_minor = struct.unpack('<I', pack.read(4))[0]
    version_patch = struct.unpack('<I', pack.read(4))[0]
    pack_flags = struct.unpack('<I', pack.read(4))[0]
    file_base = struct.unpack('<Q', pack.read(8))[0]

    print(f"Godot v{version_major}.{version_minor}.{version_patch} PCK v{format_version} file")
    print(f"pack flags: {pack_flags:08x}h")

    pack.read(0x40) # Skip the empty padding (reserved)

    # godot/core/io/file_access_pack.cpp::PackedSourcePCK::try_open_pack()  L217
    file_count = struct.unpack('<I', pack.read(4))[0]
    print("file count:", file_count)
    print(24 * "-")

    for i in range(file_count):
        print(f"File: {i}")
        name_len = struct.unpack('<I', pack.read(4))[0]
        name = pack.read(name_len).rstrip(b'\x00').decode('utf-8', errors="ignore")
        print(f"name length: {name_len} ({name_len:#06x})")
        print(f"name: \"{name}\"")

        offset = struct.unpack('<Q', pack.read(8))[0]
        print(f"offset: {offset} ({offset:#010x})")
        size = struct.unpack('<Q', pack.read(8))[0]
        print(f"size: {size} ({size:#010x})")

        md5_hash = pack.read(16)
        print(f"md5sum: {binascii.b2a_hex(md5_hash).decode()}")
        is_encrypted = bool(struct.unpack('<I', pack.read(4))[0])
        print(f"is encrypted: {is_encrypted}")
        print()
