import pefile
import sys
import os
import subprocess

def GetFileInfo(pe):
    results = {}
    if not hasattr(pe, 'FileInfo'):
        return results
    for file_info in pe.FileInfo:
        for info in file_info:
            if info.Key == b'StringFileInfo':
                for string_table in info.StringTable:
                    for entry in string_table.entries.items():
                        key = entry[0].decode('utf-8', errors='replace')
                        value = entry[1].decode('utf-8', errors='replace')
                        results[key] = value
    return results

def GetVersionNumbers(pe):
    if not hasattr(pe, 'VS_FIXEDFILEINFO'):
        return (1, 0, 0, 0), (1, 0, 0, 0)
    
    fixed = pe.VS_FIXEDFILEINFO[0]
    
    fv = (
        (fixed.FileVersionMS >> 16) & 0xFFFF,
        (fixed.FileVersionMS)       & 0xFFFF,
        (fixed.FileVersionLS >> 16) & 0xFFFF,
        (fixed.FileVersionLS)       & 0xFFFF
    )
    pv = (
        (fixed.ProductVersionMS >> 16) & 0xFFFF,
        (fixed.ProductVersionMS)       & 0xFFFF,
        (fixed.ProductVersionLS >> 16) & 0xFFFF,
        (fixed.ProductVersionLS)       & 0xFFFF
    )
    return fv, pv

def CreateRC(string_info, file_ver, prod_ver, output_path):
    fv_comma = f"{file_ver[0]},{file_ver[1]},{file_ver[2]},{file_ver[3]}"
    pv_comma = f"{prod_ver[0]},{prod_ver[1]},{prod_ver[2]},{prod_ver[3]}"
    fv_dot   = f"{file_ver[0]}.{file_ver[1]}.{file_ver[2]}.{file_ver[3]}"
    pv_dot   = f"{prod_ver[0]}.{prod_ver[1]}.{prod_ver[2]}.{prod_ver[3]}"

    # Use values from source or fallback
    company      = string_info.get('CompanyName',    'Unknown')
    description  = string_info.get('FileDescription','Unknown')
    file_ver_str = string_info.get('FileVersion',     fv_dot)
    prod_ver_str = string_info.get('ProductVersion',  pv_dot)
    product_name = string_info.get('ProductName',    'Unknown')
    copyright    = string_info.get('LegalCopyright', 'Unknown')
    trademarks   = string_info.get('LegalTrademarks','')
    internal     = string_info.get('InternalName',   '')
    original     = string_info.get('OriginalFilename','')
    comments     = string_info.get('Comments',       '')

    rc = f"""#include <windows.h>

/////////////////////////////////////////////////////////////////////////////
// Cloned Resource
/////////////////////////////////////////////////////////////////////////////

VS_VERSION_INFO VERSIONINFO
    FILEVERSION     {fv_comma}
    PRODUCTVERSION  {pv_comma}
    FILEFLAGSMASK   VS_FFI_FILEFLAGSMASK
    FILEFLAGS       0x0L
    FILEOS          VOS__WINDOWS32
    FILETYPE        VFT_DLL
    FILESUBTYPE     VFT2_UNKNOWN
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName",      "{company}"
            VALUE "FileDescription",  "{description}"
            VALUE "FileVersion",      "{file_ver_str}"
            VALUE "ProductVersion",   "{prod_ver_str}"
            VALUE "ProductName",      "{product_name}"
            VALUE "LegalCopyright",   "{copyright}"
"""

    if trademarks:
        rc += f'            VALUE "LegalTrademarks",  "{trademarks}"\n'
    if internal:
        rc += f'            VALUE "InternalName",     "{internal}"\n'
    if original:
        rc += f'            VALUE "OriginalFilename", "{original}"\n'
    if comments:
        rc += f'            VALUE "Comments",         "{comments}"\n'

    rc += """        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(rc)
    print(f"[+] RC file written:     {output_path}")



def CloneDetails(source_dll, output_dir):
    if not os.path.exists(source_dll):
        print(f"[!] Source DLL not found: {source_dll}")
        sys.exit(1)

    os.makedirs(output_dir, exist_ok=True)

    print(f"[*] Reading from: {source_dll}")
    pe          = pefile.PE(source_dll)
    string_info = GetFileInfo(pe)
    file_ver, prod_ver = GetVersionNumbers(pe)
    pe.close()

    if not string_info:
        print("[!] No version info found in source DLL")
        sys.exit(1)

    print("\n[*] File details found:")
    for k, v in string_info.items():
        print(f"  {k:<35} {v}")
    print(f"  {'FileVersion (binary)':<35} {'.'.join(map(str, file_ver))}")
    print(f"  {'ProductVersion (binary)':<35} {'.'.join(map(str, prod_ver))}")

    print(f"\n[*] Generating files in: {output_dir}")

    CreateRC(string_info,     file_ver, prod_ver, os.path.join(output_dir, 'version.rc'))

    print(f"""
[+] All files generated successfully.
\n[*] Building .res file...
""")
    try:
        result = subprocess.run(["rc.exe", "/fo",output_dir+"\\version.res",output_dir+"\\version.rc"], capture_output=True, text=True)
        print(result.stdout)
        print("[+] .res Built successfully in "+sys.argv[2])
        print("\n[!] Check resulting .rc file for strange special characters. Remove if they exist and rebuild .res file with:\nrc.exe /fo version.res version.rc")
    except FileNotFoundError:
        print("[!] rc.exe not found, make sure to run in VS developer shell.")
        print("[!] Can be built manually with: rc.exe /fo version.res version.rc")
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python {sys.argv[0]} <source_dll> <output_dir>")
        print(f"Example: python {sys.argv[0]} libvlc.dll ./output")
        sys.exit(1)

    CloneDetails(sys.argv[1], sys.argv[2])
