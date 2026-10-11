// Shared file details for every Connected Hearts binary. Each target's .rc defines CH_DESC and
// CH_FILE, then includes this file.
#include <winver.h>
#define CH_VER 0,1,1,0
#define CH_VER_STR "0.1.1.0"
VS_VERSION_INFO VERSIONINFO
FILEVERSION CH_VER
PRODUCTVERSION CH_VER
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE CH_TYPE
FILESUBTYPE 0x0L
BEGIN
    BLOCK "StringFileInfo"
    BEGIN
        BLOCK "040904b0"
        BEGIN
            VALUE "CompanyName", "Connected Hearts"
            VALUE "FileDescription", CH_DESC
            VALUE "FileVersion", CH_VER_STR
            VALUE "InternalName", CH_FILE
            VALUE "LegalCopyright", "Connected Hearts contributors, GPL-3.0"
            VALUE "OriginalFilename", CH_FILE
            VALUE "ProductName", "Connected Hearts"
            VALUE "ProductVersion", CH_VER_STR
        END
    END
    BLOCK "VarFileInfo"
    BEGIN
        VALUE "Translation", 0x409, 1200
    END
END
