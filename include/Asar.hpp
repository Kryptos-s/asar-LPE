#pragma once

#include <windows.h>

#define ASAR_BLOCK_SIZE  (4 * 1024 * 1024)

struct FILE_ENTRY
{
    LPSTR        pszRelativePath;
    DWORD        dwOffset;
    DWORD        dwSize;
    BOOL         bIsDirectory;
    BOOL         bIsExecutable;
    LPSTR        pszHash;
    LPSTR*       ppszBlocks;
    DWORD        dwBlockCount;
    FILE_ENTRY*  pNext;
};
using PFILE_ENTRY = FILE_ENTRY*;

BOOL UnpackAsarFile(LPCSTR pszAsarPath, LPCSTR pszOutputDir);
BOOL PackAsarFile(LPCSTR pszInputDir, LPCSTR pszAsarPath);
BOOL VerifyAsarFile(LPCSTR pszAsarPath);
