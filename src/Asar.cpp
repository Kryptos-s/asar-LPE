#include <windows.h>
#include <strsafe.h>
#include <shlwapi.h>
#include <bcrypt.h>
#include <stdio.h>
#include <algorithm>

#pragma comment(lib, "bcrypt.lib")

#include "Json.hpp"
#include "Asar.hpp"

#define SHA256_HASH_SIZE  32

static BOOL       CreateDirectoryRecursive(LPCSTR pszPath);
static BOOL       ExtractFilesFromJson(PJSON_VALUE pFiles, LPCSTR pszPrefix, PFILE_ENTRY* ppEntries);
static PFILE_ENTRY BuildFileList(LPCSTR pszDirectory, PDWORD pdwTotalSize);
static PJSON_VALUE BuildJsonFromFileList(PFILE_ENTRY pEntries);

static BOOL CreateDirectoryRecursive(LPCSTR pszPath)
{
    CHAR  szPath[MAX_PATH] = {};
    DWORD dwError          = 0;

    if (!pszPath || lstrlenA(pszPath) == 0)
        return FALSE;

    if (FAILED(StringCbCopyA(szPath, sizeof(szPath), pszPath)))
        return FALSE;

    LPSTR pszSlash = strchr(szPath, '\\');

    while (pszSlash)
    {
        *pszSlash = '\0';

        if (lstrlenA(szPath) > 0 && lstrcmpA(szPath, ".") != 0)
        {
            if (!CreateDirectoryA(szPath, nullptr))
            {
                dwError = GetLastError();
                if (dwError != ERROR_ALREADY_EXISTS)
                    return FALSE;
            }
        }

        *pszSlash = '\\';
        pszSlash  = strchr(pszSlash + 1, '\\');
    }

    if (!CreateDirectoryA(szPath, nullptr))
    {
        dwError = GetLastError();
        if (dwError != ERROR_ALREADY_EXISTS)
            return FALSE;
    }

    return TRUE;
}

static BOOL ExtractFilesFromJson(PJSON_VALUE pFiles, LPCSTR pszPrefix, PFILE_ENTRY* ppEntries)
{
    if (!pFiles || pFiles->type != JSON_TYPE_OBJECT || !ppEntries)
        return FALSE;

    PJSON_PAIR   pPair        = pFiles->pObject;
    PFILE_ENTRY  pEntry       = nullptr;
    PFILE_ENTRY  pDirEntry    = nullptr;
    LPSTR        pszFullPath  = nullptr;
    BOOL         bResult      = FALSE;

    while (pPair)
    {
        pszFullPath = nullptr;

        SIZE_T nPrefixLen   = pszPrefix ? lstrlenA(pszPrefix) : 0;
        SIZE_T nKeyLen      = lstrlenA(pPair->pszKey);
        SIZE_T nFullPathSize = nPrefixLen + nKeyLen + 2;

        pszFullPath = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nFullPathSize);
        if (!pszFullPath)
            goto _END_OF_FUNC;

        if (pszPrefix && nPrefixLen > 0)
        {
            StringCbCopyA(pszFullPath, nFullPathSize, pszPrefix);
            StringCbCatA(pszFullPath, nFullPathSize, "\\");
        }

        StringCbCatA(pszFullPath, nFullPathSize, pPair->pszKey);

        PJSON_VALUE pFilesObj = JsonGetObject(pPair->pValue, "files");

        if (pFilesObj && pFilesObj->type == JSON_TYPE_OBJECT)
        {
            pDirEntry = (PFILE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_ENTRY));
            if (!pDirEntry)
                goto _END_OF_FUNC;

            pDirEntry->pszRelativePath = pszFullPath;
            pDirEntry->bIsDirectory    = TRUE;
            pDirEntry->pNext           = *ppEntries;
            *ppEntries                 = pDirEntry;
            pszFullPath                = nullptr;

            if (!ExtractFilesFromJson(pFilesObj, pDirEntry->pszRelativePath, ppEntries))
                goto _END_OF_FUNC;

            pDirEntry = nullptr;
        }
        else
        {
            PJSON_VALUE pOffset     = JsonGetObject(pPair->pValue, "offset");
            PJSON_VALUE pSize       = JsonGetObject(pPair->pValue, "size");
            PJSON_VALUE pExecutable = JsonGetObject(pPair->pValue, "executable");
            PJSON_VALUE pIntegrity  = JsonGetObject(pPair->pValue, "integrity");

            if (pOffset && pSize)
            {
                DWORD dwOffset = 0;
                DWORD dwSize   = 0;

                if (pOffset->type == JSON_TYPE_STRING)
                {
                    LPSTR pszOffset = JsonGetString(pOffset);
                    if (pszOffset && *pszOffset)
                        dwOffset = (DWORD)_atoi64(pszOffset);
                }
                else if (pOffset->type == JSON_TYPE_NUMBER)
                {
                    dwOffset = (DWORD)JsonGetNumber(pOffset);
                }

                if (pSize->type == JSON_TYPE_NUMBER)
                {
                    dwSize = (DWORD)JsonGetNumber(pSize);
                }
                else if (pSize->type == JSON_TYPE_STRING)
                {
                    LPSTR pszSize = JsonGetString(pSize);
                    if (pszSize && *pszSize)
                        dwSize = (DWORD)_atoi64(pszSize);
                }

                pEntry = (PFILE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_ENTRY));
                if (!pEntry)
                    goto _END_OF_FUNC;

                pEntry->pszRelativePath = pszFullPath;
                pEntry->dwOffset        = dwOffset;
                pEntry->dwSize          = dwSize;
                pEntry->bIsDirectory    = FALSE;
                pEntry->bIsExecutable   = FALSE;

                if (pExecutable)
                {
                    if (pExecutable->type == JSON_TYPE_BOOLEAN)
                        pEntry->bIsExecutable = pExecutable->bValue;
                    else if (pExecutable->type == JSON_TYPE_NUMBER)
                        pEntry->bIsExecutable = (JsonGetNumber(pExecutable) != 0);
                }

                if (pIntegrity && pIntegrity->type == JSON_TYPE_OBJECT)
                {
                    PJSON_VALUE pHashValue   = JsonGetObject(pIntegrity, "hash");
                    PJSON_VALUE pBlocksValue = JsonGetObject(pIntegrity, "blocks");

                    if (pHashValue && pHashValue->type == JSON_TYPE_STRING)
                    {
                        LPSTR  pszHashSrc = JsonGetString(pHashValue);
                        SIZE_T nHashLen   = pszHashSrc ? lstrlenA(pszHashSrc) : 0;

                        if (pszHashSrc && nHashLen > 0)
                        {
                            pEntry->pszHash = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nHashLen + 1);
                            if (pEntry->pszHash)
                                StringCbCopyA(pEntry->pszHash, nHashLen + 1, pszHashSrc);
                        }
                    }

                    if (pBlocksValue && pBlocksValue->type == JSON_TYPE_ARRAY && pBlocksValue->pArray)
                    {
                        DWORD       dwBlockCount = 0;
                        PJSON_VALUE pElem        = pBlocksValue->pArray;

                        while (pElem) { dwBlockCount++; pElem = pElem->pNext; }

                        if (dwBlockCount > 0)
                        {
                            pEntry->ppszBlocks = (LPSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBlockCount * sizeof(LPSTR));
                            if (pEntry->ppszBlocks)
                            {
                                pEntry->dwBlockCount = dwBlockCount;
                                pElem = pBlocksValue->pArray;

                                for (DWORD i = 0; i < dwBlockCount && pElem; i++)
                                {
                                    if (pElem->type == JSON_TYPE_STRING)
                                    {
                                        LPSTR  pszBlockSrc = JsonGetString(pElem);
                                        SIZE_T nBlockLen   = pszBlockSrc ? lstrlenA(pszBlockSrc) : 0;

                                        if (pszBlockSrc && nBlockLen > 0)
                                        {
                                            pEntry->ppszBlocks[i] = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nBlockLen + 1);
                                            if (pEntry->ppszBlocks[i])
                                                StringCbCopyA(pEntry->ppszBlocks[i], nBlockLen + 1, pszBlockSrc);
                                        }
                                    }
                                    pElem = pElem->pNext;
                                }
                            }
                        }
                    }
                }

                pEntry->pNext = *ppEntries;
                *ppEntries    = pEntry;
                pszFullPath   = nullptr;
                pEntry        = nullptr;
            }
            else
            {
                HeapFree(GetProcessHeap(), 0, pszFullPath);
                pszFullPath = nullptr;
            }
        }

        pPair = pPair->pNext;
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pszFullPath)
        HeapFree(GetProcessHeap(), 0, pszFullPath);
    return bResult;
}

static void FreeFileEntries(PFILE_ENTRY pEntries)
{
    while (pEntries)
    {
        PFILE_ENTRY pNext = pEntries->pNext;

        if (pEntries->pszRelativePath)
            HeapFree(GetProcessHeap(), 0, pEntries->pszRelativePath);
        if (pEntries->pszHash)
            HeapFree(GetProcessHeap(), 0, pEntries->pszHash);
        if (pEntries->ppszBlocks)
        {
            for (DWORD i = 0; i < pEntries->dwBlockCount; i++)
            {
                if (pEntries->ppszBlocks[i])
                    HeapFree(GetProcessHeap(), 0, pEntries->ppszBlocks[i]);
            }
            HeapFree(GetProcessHeap(), 0, pEntries->ppszBlocks);
        }

        HeapFree(GetProcessHeap(), 0, pEntries);
        pEntries = pNext;
    }
}

static PFILE_ENTRY BuildFileList(LPCSTR pszDirectory, PDWORD pdwTotalSize)
{
    if (!pszDirectory)
        return nullptr;

    HANDLE           hFind                  = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATAA FindData               = {};
    PFILE_ENTRY      pEntries               = nullptr;
    PFILE_ENTRY      pSubEntries            = nullptr;
    PFILE_ENTRY      pEntry                 = nullptr;
    PFILE_ENTRY      pLast                  = nullptr;
    CHAR             szSearchPath[MAX_PATH] = {};
    CHAR             szFullPath[MAX_PATH]   = {};
    DWORD            dwTotalSize            = 0;

    if (FAILED(StringCbPrintfA(szSearchPath, sizeof(szSearchPath), "%s\\*", pszDirectory)))
        return nullptr;

    hFind = FindFirstFileA(szSearchPath, &FindData);
    if (hFind == INVALID_HANDLE_VALUE)
        return nullptr;

    do
    {
        if (lstrcmpA(FindData.cFileName, ".") == 0 || lstrcmpA(FindData.cFileName, "..") == 0)
            continue;

        if (FAILED(StringCbPrintfA(szFullPath, sizeof(szFullPath), "%s\\%s", pszDirectory, FindData.cFileName)))
            continue;

        if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
        {
            pSubEntries = BuildFileList(szFullPath, &dwTotalSize);

            if (pSubEntries)
            {
                pLast = pSubEntries;
                while (pLast->pNext)
                    pLast = pLast->pNext;

                pLast->pNext = pEntries;
                pEntries     = pSubEntries;
                pSubEntries  = nullptr;
            }
        }
        else
        {
            pEntry = (PFILE_ENTRY)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(FILE_ENTRY));
            if (!pEntry)
                continue;

            SIZE_T nPathLen = lstrlenA(szFullPath);
            pEntry->pszRelativePath = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nPathLen + 1);

            if (!pEntry->pszRelativePath)
            {
                HeapFree(GetProcessHeap(), 0, pEntry);
                pEntry = nullptr;
                continue;
            }

            StringCbCopyA(pEntry->pszRelativePath, nPathLen + 1, szFullPath);
            pEntry->dwSize       = FindData.nFileSizeLow;
            pEntry->bIsDirectory = FALSE;
            pEntry->dwOffset     = dwTotalSize;
            dwTotalSize         += pEntry->dwSize;

            LPCSTR pszExt = PathFindExtensionA(FindData.cFileName);
            if (pszExt && (lstrcmpiA(pszExt, ".exe") == 0 ||
                           lstrcmpiA(pszExt, ".dll") == 0 ||
                           lstrcmpiA(pszExt, ".bat") == 0 ||
                           lstrcmpiA(pszExt, ".cmd") == 0))
            {
                pEntry->bIsExecutable = TRUE;
            }

            if (!pEntries)
            {
                pEntries = pEntry;
            }
            else
            {
                pLast = pEntries;
                while (pLast->pNext)
                    pLast = pLast->pNext;
                pLast->pNext = pEntry;
            }

            pEntry = nullptr;
        }
    }
    while (FindNextFileA(hFind, &FindData));

    if (hFind != INVALID_HANDLE_VALUE)
        FindClose(hFind);

    if (pdwTotalSize)
        *pdwTotalSize += dwTotalSize;

    return pEntries;
}

static PJSON_VALUE BuildJsonFromFileList(PFILE_ENTRY pEntries)
{
    PJSON_VALUE  pRoot    = nullptr;
    PJSON_VALUE  pFiles   = nullptr;
    PFILE_ENTRY  pEntry   = pEntries;
    CHAR         szOffset[32] = {};

    pRoot = JsonCreateObject();
    if (!pRoot)
        goto _END_OF_FUNC;

    pFiles = JsonCreateObject();
    if (!pFiles)
        goto _END_OF_FUNC;

    JsonObjectAdd(pRoot, "files", pFiles);

    while (pEntry)
    {
        if (!pEntry->bIsDirectory && pEntry->pszRelativePath)
        {
            PJSON_VALUE pCurrent   = pFiles;
            SIZE_T      nPathLen   = lstrlenA(pEntry->pszRelativePath);
            LPSTR       pszCopy    = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nPathLen + 1);

            if (!pszCopy)
            {
                pEntry = pEntry->pNext;
                continue;
            }

            StringCbCopyA(pszCopy, nPathLen + 1, pEntry->pszRelativePath);

            LPSTR pszContext = nullptr;
            LPSTR pszToken   = strtok_s(pszCopy, "\\", &pszContext);
            LPSTR pszNext    = strtok_s(nullptr, "\\", &pszContext);

            while (pszToken && pszNext)
            {
                PJSON_VALUE pDir = JsonGetObject(pCurrent, pszToken);

                if (!pDir)
                {
                    pDir = JsonCreateObject();
                    if (!pDir)
                        break;

                    PJSON_VALUE pDirFiles = JsonCreateObject();
                    if (!pDirFiles)
                    {
                        JsonFree(pDir);
                        pDir = nullptr;
                        break;
                    }

                    JsonObjectAdd(pDir, "files", pDirFiles);
                    JsonObjectAdd(pCurrent, pszToken, pDir);
                }

                pCurrent = JsonGetObject(pDir, "files");
                pszToken = pszNext;
                pszNext  = strtok_s(nullptr, "\\", &pszContext);
            }

            if (pszToken && pCurrent)
            {
                PJSON_VALUE pFileObj = JsonCreateObject();
                if (pFileObj)
                {
                    JsonObjectAdd(pFileObj, "size", JsonCreateNumber(pEntry->dwSize));

                    StringCbPrintfA(szOffset, sizeof(szOffset), "%lu", (ULONG)pEntry->dwOffset);
                    JsonObjectAdd(pFileObj, "offset", JsonCreateString(szOffset));

                    if (pEntry->bIsExecutable)
                        JsonObjectAdd(pFileObj, "executable", JsonCreateBoolean(TRUE));

                    if (pEntry->pszHash)
                    {
                        PJSON_VALUE pIntegrity = JsonCreateObject();
                        PJSON_VALUE pBlocks    = JsonCreateArray();

                        if (pIntegrity && pBlocks)
                        {
                            JsonObjectAdd(pIntegrity, "algorithm", JsonCreateString("SHA256"));
                            JsonObjectAdd(pIntegrity, "hash",      JsonCreateString(pEntry->pszHash));
                            JsonObjectAdd(pIntegrity, "blockSize", JsonCreateNumber(ASAR_BLOCK_SIZE));

                            for (DWORD b = 0; b < pEntry->dwBlockCount; b++)
                            {
                                if (pEntry->ppszBlocks[b])
                                    JsonArrayAdd(pBlocks, JsonCreateString(pEntry->ppszBlocks[b]));
                            }

                            JsonObjectAdd(pIntegrity, "blocks", pBlocks);
                            JsonObjectAdd(pFileObj, "integrity", pIntegrity);
                        }
                        else
                        {
                            if (pIntegrity) JsonFree(pIntegrity);
                            if (pBlocks)    JsonFree(pBlocks);
                        }
                    }

                    JsonObjectAdd(pCurrent, pszToken, pFileObj);
                }
            }

            HeapFree(GetProcessHeap(), 0, pszCopy);
        }

        pEntry = pEntry->pNext;
    }

    return pRoot;

_END_OF_FUNC:
    if (pRoot)
        JsonFree(pRoot);
    else if (pFiles)
        JsonFree(pFiles);
    return nullptr;
}

static LPSTR BytesToHex(LPBYTE pbData, DWORD dwBytesLength)
{
    static LPCSTR pszHexChars = "0123456789abcdef";

    LPSTR pszOutput = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (dwBytesLength * 2) + 1);
    if (!pszOutput)
        return nullptr;

    for (DWORD i = 0; i < dwBytesLength; i++)
    {
        pszOutput[i * 2]     = pszHexChars[(pbData[i] >> 4) & 0x0F];
        pszOutput[i * 2 + 1] = pszHexChars[pbData[i] & 0x0F];
    }

    return pszOutput;
}

static LPSTR ComputeSha256Hex(LPBYTE pbData, DWORD dwLength)
{
    BCRYPT_ALG_HANDLE  hAlgorithm              = nullptr;
    BCRYPT_HASH_HANDLE hHash                   = nullptr;
    BYTE               rgHash[SHA256_HASH_SIZE] = {};
    LPSTR              pszHex                  = nullptr;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_SHA256_ALGORITHM, nullptr, 0)))
        goto _END_OF_FUNC;

    if (!BCRYPT_SUCCESS(BCryptCreateHash(hAlgorithm, &hHash, nullptr, 0, nullptr, 0, 0)))
        goto _END_OF_FUNC;

    if (!BCRYPT_SUCCESS(BCryptHashData(hHash, pbData, dwLength, 0)))
        goto _END_OF_FUNC;

    if (!BCRYPT_SUCCESS(BCryptFinishHash(hHash, rgHash, SHA256_HASH_SIZE, 0)))
        goto _END_OF_FUNC;

    pszHex = BytesToHex(rgHash, SHA256_HASH_SIZE);

_END_OF_FUNC:
    if (hHash)       BCryptDestroyHash(hHash);
    if (hAlgorithm)  BCryptCloseAlgorithmProvider(hAlgorithm, 0);
    return pszHex;
}

static BOOL ComputeFileIntegrity(LPCSTR pszFilePath, PFILE_ENTRY pEntry)
{
    HANDLE hFile       = INVALID_HANDLE_VALUE;
    LPBYTE pbFileData  = nullptr;
    DWORD  dwBytesRead = 0;
    BOOL   bResult     = FALSE;

    hFile = CreateFileA(pszFilePath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    if (pEntry->dwSize == 0)
    {
        pEntry->pszHash = ComputeSha256Hex((LPBYTE)"", 0);
        if (!pEntry->pszHash)
            goto _END_OF_FUNC;

        pEntry->dwBlockCount = 1;
        pEntry->ppszBlocks   = (LPSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(LPSTR));
        if (!pEntry->ppszBlocks)
            goto _END_OF_FUNC;

        pEntry->ppszBlocks[0] = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, lstrlenA(pEntry->pszHash) + 1);
        if (!pEntry->ppszBlocks[0])
            goto _END_OF_FUNC;

        StringCbCopyA(pEntry->ppszBlocks[0], lstrlenA(pEntry->pszHash) + 1, pEntry->pszHash);
        bResult = TRUE;
        goto _END_OF_FUNC;
    }

    pbFileData = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, pEntry->dwSize);
    if (!pbFileData)
        goto _END_OF_FUNC;

    if (!ReadFile(hFile, pbFileData, pEntry->dwSize, &dwBytesRead, nullptr) || dwBytesRead != pEntry->dwSize)
        goto _END_OF_FUNC;

    pEntry->pszHash = ComputeSha256Hex(pbFileData, pEntry->dwSize);
    if (!pEntry->pszHash)
        goto _END_OF_FUNC;

    {
        DWORD dwBlockCount  = (pEntry->dwSize + ASAR_BLOCK_SIZE - 1) / ASAR_BLOCK_SIZE;
        pEntry->dwBlockCount = dwBlockCount;
        pEntry->ppszBlocks   = (LPSTR*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBlockCount * sizeof(LPSTR));

        if (!pEntry->ppszBlocks)
            goto _END_OF_FUNC;

        for (DWORD i = 0; i < dwBlockCount; i++)
        {
            DWORD dwBlockOffset = i * ASAR_BLOCK_SIZE;
            DWORD dwBlockSize   = std::min<DWORD>(ASAR_BLOCK_SIZE, pEntry->dwSize - dwBlockOffset);

            pEntry->ppszBlocks[i] = ComputeSha256Hex(pbFileData + dwBlockOffset, dwBlockSize);
            if (!pEntry->ppszBlocks[i])
                goto _END_OF_FUNC;
        }
    }

    bResult = TRUE;

_END_OF_FUNC:
    if (pbFileData)                HeapFree(GetProcessHeap(), 0, pbFileData);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}

BOOL UnpackAsarFile(LPCSTR pszAsarPath, LPCSTR pszOutputDir)
{
    if (!pszAsarPath || !pszOutputDir)
        return FALSE;

    BOOL          bResult                = FALSE;
    HANDLE        hFile                  = INVALID_HANDLE_VALUE;
    HANDLE        hOutFile               = INVALID_HANDLE_VALUE;
    LPBYTE        pbAsarData             = nullptr;
    LPSTR         pszJson                = nullptr;
    PJSON_VALUE   pJsonRoot              = nullptr;
    PJSON_VALUE   pFiles                 = nullptr;
    PFILE_ENTRY   pEntries               = nullptr;
    PFILE_ENTRY   pEntry                 = nullptr;
    LARGE_INTEGER liFileSize             = {};
    DWORD         dwBytesRead            = 0;
    DWORD         dwBytesWritten         = 0;
    DWORD         dwSizePayload          = 0;
    DWORD         dwHeaderSize           = 0;
    DWORD         dwHeaderPayload        = 0;
    DWORD         dwJsonLen              = 0;
    DWORD         dwDataOffset           = 0;
    DWORD         dwError                = 0;
    CHAR          szOutputPath[MAX_PATH] = {};
    CHAR          szParentDir[MAX_PATH]  = {};

    hFile = CreateFileA(pszAsarPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        goto _END_OF_FUNC;

    if (!GetFileSizeEx(hFile, &liFileSize))
        goto _END_OF_FUNC;

    pbAsarData = (LPBYTE)VirtualAlloc(nullptr, (SIZE_T)liFileSize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pbAsarData)
        goto _END_OF_FUNC;

    if (!ReadFile(hFile, pbAsarData, (DWORD)liFileSize.QuadPart, &dwBytesRead, nullptr) || dwBytesRead != (DWORD)liFileSize.QuadPart)
        goto _END_OF_FUNC;

    if (dwBytesRead < 8)
        goto _END_OF_FUNC;

    dwSizePayload  = *(DWORD*)(pbAsarData + 0);
    dwHeaderSize   = *(DWORD*)(pbAsarData + 4);

    if (dwSizePayload != 4)
        goto _END_OF_FUNC;

    {
        LPBYTE pbHeaderPickle = pbAsarData + 8;
        dwHeaderPayload = *(DWORD*)(pbHeaderPickle + 0);
        dwJsonLen       = *(DWORD*)(pbHeaderPickle + 4);
        LPBYTE pbJsonData = pbHeaderPickle + 8;

        pszJson = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwJsonLen + 1);
        if (!pszJson)
            goto _END_OF_FUNC;

        RtlCopyMemory(pszJson, pbJsonData, dwJsonLen);
    }

    pJsonRoot = JsonParse(pszJson);
    if (!pJsonRoot)
        goto _END_OF_FUNC;

    pFiles = JsonGetObject(pJsonRoot, "files");
    if (!pFiles)
        goto _END_OF_FUNC;

    if (!ExtractFilesFromJson(pFiles, nullptr, &pEntries))
        goto _END_OF_FUNC;

    if (!CreateDirectoryA(pszOutputDir, nullptr))
    {
        dwError = GetLastError();
        if (dwError != ERROR_ALREADY_EXISTS)
            goto _END_OF_FUNC;
    }

    dwDataOffset = 8 + dwHeaderSize;
    pEntry       = pEntries;

    while (pEntry)
    {
        if (FAILED(StringCbPrintfA(szOutputPath, sizeof(szOutputPath), "%s\\%s", pszOutputDir, pEntry->pszRelativePath)))
        {
            pEntry = pEntry->pNext;
            continue;
        }

        if (pEntry->bIsDirectory)
        {
            CreateDirectoryRecursive(szOutputPath);
        }
        else
        {
            StringCbCopyA(szParentDir, sizeof(szParentDir), szOutputPath);
            PathRemoveFileSpecA(szParentDir);
            CreateDirectoryRecursive(szParentDir);

            hOutFile = CreateFileA(szOutputPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hOutFile != INVALID_HANDLE_VALUE)
            {
                if (pEntry->dwSize > 0)
                {
                    WriteFile(hOutFile, pbAsarData + dwDataOffset + pEntry->dwOffset, pEntry->dwSize, &dwBytesWritten, nullptr);
                }

                CloseHandle(hOutFile);
                hOutFile = INVALID_HANDLE_VALUE;
            }
        }

        pEntry = pEntry->pNext;
    }

    bResult = TRUE;

_END_OF_FUNC:
    FreeFileEntries(pEntries);
    if (pJsonRoot)                     JsonFree(pJsonRoot);
    if (pszJson)                       HeapFree(GetProcessHeap(), 0, pszJson);
    if (pbAsarData)                    VirtualFree(pbAsarData, 0, MEM_RELEASE);
    if (hOutFile != INVALID_HANDLE_VALUE) CloseHandle(hOutFile);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}

BOOL PackAsarFile(LPCSTR pszInputDir, LPCSTR pszAsarPath)
{
    if (!pszInputDir || !pszAsarPath)
        return FALSE;

    BOOL        bResult              = FALSE;
    HANDLE      hFile                = INVALID_HANDLE_VALUE;
    HANDLE      hInFile              = INVALID_HANDLE_VALUE;
    LPBYTE      pbHeaderPickle       = nullptr;
    LPBYTE      pbBuffer             = nullptr;
    LPSTR       pszJson              = nullptr;
    LPSTR       pszNew               = nullptr;
    PJSON_VALUE pJsonRoot            = nullptr;
    PFILE_ENTRY pEntries             = nullptr;
    PFILE_ENTRY pEntry               = nullptr;
    DWORD       dwBytesWritten       = 0;
    DWORD       dwBytesRead          = 0;
    DWORD       dwTotalDataSize      = 0;
    DWORD       dwJsonLen            = 0;
    DWORD       dwPadding            = 0;
    DWORD       dwHeaderPayloadSize  = 0;
    DWORD       dwHeaderSize         = 0;
    DWORD       dwCurrentOffset      = 0;
    CHAR        szFullPath[MAX_PATH] = {};
    BYTE        rgSizePickle[8]      = {};

    pEntries = BuildFileList(pszInputDir, &dwTotalDataSize);
    if (!pEntries)
        goto _END_OF_FUNC;

    {
        SIZE_T nBaseLen = lstrlenA(pszInputDir) + 1;
        pEntry = pEntries;

        while (pEntry)
        {
            if (pEntry->pszRelativePath)
            {
                SIZE_T nNewPathLen = lstrlenA(pEntry->pszRelativePath + nBaseLen) + 1;
                pszNew = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nNewPathLen);

                if (pszNew)
                {
                    StringCbCopyA(pszNew, nNewPathLen, pEntry->pszRelativePath + nBaseLen);
                    HeapFree(GetProcessHeap(), 0, pEntry->pszRelativePath);
                    pEntry->pszRelativePath = pszNew;
                    pszNew = nullptr;
                }
            }

            pEntry = pEntry->pNext;
        }
    }

    pEntry = pEntries;
    while (pEntry)
    {
        if (!pEntry->bIsDirectory && pEntry->pszRelativePath)
        {
            if (SUCCEEDED(StringCbPrintfA(szFullPath, sizeof(szFullPath), "%s\\%s", pszInputDir, pEntry->pszRelativePath)))
                ComputeFileIntegrity(szFullPath, pEntry);
        }
        pEntry = pEntry->pNext;
    }

    dwCurrentOffset = 0;
    pEntry = pEntries;
    while (pEntry)
    {
        if (!pEntry->bIsDirectory)
        {
            pEntry->dwOffset = dwCurrentOffset;
            dwCurrentOffset += pEntry->dwSize;
        }
        pEntry = pEntry->pNext;
    }
    dwTotalDataSize = dwCurrentOffset;

    pJsonRoot = BuildJsonFromFileList(pEntries);
    if (!pJsonRoot)
        goto _END_OF_FUNC;

    pszJson = JsonStringify(pJsonRoot, &dwJsonLen);
    if (!pszJson)
        goto _END_OF_FUNC;

    hFile = CreateFileA(pszAsarPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        goto _END_OF_FUNC;

    dwPadding           = (4 - (dwJsonLen & 3)) & 3;
    dwHeaderPayloadSize = 4 + dwJsonLen + dwPadding;
    dwHeaderSize        = 4 + dwHeaderPayloadSize;

    *(DWORD*)(rgSizePickle + 0) = 4;
    *(DWORD*)(rgSizePickle + 4) = dwHeaderSize;

    pbHeaderPickle = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwHeaderSize);
    if (!pbHeaderPickle)
        goto _END_OF_FUNC;

    *(DWORD*)(pbHeaderPickle + 0) = dwHeaderPayloadSize;
    *(DWORD*)(pbHeaderPickle + 4) = dwJsonLen;
    RtlCopyMemory(pbHeaderPickle + 8, pszJson, dwJsonLen);

    if (!WriteFile(hFile, rgSizePickle, 8, &dwBytesWritten, nullptr))
        goto _END_OF_FUNC;

    if (!WriteFile(hFile, pbHeaderPickle, dwHeaderSize, &dwBytesWritten, nullptr))
        goto _END_OF_FUNC;

    pEntry = pEntries;
    while (pEntry)
    {
        if (!pEntry->bIsDirectory && pEntry->dwSize > 0)
        {
            if (FAILED(StringCbPrintfA(szFullPath, sizeof(szFullPath), "%s\\%s", pszInputDir, pEntry->pszRelativePath)))
            {
                pEntry = pEntry->pNext;
                continue;
            }

            hInFile = CreateFileA(szFullPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hInFile != INVALID_HANDLE_VALUE)
            {
                pbBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, pEntry->dwSize);
                if (pbBuffer)
                {
                    if (ReadFile(hInFile, pbBuffer, pEntry->dwSize, &dwBytesRead, nullptr))
                        WriteFile(hFile, pbBuffer, pEntry->dwSize, &dwBytesWritten, nullptr);

                    HeapFree(GetProcessHeap(), 0, pbBuffer);
                    pbBuffer = nullptr;
                }

                CloseHandle(hInFile);
                hInFile = INVALID_HANDLE_VALUE;
            }
        }

        pEntry = pEntry->pNext;
    }

    bResult = TRUE;

_END_OF_FUNC:
    FreeFileEntries(pEntries);
    if (pbHeaderPickle)                HeapFree(GetProcessHeap(), 0, pbHeaderPickle);
    if (pJsonRoot)                     JsonFree(pJsonRoot);
    if (pszJson)                       HeapFree(GetProcessHeap(), 0, pszJson);
    if (pbBuffer)                      HeapFree(GetProcessHeap(), 0, pbBuffer);
    if (hInFile != INVALID_HANDLE_VALUE) CloseHandle(hInFile);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}

BOOL VerifyAsarFile(LPCSTR pszAsarPath)
{
    if (!pszAsarPath)
        return FALSE;

    HANDLE        hFile                  = INVALID_HANDLE_VALUE;
    LPBYTE        pbAsarData             = nullptr;
    LPSTR         pszJson                = nullptr;
    LPSTR         pszComputedHash        = nullptr;
    LPSTR         pszBlockHash           = nullptr;
    PJSON_VALUE   pJsonRoot              = nullptr;
    PJSON_VALUE   pFiles                 = nullptr;
    PFILE_ENTRY   pEntries               = nullptr;
    PFILE_ENTRY   pEntry                 = nullptr;
    LARGE_INTEGER liFileSize             = {};
    DWORD         dwBytesRead            = 0;
    DWORD         dwSizePayload          = 0;
    DWORD         dwHeaderSize           = 0;
    DWORD         dwJsonLen              = 0;
    DWORD         dwDataOffset           = 0;
    DWORD         dwFileCount            = 0;
    DWORD         dwFilesWithIntegrity   = 0;
    DWORD         dwFilesMissingIntegrity = 0;
    DWORD         dwFilesHashOk          = 0;
    DWORD         dwFilesHashMismatch    = 0;
    DWORD         dwFilesBlocksMismatch  = 0;
    DWORD         dwOffsetErrors         = 0;
    BOOL          bResult                = FALSE;

    hFile = CreateFileA(pszAsarPath, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        goto _END_OF_FUNC;

    if (!GetFileSizeEx(hFile, &liFileSize) || liFileSize.QuadPart < 8)
        goto _END_OF_FUNC;

    pbAsarData = (LPBYTE)VirtualAlloc(nullptr, (SIZE_T)liFileSize.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pbAsarData)
        goto _END_OF_FUNC;

    if (!ReadFile(hFile, pbAsarData, (DWORD)liFileSize.QuadPart, &dwBytesRead, nullptr) || dwBytesRead != (DWORD)liFileSize.QuadPart)
        goto _END_OF_FUNC;

    dwSizePayload = *(DWORD*)(pbAsarData + 0);
    dwHeaderSize  = *(DWORD*)(pbAsarData + 4);

    if (dwSizePayload != 4)
        goto _END_OF_FUNC;

    if ((ULONGLONG)8 + dwHeaderSize > (ULONGLONG)liFileSize.QuadPart)
        goto _END_OF_FUNC;

    {
        LPBYTE pbHeaderPickle = pbAsarData + 8;
        dwJsonLen = *(DWORD*)(pbHeaderPickle + 4);
        LPBYTE pbJsonData = pbHeaderPickle + 8;

        if ((ULONGLONG)8 + dwJsonLen > (ULONGLONG)dwHeaderSize)
            goto _END_OF_FUNC;

        pszJson = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwJsonLen + 1);
        if (!pszJson)
            goto _END_OF_FUNC;

        RtlCopyMemory(pszJson, pbJsonData, dwJsonLen);
    }

    pJsonRoot = JsonParse(pszJson);
    if (!pJsonRoot)
        goto _END_OF_FUNC;

    pFiles = JsonGetObject(pJsonRoot, "files");
    if (!pFiles)
        goto _END_OF_FUNC;

    if (!ExtractFilesFromJson(pFiles, nullptr, &pEntries))
        goto _END_OF_FUNC;

    dwDataOffset = 8 + dwHeaderSize;
    pEntry       = pEntries;

    while (pEntry)
    {
        if (pEntry->bIsDirectory)
        {
            pEntry = pEntry->pNext;
            continue;
        }

        dwFileCount++;

        ULONGLONG ullStart   = (ULONGLONG)dwDataOffset + pEntry->dwOffset;
        ULONGLONG ullEnd     = ullStart + pEntry->dwSize;
        LPBYTE    pbFileData = nullptr;

        if (ullEnd > (ULONGLONG)liFileSize.QuadPart)
        {
            dwOffsetErrors++;
            pEntry = pEntry->pNext;
            continue;
        }

        pbFileData      = pbAsarData + (SIZE_T)ullStart;
        pszComputedHash = ComputeSha256Hex(pbFileData, pEntry->dwSize);

        if (!pszComputedHash)
        {
            dwOffsetErrors++;
            pEntry = pEntry->pNext;
            continue;
        }

        if (pEntry->pszHash && *pEntry->pszHash)
        {
            dwFilesWithIntegrity++;

            if (lstrcmpA(pEntry->pszHash, pszComputedHash) == 0)
            {
                dwFilesHashOk++;
            }
            else
            {
                printf("hash mismatch: %s\n", pEntry->pszRelativePath);
                dwFilesHashMismatch++;
            }
        }
        else
        {
            dwFilesMissingIntegrity++;
        }

        if (pEntry->ppszBlocks && pEntry->dwBlockCount > 0)
        {
            BOOL  bBlocksOk        = TRUE;
            DWORD dwExpectedBlocks = pEntry->dwBlockCount;
            DWORD dwComputedBlocks = (pEntry->dwSize == 0) ? 1 :
                                     (pEntry->dwSize + ASAR_BLOCK_SIZE - 1) / ASAR_BLOCK_SIZE;

            if (dwExpectedBlocks != dwComputedBlocks)
            {
                bBlocksOk = FALSE;
            }
            else
            {
                for (DWORD i = 0; i < dwExpectedBlocks; i++)
                {
                    DWORD dwBlockOffset = i * ASAR_BLOCK_SIZE;
                    DWORD dwBlockSize   = (pEntry->dwSize == 0) ? 0 :
                                          std::min<DWORD>(ASAR_BLOCK_SIZE, pEntry->dwSize - dwBlockOffset);

                    pszBlockHash = ComputeSha256Hex(pbFileData + dwBlockOffset, dwBlockSize);

                    if (!pszBlockHash || !pEntry->ppszBlocks[i] || lstrcmpA(pEntry->ppszBlocks[i], pszBlockHash) != 0)
                    {
                        printf("block mismatch: %s (block %lu)\n", pEntry->pszRelativePath, i);
                        bBlocksOk = FALSE;
                    }

                    if (pszBlockHash)
                    {
                        HeapFree(GetProcessHeap(), 0, pszBlockHash);
                        pszBlockHash = nullptr;
                    }

                    if (!bBlocksOk)
                        break;
                }
            }

            if (!bBlocksOk)
                dwFilesBlocksMismatch++;
        }

        if (pszComputedHash)
        {
            HeapFree(GetProcessHeap(), 0, pszComputedHash);
            pszComputedHash = nullptr;
        }

        pEntry = pEntry->pNext;
    }

    bResult = (dwFilesHashMismatch == 0) &&
              (dwFilesBlocksMismatch == 0) &&
              (dwOffsetErrors == 0) &&
              (dwFilesWithIntegrity > 0) &&
              (dwFilesMissingIntegrity == 0) &&
              (dwFilesWithIntegrity == dwFilesHashOk);

_END_OF_FUNC:
    if (pszBlockHash)     HeapFree(GetProcessHeap(), 0, pszBlockHash);
    if (pszComputedHash)  HeapFree(GetProcessHeap(), 0, pszComputedHash);
    FreeFileEntries(pEntries);
    if (pJsonRoot)        JsonFree(pJsonRoot);
    if (pszJson)          HeapFree(GetProcessHeap(), 0, pszJson);
    if (pbAsarData)       VirtualFree(pbAsarData, 0, MEM_RELEASE);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    return bResult;
}
