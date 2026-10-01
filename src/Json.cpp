#include <windows.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdlib.h>

#include "Json.hpp"

static void        JsonSkipWhitespace(PJSON_PARSER pParser);
static PJSON_VALUE JsonParseValue(PJSON_PARSER pParser);
static PJSON_VALUE JsonParseString(PJSON_PARSER pParser);
static PJSON_VALUE JsonParseNumber(PJSON_PARSER pParser);
static PJSON_VALUE JsonParseObject(PJSON_PARSER pParser);
static PJSON_VALUE JsonParseArray(PJSON_PARSER pParser);
static SIZE_T      JsonEscapeString(LPCSTR pszSrc, LPSTR pszDest, SIZE_T nDestSize);
static SIZE_T      JsonStringifyValue(PJSON_VALUE pValue, LPSTR pszBuffer, SIZE_T nBufferSize);
static SIZE_T      JsonStringifyObject(PJSON_VALUE pObject, LPSTR pszBuffer, SIZE_T nBufferSize);

static void JsonSkipWhitespace(PJSON_PARSER pParser)
{
    while (pParser->nPos < pParser->nLength)
    {
        CHAR ch = pParser->pszJson[pParser->nPos];
        if (ch != ' ' && ch != '\t' && ch != '\n' && ch != '\r')
            break;
        pParser->nPos++;
    }
}

static PJSON_VALUE JsonParseValue(PJSON_PARSER pParser)
{
    JsonSkipWhitespace(pParser);

    if (pParser->nPos >= pParser->nLength)
        return nullptr;

    PJSON_VALUE pValue = nullptr;

    if (pParser->pszJson[pParser->nPos] == '"')
        return JsonParseString(pParser);
    else if (pParser->pszJson[pParser->nPos] == '{')
        return JsonParseObject(pParser);
    else if (pParser->pszJson[pParser->nPos] == '[')
        return JsonParseArray(pParser);
    else if ((pParser->pszJson[pParser->nPos] >= '0' && pParser->pszJson[pParser->nPos] <= '9') || pParser->pszJson[pParser->nPos] == '-')
        return JsonParseNumber(pParser);
    else if (pParser->nPos + 4 <= pParser->nLength && CompareStringA(LOCALE_INVARIANT, 0, &pParser->pszJson[pParser->nPos], 4, "null", 4) == CSTR_EQUAL)
    {
        pParser->nPos += 4;
        pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
        if (pValue) pValue->type = JSON_TYPE_NULL;
        return pValue;
    }
    else if (pParser->nPos + 4 <= pParser->nLength && CompareStringA(LOCALE_INVARIANT, 0, &pParser->pszJson[pParser->nPos], 4, "true", 4) == CSTR_EQUAL)
    {
        pParser->nPos += 4;
        pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
        if (pValue)
        {
            pValue->type   = JSON_TYPE_BOOLEAN;
            pValue->bValue = TRUE;
        }
        return pValue;
    }
    else if (pParser->nPos + 5 <= pParser->nLength && CompareStringA(LOCALE_INVARIANT, 0, &pParser->pszJson[pParser->nPos], 5, "false", 5) == CSTR_EQUAL)
    {
        pParser->nPos += 5;
        pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
        if (pValue)
        {
            pValue->type   = JSON_TYPE_BOOLEAN;
            pValue->bValue = FALSE;
        }
        return pValue;
    }

    return nullptr;
}

static PJSON_VALUE JsonParseString(PJSON_PARSER pParser)
{
    if (pParser->pszJson[pParser->nPos] != '"')
        return nullptr;

    pParser->nPos++;

    SIZE_T      nStart       = pParser->nPos;
    SIZE_T      nLength      = 0;
    SIZE_T      nSource      = 0;
    SIZE_T      nDestination = 0;
    LPSTR       pszString    = nullptr;
    PJSON_VALUE pValue       = nullptr;
    BOOL        bEscaped     = FALSE;

    while (pParser->nPos < pParser->nLength)
    {
        if (!bEscaped && pParser->pszJson[pParser->nPos] == '"')
            break;
        bEscaped = (!bEscaped && pParser->pszJson[pParser->nPos] == '\\');
        pParser->nPos++;
        nLength++;
    }

    if (pParser->pszJson[pParser->nPos] != '"')
        return nullptr;

    pszString = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nLength + 1);
    if (!pszString)
        return nullptr;

    bEscaped = FALSE;
    nSource  = nStart;

    while (nSource < nStart + nLength)
    {
        if (bEscaped)
        {
            switch (pParser->pszJson[nSource])
            {
                case '"':  pszString[nDestination++] = '"';  break;
                case '\\': pszString[nDestination++] = '\\'; break;
                case '/':  pszString[nDestination++] = '/';  break;
                case 'b':  pszString[nDestination++] = '\b'; break;
                case 'f':  pszString[nDestination++] = '\f'; break;
                case 'n':  pszString[nDestination++] = '\n'; break;
                case 'r':  pszString[nDestination++] = '\r'; break;
                case 't':  pszString[nDestination++] = '\t'; break;
                case 'u':
                {
                    if (nSource + 5 <= nStart + nLength)
                    {
                        CHAR  szHex[5]    = {};
                        DWORD dwCodepoint = 0;

                        StringCbCopyNA(szHex, sizeof(szHex), &pParser->pszJson[nSource + 1], 4);
                        dwCodepoint = strtoul(szHex, nullptr, 16);

                        if (dwCodepoint < 128)
                        {
                            pszString[nDestination++] = (CHAR)dwCodepoint;
                        }
                        else if (dwCodepoint < 2048)
                        {
                            pszString[nDestination++] = (CHAR)(192 | (dwCodepoint >> 6));
                            pszString[nDestination++] = (CHAR)(128 | (dwCodepoint & 63));
                        }
                        else
                        {
                            pszString[nDestination++] = (CHAR)(224 | (dwCodepoint >> 12));
                            pszString[nDestination++] = (CHAR)(128 | ((dwCodepoint >> 6) & 63));
                            pszString[nDestination++] = (CHAR)(128 | (dwCodepoint & 63));
                        }

                        nSource += 4;
                    }
                    break;
                }
                default:
                    pszString[nDestination++] = pParser->pszJson[nSource];
                    break;
            }
            bEscaped = FALSE;
        }
        else if (pParser->pszJson[nSource] == '\\')
        {
            bEscaped = TRUE;
        }
        else
        {
            pszString[nDestination++] = pParser->pszJson[nSource];
        }

        nSource++;
    }

    pszString[nDestination] = '\0';
    pParser->nPos++;

    pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
    {
        HeapFree(GetProcessHeap(), 0, pszString);
        return nullptr;
    }

    pValue->type     = JSON_TYPE_STRING;
    pValue->pszValue = pszString;

    return pValue;
}

static PJSON_VALUE JsonParseNumber(PJSON_PARSER pParser)
{
    SIZE_T      nStart    = pParser->nPos;
    SIZE_T      nLength   = 0;
    BOOL        bNegative = FALSE;
    CHAR        szNumber[32] = {};
    PJSON_VALUE pValue    = nullptr;

    if (pParser->pszJson[pParser->nPos] == '-')
    {
        bNegative = TRUE;
        pParser->nPos++;
    }

    while (pParser->nPos < pParser->nLength)
    {
        if (pParser->pszJson[pParser->nPos] < '0' || pParser->pszJson[pParser->nPos] > '9')
            break;
        pParser->nPos++;
    }

    nLength = pParser->nPos - nStart;

    if (nLength == 0 || (nLength == 1 && bNegative))
        return nullptr;

    if (nLength >= sizeof(szNumber))
        return nullptr;

    StringCbCopyNA(szNumber, sizeof(szNumber), &pParser->pszJson[nStart], nLength);

    pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;

    pValue->type    = JSON_TYPE_NUMBER;
    pValue->llValue = _atoi64(szNumber);

    return pValue;
}

static PJSON_VALUE JsonParseObject(PJSON_PARSER pParser)
{
    if (pParser->pszJson[pParser->nPos] != '{')
        return nullptr;

    pParser->nPos++;

    PJSON_VALUE  pObject = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pObject)
        return nullptr;

    pObject->type    = JSON_TYPE_OBJECT;
    pObject->pObject = nullptr;

    PJSON_VALUE  pKey   = nullptr;
    PJSON_VALUE  pVal   = nullptr;
    PJSON_PAIR   pPair  = nullptr;
    PJSON_PAIR*  ppNext = &pObject->pObject;

    while (pParser->nPos < pParser->nLength)
    {
        JsonSkipWhitespace(pParser);

        if (pParser->pszJson[pParser->nPos] == '}')
        {
            pParser->nPos++;
            break;
        }

        if (pObject->pObject != nullptr)
        {
            if (pParser->pszJson[pParser->nPos] != ',')
                goto _END_OF_FUNC;
            pParser->nPos++;
            JsonSkipWhitespace(pParser);
        }

        pKey = JsonParseString(pParser);
        if (!pKey || pKey->type != JSON_TYPE_STRING)
            goto _END_OF_FUNC;

        JsonSkipWhitespace(pParser);

        if (pParser->pszJson[pParser->nPos] != ':')
            goto _END_OF_FUNC;

        pParser->nPos++;
        JsonSkipWhitespace(pParser);

        pVal = JsonParseValue(pParser);
        if (!pVal)
            goto _END_OF_FUNC;

        pPair = (PJSON_PAIR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_PAIR));
        if (!pPair)
            goto _END_OF_FUNC;

        pPair->pszKey  = pKey->pszValue;
        pPair->pValue  = pVal;
        pPair->pNext   = nullptr;
        pKey->pszValue = nullptr;

        JsonFree(pKey);
        pKey  = nullptr;
        pVal  = nullptr;
        *ppNext = pPair;
        ppNext  = &pPair->pNext;
        pPair   = nullptr;
    }

    return pObject;

_END_OF_FUNC:
    if (pKey) JsonFree(pKey);
    if (pVal) JsonFree(pVal);
    if (pObject) JsonFree(pObject);
    return nullptr;
}

static PJSON_VALUE JsonParseArray(PJSON_PARSER pParser)
{
    if (pParser->pszJson[pParser->nPos] != '[')
        return nullptr;

    pParser->nPos++;

    PJSON_VALUE  pArray   = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pArray)
        return nullptr;

    pArray->type   = JSON_TYPE_ARRAY;
    pArray->pArray = nullptr;

    PJSON_VALUE  pElement = nullptr;
    PJSON_VALUE* ppNext   = &pArray->pArray;

    while (pParser->nPos < pParser->nLength)
    {
        JsonSkipWhitespace(pParser);

        if (pParser->pszJson[pParser->nPos] == ']')
        {
            pParser->nPos++;
            break;
        }

        if (pArray->pArray != nullptr)
        {
            if (pParser->pszJson[pParser->nPos] != ',')
                goto _END_OF_FUNC;
            pParser->nPos++;
            JsonSkipWhitespace(pParser);
        }

        pElement = JsonParseValue(pParser);
        if (!pElement)
            goto _END_OF_FUNC;

        *ppNext   = pElement;
        ppNext    = &pElement->pNext;
        pElement  = nullptr;
    }

    return pArray;

_END_OF_FUNC:
    if (pArray) JsonFree(pArray);
    return nullptr;
}

static SIZE_T JsonEscapeString(LPCSTR pszSource, LPSTR pszDest, SIZE_T nDestSize)
{
    if (!pszSource)
        return 0;

    SIZE_T nWritten   = 0;
    SIZE_T nEscLength = 0;
    CHAR   szEscape[7] = {};

    while (*pszSource)
    {
        LPCSTR pszEscape = nullptr;
        nEscLength = 0;

        switch (*pszSource)
        {
            case '\"': pszEscape = "\\\""; nEscLength = 2; break;
            case '\\': pszEscape = "\\\\"; nEscLength = 2; break;
            case '\b': pszEscape = "\\b";  nEscLength = 2; break;
            case '\f': pszEscape = "\\f";  nEscLength = 2; break;
            case '\n': pszEscape = "\\n";  nEscLength = 2; break;
            case '\r': pszEscape = "\\r";  nEscLength = 2; break;
            case '\t': pszEscape = "\\t";  nEscLength = 2; break;
            default:
                if ((BYTE)*pszSource < 32)
                {
                    wsprintfA(szEscape, "\\u%04X", (UINT)(BYTE)*pszSource);
                    pszEscape  = szEscape;
                    nEscLength = 6;
                }
                break;
        }

        if (pszEscape)
        {
            if (pszDest && nWritten + nEscLength <= nDestSize)
                StringCbCopyNA(pszDest + nWritten, nDestSize - nWritten, pszEscape, nEscLength);
            nWritten += nEscLength;
        }
        else
        {
            if (pszDest && nWritten < nDestSize)
                pszDest[nWritten] = *pszSource;
            nWritten++;
        }

        pszSource++;
    }

    return nWritten;
}

static SIZE_T JsonStringifyValue(PJSON_VALUE pValue, LPSTR pszBuffer, SIZE_T nBufferSize)
{
    SIZE_T nWritten = 0;
    SIZE_T nLength  = 0;

    if (!pValue)
        return 0;

    switch (pValue->type)
    {
        case JSON_TYPE_NULL:
        {
            nLength = 4;
            if (pszBuffer && nLength <= nBufferSize)
                StringCbCopyNA(pszBuffer, nBufferSize, "null", nLength);
            return nLength;
        }

        case JSON_TYPE_BOOLEAN:
        {
            LPCSTR pszBool = pValue->bValue ? "true" : "false";
            nLength = pValue->bValue ? 4 : 5;
            if (pszBuffer && nLength <= nBufferSize)
                StringCbCopyNA(pszBuffer, nBufferSize, pszBool, nLength);
            return nLength;
        }

        case JSON_TYPE_NUMBER:
        {
            CHAR szNumber[32] = {};
            nLength = (SIZE_T)wsprintfA(szNumber, "%I64d", pValue->llValue);
            if (pszBuffer && nLength <= nBufferSize)
                StringCbCopyNA(pszBuffer, nBufferSize, szNumber, nLength);
            return nLength;
        }

        case JSON_TYPE_STRING:
        {
            if (pszBuffer && nWritten < nBufferSize)
                pszBuffer[nWritten] = '"';
            nWritten++;

            nWritten += JsonEscapeString(pValue->pszValue,
                pszBuffer ? &pszBuffer[nWritten] : nullptr,
                nBufferSize > nWritten ? nBufferSize - nWritten : 0);

            if (pszBuffer && nWritten < nBufferSize)
                pszBuffer[nWritten] = '"';
            nWritten++;

            return nWritten;
        }

        case JSON_TYPE_OBJECT:
            return JsonStringifyObject(pValue, pszBuffer, nBufferSize);

        case JSON_TYPE_ARRAY:
        {
            PJSON_VALUE pElement = pValue->pArray;
            BOOL        bFirst   = TRUE;

            if (pszBuffer && nWritten < nBufferSize)
                pszBuffer[nWritten] = '[';
            nWritten++;

            while (pElement)
            {
                if (!bFirst)
                {
                    if (pszBuffer && nWritten < nBufferSize)
                        pszBuffer[nWritten] = ',';
                    nWritten++;
                }

                bFirst    = FALSE;
                nLength   = JsonStringifyValue(pElement,
                    pszBuffer ? &pszBuffer[nWritten] : nullptr,
                    nBufferSize > nWritten ? nBufferSize - nWritten : 0);
                nWritten += nLength;
                pElement  = pElement->pNext;
            }

            if (pszBuffer && nWritten < nBufferSize)
                pszBuffer[nWritten] = ']';
            nWritten++;

            return nWritten;
        }
    }

    return 0;
}

static SIZE_T JsonStringifyObject(PJSON_VALUE pObject, LPSTR pszBuffer, SIZE_T nBufferSize)
{
    SIZE_T     nWritten = 0;
    SIZE_T     nLength  = 0;
    PJSON_PAIR pPair    = pObject->pObject;
    BOOL       bFirst   = TRUE;

    if (pszBuffer && nWritten < nBufferSize)
        pszBuffer[nWritten] = '{';
    nWritten++;

    while (pPair)
    {
        if (!bFirst)
        {
            if (pszBuffer && nWritten < nBufferSize)
                pszBuffer[nWritten] = ',';
            nWritten++;
        }

        bFirst = FALSE;

        if (pszBuffer && nWritten < nBufferSize)
            pszBuffer[nWritten] = '"';
        nWritten++;

        nLength = lstrlenA(pPair->pszKey);
        if (pszBuffer && nWritten + nLength <= nBufferSize)
            StringCbCopyNA(&pszBuffer[nWritten], nBufferSize - nWritten, pPair->pszKey, nLength);
        nWritten += nLength;

        if (pszBuffer && nWritten < nBufferSize)
            pszBuffer[nWritten] = '"';
        nWritten++;

        if (pszBuffer && nWritten < nBufferSize)
            pszBuffer[nWritten] = ':';
        nWritten++;

        nLength   = JsonStringifyValue(pPair->pValue,
            pszBuffer ? &pszBuffer[nWritten] : nullptr,
            nBufferSize > nWritten ? nBufferSize - nWritten : 0);
        nWritten += nLength;
        pPair     = pPair->pNext;
    }

    if (pszBuffer && nWritten < nBufferSize)
        pszBuffer[nWritten] = '}';
    nWritten++;

    return nWritten;
}

PJSON_VALUE JsonParse(LPCSTR pszJson)
{
    if (!pszJson)
        return nullptr;

    JSON_PARSER Parser = {};
    Parser.pszJson  = pszJson;
    Parser.nLength  = lstrlenA(pszJson);
    Parser.nPos     = 0;

    return JsonParseValue(&Parser);
}

void JsonFree(PJSON_VALUE pValue)
{
    if (!pValue)
        return;

    switch (pValue->type)
    {
        case JSON_TYPE_STRING:
        {
            if (pValue->pszValue)
                HeapFree(GetProcessHeap(), 0, pValue->pszValue);
            break;
        }

        case JSON_TYPE_OBJECT:
        {
            PJSON_PAIR pPair = pValue->pObject;
            while (pPair)
            {
                PJSON_PAIR pNext = pPair->pNext;
                if (pPair->pszKey)
                    HeapFree(GetProcessHeap(), 0, pPair->pszKey);
                JsonFree(pPair->pValue);
                HeapFree(GetProcessHeap(), 0, pPair);
                pPair = pNext;
            }
            break;
        }

        case JSON_TYPE_ARRAY:
        {
            PJSON_VALUE pElement = pValue->pArray;
            while (pElement)
            {
                PJSON_VALUE pNext = pElement->pNext;
                JsonFree(pElement);
                pElement = pNext;
            }
            break;
        }
    }

    HeapFree(GetProcessHeap(), 0, pValue);
}

PJSON_VALUE JsonGetObject(PJSON_VALUE pObject, LPCSTR pszKey)
{
    if (!pObject || pObject->type != JSON_TYPE_OBJECT || !pszKey)
        return nullptr;

    PJSON_PAIR pPair = pObject->pObject;
    while (pPair)
    {
        if (pPair->pszKey && lstrcmpA(pPair->pszKey, pszKey) == 0)
            return pPair->pValue;
        pPair = pPair->pNext;
    }

    return nullptr;
}

LPSTR JsonGetString(PJSON_VALUE pValue)
{
    if (!pValue || pValue->type != JSON_TYPE_STRING)
        return nullptr;
    return pValue->pszValue;
}

LONGLONG JsonGetNumber(PJSON_VALUE pValue)
{
    if (!pValue || pValue->type != JSON_TYPE_NUMBER)
        return 0;
    return pValue->llValue;
}

PJSON_VALUE JsonCreateObject()
{
    PJSON_VALUE pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;
    pValue->type    = JSON_TYPE_OBJECT;
    pValue->pObject = nullptr;
    return pValue;
}

PJSON_VALUE JsonCreateString(LPCSTR pszString)
{
    if (!pszString)
        return nullptr;

    PJSON_VALUE pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;

    SIZE_T nLength = lstrlenA(pszString);
    pValue->pszValue = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nLength + 1);

    if (!pValue->pszValue)
    {
        HeapFree(GetProcessHeap(), 0, pValue);
        return nullptr;
    }

    StringCbCopyA(pValue->pszValue, nLength + 1, pszString);
    pValue->type = JSON_TYPE_STRING;
    return pValue;
}

PJSON_VALUE JsonCreateNumber(LONGLONG llValue)
{
    PJSON_VALUE pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;
    pValue->type    = JSON_TYPE_NUMBER;
    pValue->llValue = llValue;
    return pValue;
}

PJSON_VALUE JsonCreateBoolean(BOOL bValue)
{
    PJSON_VALUE pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;
    pValue->type   = JSON_TYPE_BOOLEAN;
    pValue->bValue = bValue ? TRUE : FALSE;
    return pValue;
}

PJSON_VALUE JsonCreateArray()
{
    PJSON_VALUE pValue = (PJSON_VALUE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_VALUE));
    if (!pValue)
        return nullptr;
    pValue->type   = JSON_TYPE_ARRAY;
    pValue->pArray = nullptr;
    return pValue;
}

void JsonArrayAdd(PJSON_VALUE pArray, PJSON_VALUE pValue)
{
    if (!pArray || pArray->type != JSON_TYPE_ARRAY || !pValue)
        return;

    if (!pArray->pArray)
    {
        pArray->pArray = pValue;
        return;
    }

    PJSON_VALUE pCurrent = pArray->pArray;
    while (pCurrent->pNext)
        pCurrent = pCurrent->pNext;
    pCurrent->pNext = pValue;
}

void JsonObjectAdd(PJSON_VALUE pObject, LPCSTR pszKey, PJSON_VALUE pValue)
{
    if (!pObject || pObject->type != JSON_TYPE_OBJECT || !pszKey || !pValue)
        return;

    PJSON_PAIR pPair = (PJSON_PAIR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(JSON_PAIR));
    if (!pPair)
        return;

    SIZE_T nKeyLength = lstrlenA(pszKey);
    pPair->pszKey = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nKeyLength + 1);

    if (!pPair->pszKey)
    {
        HeapFree(GetProcessHeap(), 0, pPair);
        return;
    }

    StringCbCopyA(pPair->pszKey, nKeyLength + 1, pszKey);
    pPair->pValue = pValue;
    pPair->pNext  = nullptr;

    if (!pObject->pObject)
    {
        pObject->pObject = pPair;
        return;
    }

    PJSON_PAIR pCurrent = pObject->pObject;
    while (pCurrent->pNext)
        pCurrent = pCurrent->pNext;
    pCurrent->pNext = pPair;
}

LPSTR JsonStringify(PJSON_VALUE pValue, PDWORD pdwLength)
{
    if (!pValue)
        return nullptr;

    SIZE_T nSize = JsonStringifyValue(pValue, nullptr, 0);

    LPSTR pszJson = (LPSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, nSize + 1);
    if (!pszJson)
        return nullptr;

    JsonStringifyValue(pValue, pszJson, nSize);

    if (pdwLength)
        *pdwLength = (DWORD)nSize;

    return pszJson;
}
