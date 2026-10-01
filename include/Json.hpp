#pragma once

#include <windows.h>

enum JSON_TYPE
{
    JSON_TYPE_NULL,
    JSON_TYPE_BOOLEAN,
    JSON_TYPE_NUMBER,
    JSON_TYPE_STRING,
    JSON_TYPE_OBJECT,
    JSON_TYPE_ARRAY
};

struct JSON_VALUE;
struct JSON_PAIR;

struct JSON_PAIR
{
    LPSTR      pszKey;
    JSON_VALUE* pValue;
    JSON_PAIR*  pNext;
};

struct JSON_VALUE
{
    JSON_TYPE type;
    union
    {
        BOOL        bValue;
        LONGLONG    llValue;
        LPSTR       pszValue;
        JSON_PAIR*  pObject;
        JSON_VALUE* pArray;
    };
    JSON_VALUE* pNext;
};

struct JSON_PARSER
{
    LPCSTR pszJson;
    SIZE_T nPos;
    SIZE_T nLength;
};

using PJSON_VALUE  = JSON_VALUE*;
using PJSON_PAIR   = JSON_PAIR*;
using PJSON_PARSER = JSON_PARSER*;

PJSON_VALUE JsonParse(LPCSTR pszJson);
void        JsonFree(PJSON_VALUE pValue);
PJSON_VALUE JsonGetObject(PJSON_VALUE pObject, LPCSTR pszKey);
LPSTR       JsonGetString(PJSON_VALUE pValue);
LONGLONG    JsonGetNumber(PJSON_VALUE pValue);

PJSON_VALUE JsonCreateObject();
PJSON_VALUE JsonCreateString(LPCSTR pszValue);
PJSON_VALUE JsonCreateNumber(LONGLONG llValue);
PJSON_VALUE JsonCreateBoolean(BOOL bValue);
PJSON_VALUE JsonCreateArray();
void        JsonObjectAdd(PJSON_VALUE pObject, LPCSTR pszKey, PJSON_VALUE pValue);
void        JsonArrayAdd(PJSON_VALUE pArray, PJSON_VALUE pValue);
LPSTR       JsonStringify(PJSON_VALUE pValue, PDWORD pdwLength);
