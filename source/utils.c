#ifndef UTILS
#define UTILS
#include "utils.h"
#include <string.h>
#include <ctype.h>
#include <stdio.h>

int memIns(void *Buf, DWORD BufSize, void *InsBuf, DWORD InsBufSize, DWORD Position){
    memcpy((UCHAR *)Buf + Position + InsBufSize, (UCHAR *)Buf + Position, BufSize - Position - InsBufSize);
    memcpy((UCHAR *)Buf + Position, InsBuf, InsBufSize);
    return 0;
}

int memDel(void *Buf, DWORD BufSize, DWORD Position, DWORD Length){
    memcpy((UCHAR *)Buf + Position, (UCHAR *)Buf + Position + Length, BufSize - Position - Length);
    return 0;
}

int strIsSubStr(UCHAR *Str, UCHAR *SubStr){
    int Length = strlen(Str);
    int SubLength = strlen(SubStr);
    for (int i = 0; i < Length - SubLength + 1; i++)
        if (Str[i] == SubStr[0]){
            int IsSub = 1;
            for (int j = 0; j < SubLength; j++)
                if (Str[i + j] != SubStr[j])
                    IsSub = 0;
            if (IsSub)
                return 1;
        }
    return 0;
}

int strIsRelativeSubStr(UCHAR *Str, UCHAR *SubStr){
    int Length = strlen(Str);
    int SubLength = strlen(SubStr);
    UCHAR *LowStr = (UCHAR *) malloc(Length + 1);
    UCHAR *LowSubStr = (UCHAR *) malloc(SubLength + 1);

    for (int i = 0; i < Length + 1; i++)
        LowStr[i] = tolower(Str[i]);
    for (int i = 0; i < SubLength + 1; i++)
        LowSubStr[i] = tolower(SubStr[i]);

    int result = strIsSubStr(LowStr, LowSubStr);

    free(LowStr);
    free(LowSubStr);
    return result;
}

int DWORD2AddressAsShellcode(DWORD d, UCHAR *Shellcode){
    Shellcode[0] = *((UCHAR *)&d + 0);
    Shellcode[1] = *((UCHAR *)&d + 1);
    Shellcode[2] = *((UCHAR *)&d + 2);
    Shellcode[3] = *((UCHAR *)&d + 3);
    return 0;
}

int char2Wchar(UCHAR *Buffer, WCHAR *WBuffer){
    int Length = strlen(Buffer);
    for (int i = 0; i < Length; i++)
        WBuffer[i] = Buffer[i];
    WBuffer[Length] = 0;
    return 0;
}

int copyToFile(FILE *Dst, FILE *Src, DWORD Offset, DWORD Size, DWORD MaxBufferLenght){
    UCHAR *Buffer = (PUCHAR) malloc(MaxBufferLenght);
    if (Offset != COPY_CURRENT_CURSOR)
        fseek(Src, Offset, SEEK_SET);
    DWORD RemainSize = Size;
    while (RemainSize != 0){
        size_t ReadBytes = fread(Buffer, 1, min(RemainSize, MaxBufferLenght), Src);
        if (ReadBytes == 0)
            break;
        fwrite(Buffer, 1, ReadBytes, Dst);
        RemainSize -= ReadBytes;
    }
    free(Buffer);
    return Size - RemainSize;
}

int copyFile(FILE *Dst, FILE *Src, DWORD MaxBufferLength){
    while (1){
        long ReadBytes = copyToFile(Dst, Src, COPY_CURRENT_CURSOR, 0xffffffff, MaxBufferLength);
        if (ReadBytes == 0)
            break;
    }
    
    return 0;
}

#endif