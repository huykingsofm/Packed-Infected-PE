#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#ifndef MAX_SECTION_SIZE
#define MAX_SECTION_SIZE 0x1000
#endif

#ifndef COPY_CURRENT_CURSOR
#define COPY_CURRENT_CURSOR -1
#endif

int memIns(void *Buf, DWORD BufSize, void *InsBuf, DWORD InsBufSize, DWORD Position);
int memDel(void *Buf, DWORD BufSize, DWORD Position, DWORD Length);

int strIsSubStr(UCHAR *Str, UCHAR *SubStr);
int strIsRelativeSubStr(UCHAR *Str, UCHAR *SubStr);

int DWORD2AddressAsShellcode(DWORD d, UCHAR *Shellcode);
int char2Wchar(UCHAR *Buffer, WCHAR *WBuffer);

int copyToFile(FILE *Dst, FILE *Src, DWORD Offset, DWORD Size, DWORD MaxBufferLenght);
int copyFile(FILE *Dst, FILE *Src, DWORD MaxBufferLength);
