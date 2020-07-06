#include <winnt.h>
#include <stdio.h>
#include <windows.h>

#ifndef MAX_SECTIONS
#define MAX_SECTIONS 32
#endif

#ifndef MAX_IMPORTED_DLL
#define MAX_IMPORTED_DLL 64
#endif

#ifndef MAX_IMPORTED_FUNC
#define MAX_IMPORTED_FUNC 512
#endif

typedef struct _LOOKUP_ELEMENT{
    UCHAR Name[32];
    DWORD Ordinal;
    DWORD Address;
} LOOKUP_ELEMENT;

int readPE32Header(
    FILE * FStream,
    PIMAGE_DOS_HEADER DOSHeader, 
    PIMAGE_NT_HEADERS32 NTHeaders,
    IMAGE_SECTION_HEADER SectionHeaders[]
);
int readPESection(FILE *FStream, IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]);
int readPEImportTable(
    FILE * FStream, 
    IMAGE_SECTION_HEADER SectionHeaders[], 
    DWORD NumberOfSections,
    IMAGE_DATA_DIRECTORY DataDirectory, 
    IMAGE_IMPORT_DESCRIPTOR PImportedDLLs[],
    PINT IndexOfSections
);
DWORD rva2Offset(DWORD rva, IMAGE_SECTION_HEADER SectionHeader);
int extractLookupTable(
    FILE * FStream,
    IMAGE_SECTION_HEADER SectionHeader, 
    IMAGE_IMPORT_DESCRIPTOR ImportedDll, 
    LOOKUP_ELEMENT LookupTable[]
);

BOOL checkBaseRelocation(
    IMAGE_OPTIONAL_HEADER32 OptionalHeader, 
    IMAGE_SECTION_HEADER SectionHeaders[],
    PIMAGE_SECTION_HEADER WhereSection
);
DWORD adjustBaseRelocation(
    FILE *FStream, 
    FILE *NewFStream,
    IMAGE_SECTION_HEADER WhereSection
);

DWORD findFuncAddressByName(FILE *FStream, UCHAR *DLLName, UCHAR *FuncName);
DWORD findFuncAddressByOrdinal(FILE *FStream, UCHAR *DLLName, DWORD Ordinal);
DWORD findFuncAddressByRelativeName(FILE *FStream, UCHAR *DLLName, UCHAR *FuncName);


DWORD align(DWORD Value, DWORD Alignment);
int padding(FILE *FStream, DWORD ActualSize);
int adjustPEHeaders(PIMAGE_NT_HEADERS32 NTHeaders, IMAGE_SECTION_HEADER SectionHeaders[], BOOL AdjustEntryPoint);
DWORD expandLastSection(
    FILE *FStream,
    FILE *NewFStream,
    DWORD ExpandSize, 
    BOOL Verbosity
);
DWORD addEmptySection(
    FILE *FStream, 
    FILE *NewFStream, 
    UCHAR *SectionName, 
    DWORD SectionSize, 
    BOOL Verbosity
);
DWORD findOffsetOfCodeCave(FILE* FStream, IMAGE_SECTION_HEADER *WhereSection, DWORD *Length);

DWORD adjustEntryPoint(FILE *FStream, FILE *NewFStream, DWORD Offset);
int infectShellcode(FILE *FStream, FILE *NewFStream, UCHAR *ShellCode, DWORD Size, DWORD Offset);

void printDOSHeader(IMAGE_DOS_HEADER DOSHeader);
void printFileHeader(IMAGE_FILE_HEADER FileHeader);
void printOptionalHeader(IMAGE_OPTIONAL_HEADER32 OptionalHeader);
void printSectionHeaders(IMAGE_SECTION_HEADER SectionHeaders[], int NumberOfSections);
void printSection(IMAGE_SECTION_HEADER SectionHeader, UCHAR Section[]);
