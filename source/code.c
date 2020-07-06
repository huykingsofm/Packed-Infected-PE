#include <windows.h>

void code(){
    void * Caption = "PlaceHoldCaption";
    void * Text = "PlaceHoldText";

    MessageBoxW(0, Text, Caption, 0);
    __asm__(
        "jmp 0x12345678" // PlaceHold of jmp instruction
    );
}

void endCode(){
}

void stableCode(){
    void* dll = "USER32.dll";
    HMODULE hModule = LoadLibrary(dll);

    char func[] = "MessageBoxA";
    LPVOID lpAddress = GetProcAddress(hModule, func);

    void * Caption = "PlaceHoldCaption";
    void * Text = "PlaceHoldText";
    int (*MessageBoxPtr)(HWND, LPCSTR, LPCSTR, UINT) = (int (*)(HWND, LPCSTR, LPCSTR, UINT)) lpAddress;
    MessageBoxPtr(0, Text, Caption, 0);
    __asm__(
        "jmp 0x12345678" // PlaceHold of jmp instruction
    );
}

void endStableCode(){
}

