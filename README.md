# Packed Infected PE
A tool is used to infected a shellcode to PE file, the shellcode is packed at compile time and unpacked at runtime

# INTRODUCTION
Program InfectMessageBox: infect a simple shellcode into PE Files. Its can choose best version of MessageBox (A or W) for shellcode. The program fail if there is no any available function MessageBox in PE Files.  

Program StableInfectMessageBox: infect a stabler shellcode into PE Files. Its can infect shellcode regarless of whether PE file have any function MessageBox or not.  

Program Packer: infect a packed of stable version of shellcode and its unpacker to shellcode. This help analyst is too difficult to examine what the shellcode do. The unpacker using anti-VM and anti-Debugger techniques to avoid someome who detect it in Virtual Machine or analyze it using debugger.

# USAGE
## Enviroment
```
> OS: Windows.  
> Effective files type: PE32 (cannot infect shellcode into PE32+ and others).
```
## Compiling
>Using MinGW to compile the programs (although sometime MinGW also cause some problems, almost all errors is in process which transform code to assembly).  

Program InfectMessageBox
```
> gcc infectMessageBox.c utils.c code.c PEFile.c -o infectMessageBox.exe
```

Program stableInfectMessageBox
```
> gcc stableInfectMessageBox.c utils.c code.c PEFile.c -o stableInfectMessageBox.exe
```

Program packer
```
> gcc packer.c utils.c code.c PEFile.c -o packer.exe
```

## Running
Run the program without any arguments to see help.  
Example:
```
> packer.exe
USAGE:
        packer.exe [PEFile] [NewPEFile] [MODE] [MESBOXVERSION]
OLIDGATORY ARGUMENTS:
        PEFile          Name of file which want to infect shellcode to it
        NewPEFile       Name of infected file
MODE OPTIONS:
        -mode0          Infect shellcode to a codecave (not change size of file) - By default
        -mode1          Expand last section to infect shellcode
        -mode2          Add more one section to infect shellcode
MESBOXVERSION OPTIONS:
        -MBA            Using MessageBoxA - By default
        -MBW            Using MessageBoxW
```
*<p align = "center"> Display help </p>*
```
> packer.exe ../examplePE/notepad.exe ../exampleInfectedPE/notepad-2-1.exe -mode1
Checking Base Relocation Table...
Generating shellcode...
        Calculating shellcode size and position of important instructions...
        Adjusting some instructions and put string to shellcode...
        Encrypt shellcode with xor...
        Using mode expand last section
        Code cave found
                Shell code Offset: 0x10e00      Length: 4096
                Shell code RVA   : 0x1013a00
        Infecting shellcode successfully~~

Generating unpack code...
        Calculating size and position of important instruction...
        Finding function LoadLibrary and GetProcAddress in PE File...
                RVA Of LoadLibrary: 0x10010c8
                RVA Of GetProcAddress: 0x1001110
        Using Message Box version A
        Adjusting some instruction and put string to unpack shellcode...
        Find code cave in PE File for unpack shellcode...
        Code cave found
                Unpack Offset: 0x10f40  Length: 3792
                Unpack RVA: 0x13b40
        Adjust Entry Point...
        Infecting unpack shellcode to PE File...
        Infecting unpack shellcode successfully~~
Done~~
```
*<p align = "center"> A successfully example </p>*
```
> packer.exe ../examplePE/notepad.exe ../exampleInfectedPE/notepad-2-0.exe
Checking Base Relocation Table...
Generating shellcode...
        Calculating shellcode size and position of important instructions...
        Adjusting some instructions and put string to shellcode...
        Encrypt shellcode with xor...
        Using mode find code cave
        Code cave found
                Shell code Offset: 0x7e00       Length: 519
                Shell code RVA   : 0x1009200
        Infecting shellcode successfully~~

Generating unpack code...
        Calculating size and position of important instruction...
        Finding function LoadLibrary and GetProcAddress in PE File...
                RVA Of LoadLibrary: 0x10010c8
                RVA Of GetProcAddress: 0x1001110
        Using Message Box version A
        Adjusting some instruction and put string to unpack shellcode...
        Find code cave in PE File for unpack shellcode...
        Not enough memory to infect unpack shellcode
Done~~
```
*<p align = "center"> A fail example because of not enough memory to infect shellcode. In this case, change mode0 to mode1 or mode2 </p>*

Same with the rest.

## Common errors
|Error|Cause|Fix|
|:----|:----|:--|
|Not enough memory to infect unpack shellcode|The available code cave in PE file is too small to infect the shellcode and unpacker into it.|Change mode0 to mode1 or mode2.|
|No function load|The PE file's import table do not load the nessessary dll file or the dll file do not include nessessary function (example KERNEL32.dll, LoadLibrary function and GetProcAddress function). |Change to another infector (infectMessageBox, stableInfectMessageBox, packer). If this can not infect shellcode either, there is no way to fix.|
|Other errors|The input file is invalid PE file, the path of output file do not exist, ...||
# Folder structure
|Folder name|Function|
|:---------|:------|
|source| Source code|
|exe|Three compiled programs for whose cannot compile them|
|examplePE|Some PE file to infect|
|exampleInfectedPE|Some infected PE file|
|Report|Detail report in word|
