// GAS/clang port of NativeOwnedEmitterGatewayRaw.asm for non-MSVC builds.
// Keep both files in sync; MSVC builds use the .asm.
    .intel_syntax noprefix
    .text

    .globl Kh2OwnedEmitterGatewayRaw
    .globl Kh2OwnedEmitterGatewayPublished
    .globl Kh2OwnedEmitterGatewayReturned
    .globl Kh2OwnedEmitterGatewayRetired
    .globl Kh2OwnedEmitterGatewayEnd
    .globl Kh2OwnedEmitterGatewayHandler

// RCX stable PrimitiveState*, RDX validated original dispatcher, R8 controller,
// R9 immutable invocation. Frame slots at actual pre-CALL T retain ownership;
// no inherited TLS or helper between publishing T and CALL.
    .def Kh2OwnedEmitterGatewayRaw; .scl 2; .type 32; .endef
    .seh_proc Kh2OwnedEmitterGatewayRaw
Kh2OwnedEmitterGatewayRaw:
    .seh_handler Kh2OwnedEmitterGatewayHandler, @except, @unwind
    push r12
    .seh_pushreg r12
    push r13
    .seh_pushreg r13
    push r14
    .seh_pushreg r14
    push r15
    .seh_pushreg r15
    sub rsp, 0x48
    .seh_stackalloc 0x48
    .seh_endprologue
    mov r12, rcx
    mov r15, rdx
    mov r14, r8
    mov r13, r9
    mov [rsp+0x20], r12
    mov [rsp+0x28], r13
    lea rax, [rsp-0x180]
    mov [r12+8], rax
    lea rax, [rsp-0x188]
    mov [r12+16], rax
    lea rax, [rsp-8]
    mov [r12+24], rax
    lea rax, [rsp-0x58]
    mov [r12+32], rax
    lea rax, [rip+Kh2OwnedEmitterGatewayReturned]
    mov [r12+40], rax
    mov [r12+200], r13
Kh2OwnedEmitterGatewayPublished:
    mov qword ptr [r12], 1
    mov rcx, r14
    xor edx, edx
    call r15
Kh2OwnedEmitterGatewayReturned:
    mov qword ptr [r12], 0
Kh2OwnedEmitterGatewayRetired:
    mov qword ptr [r12+152], 1
    add rsp, 0x48
    pop r15
    pop r14
    pop r13
    pop r12
    ret
Kh2OwnedEmitterGatewayEnd:
    .seh_endproc

// Actual x64 language handler. Search phase observes nothing; unwind retires
// only this assembly frame's published activation. DispatcherContext.ControlPc
// bounds avoid using not-yet-initialized stack locals during partial prologue.
// Return ExceptionContinueSearch (1), never swallow/redirect the exception.
    .def Kh2OwnedEmitterGatewayHandler; .scl 2; .type 32; .endef
    .seh_proc Kh2OwnedEmitterGatewayHandler
Kh2OwnedEmitterGatewayHandler:
    .seh_endprologue
    test dword ptr [rcx+4], 6
    jz 1f
    mov r10, [r9]
    lea r11, [rip+Kh2OwnedEmitterGatewayPublished]
    cmp r10, r11
    jb 1f
    lea r11, [rip+Kh2OwnedEmitterGatewayRetired]
    cmp r10, r11
    jae 1f
    mov r10, [rdx+0x20]
    mov qword ptr [r10], 0
    mov qword ptr [r10+160], 1
    mov qword ptr [r10+144], 0
    mov qword ptr [r10+208], 5
    mov qword ptr [r10+248], 1
1:
    mov eax, 1
    ret
    .seh_endproc
