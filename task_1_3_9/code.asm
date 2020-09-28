pow:
    pushq %RBX
    movq %RSI, %RBX
    movq $1, %RAX
loop:
    cmp $0, %RBX
    je finish
    mulq %RDI
    dec %RBX
    jmp loop
finish:
    popq %RBX
    ret
