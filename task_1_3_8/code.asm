min:
    movq %RSI, %RAX
    cmpq %RSI, %RDI
    ja fin
    movq %RDI, %RAX
fin:
    ret

