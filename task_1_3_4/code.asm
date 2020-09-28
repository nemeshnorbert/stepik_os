swap:
    // Put your code here
    pushq (%RDI)
    pushq (%RSI)
    popq (%RDI)
    popq (%RSI)
    retq

