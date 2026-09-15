extrn ExitProcess: PROC

.code
main PROC
    sub rsp, 40
    mov ecx, 0
    call ExitProcess
main ENDP
END
