# Hashimo Hronou :clock10:

## Description: 

* Only the chosen ones shall pass!

## Objective: 

* Bypass the filters and "login" as 

## Flag: :black_flag:
* INSSEC{472406850985991192}

## Difficulty:
* Hard

## Challenge:

First of all, we start with a `file`:  

```console
./hashim0_hronou: ELF 64-bit LSB executable, x86-64, version 1 (GNU/Linux), statically linked, stripped
```

It is a stripped 64 bit binary that is statically linked.

Then we run a string to search for anything interesting.

```console
...
M(-vrQ
UPX!
UPX!
```

As we can see, the binary is compressed with `UPX` so, we need to decompress it first.

```console
./upx -d hashim0_hronou -o hashimo_hronou
```

Now that we have a non-compressed binary, we can start our disassembler.

### Disassembly :pick:

Starting from `main()`:

```cvoid main(void)
{
  undefined *puVar1;
  int iVar2;
  uint uVar3;
  long lVar4;
  char *pcVar5;
  long lVar6;
  
  getppid();
  lVar4 = ptrace(PTRACE_TRACEME,0,1,0);
  if (lVar4 < 0) {
    printf("Debugger detected!\nExiting..");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  puts("No debugger found.");
  puVar1 = passw;
  pcVar5 = getlogin();
  iVar2 = thunk_FUN_0040052e(pcVar5,puVar1);
  if (iVar2 == 0) {
    passw = getlogin();
    uVar3 = kisskiss(passw);
    lVar4 = kisshash(passw);
    lVar6 = hashkiss(passw);
    printf("Flag: UNIWA{%lu}",lVar6 * (ulong)uVar3 * lVar4);
  }
  else {
    printf("Invalid user!\nExiting..\n");
  }
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```

As we can see, there are 5 functions that are called:

* `ptrace()`, that we need to bypass when using the debugger
* `getlogin()`, which returns the name of the user
* `kisskiss(passw)`, hashing algorithm
* `kisshash(passw)`, hashing algorithm
* `hashkiss(passw)`, hashing algorithm

`kisskiss()`:

```c
uint kisskiss(char *param_1)

{
  uint uVar1;
  uint uVar2;
  char *local_20;
  uint local_14;
  uint local_10;
  
  uVar1 = thunk_FUN_0040052e(passw);
  local_14 = 0x69696969;
  local_10 = 0;
  local_20 = param_1;
  while (local_10 < uVar1) {
    if ((local_10 & 1) == 0) {
      uVar2 = (int)*local_20 * (local_14 >> 3) ^ local_14 << 7;
    }
    else {
      uVar2 = ~(((int)*local_20 ^ local_14 >> 5) + local_14 * 0x800);
    }
    local_14 = local_14 ^ uVar2;
    local_20 = local_20 + 1;
    local_10 = local_10 + 1;
  }
  return local_14;
}
```

`kisshash()`:

```c
ulong kisshash(byte *param_1)

{
  byte *local_20;
  ulong local_10;
  
  local_10 = 0x1505;
  local_20 = param_1;
  while (*local_20 != 0) {
    local_10 = (ulong)*local_20 ^ local_10 * 0x21;
    local_20 = local_20 + 1;
  }
  return local_10;
}
```

`hashkiss()`:

```c
long hashkiss(byte *param_1)

{
  byte *local_20;
  long local_10;
  
  local_10 = 0;
  local_20 = param_1;
  while( true ) {
    if (*local_20 == 0) break;
    local_10 = local_10 * 0x1003f + (long)(int)(uint)*local_20;
    local_20 = local_20 + 1;
  }
  return local_10;
}
```

The result of all of them is multiplied and the result is the flag:

```c
printf("Flag: INSSEC{%lu}",lVar6 * (ulong)uVar3 * lVar4);
```

In order to get to this function, we need to bypass the comparison:

```c
  iVar2 = thunk_FUN_0040052e(pcVar5,puVar1);
  if (iVar2 == 0)
      ...
```

which is simply a `strcmp()`.

```gdb
        00400d65 e8 76 ab        CALL       getlogin                                         char * getlogin(void)
                 04 00
        00400d6a 48 89 de        MOV        RSI=>s_~#*$w3t&69420!_004a86a4,RBX                 = "~#*$w3t&69420!"
        00400d6d 48 89 c7        MOV        RDI,RAX
        00400d70 e8 7b f7        CALL       thunk_FUN_0040052e                               undefined thunk_FUN_0040052e()
                 ff ff
```

As we can see, we need `getlogin()` to return the string `~#*$w3t&69420!` in order to continue, so this is the correct user.

Then, the `passw` which is the argument of every hashing function, gets the value: `~#*$w3t&69420!`

So, what we need to do is is:

* bypass ptrace
* change the passw in order to get the desired value and not what `getlogin()` returns.

This happens because we cannot create such user due to the invalid characters such us `~`.

### Debugging :bug:

We need to pass all the comparisons:

```gdb
$rax   : 0xffffffffffffffff
...
     0x400d22 <main+31>        add    BYTE PTR [rdi+0x0], bh
     0x400d28 <main+37>        mov    eax, 0x0
     0x400d2d <main+42>        call   0x449cb0 <ptrace>
 →   0x400d32 <main+47>        test   rax, rax
```

This is the return of `ptrace`. We need it to return 0 so, we make `$rax` = 0

```gdb
set $rax = 0
```

When `getlogin()` is called, it returns this: 

```gdb
$rax   : 0x00000000006d3ee0  →  "w3th4nds"
```

which is my user id that is currently logged in.

After that, `strcmp()` is called, with these arguments:

```gdb
$rax   : 0xfffffff9        
$rbx   : 0x00000000004a86a4  →  "~#*$w3t&69420!"
$rcx   : 0x0               
$rdx   : 0x7e              
$rsp   : 0x00007fffffffdcf0  →  0x0000000000401ae0  →  <__libc_csu_init+0> push r15
$rbp   : 0x00007fffffffdd10  →  0x0000000000401ae0  →  <__libc_csu_init+0> push r15
$rsi   : 0x00000000004a86a4  →  "~#*$w3t&69420!"
$rdi   : 0x00000000006d3ee0  →  "w3th4nds"
...
     0x400d6a <main+103>       mov    rsi, rbx
     0x400d6d <main+106>       mov    rdi, rax
     0x400d70 <main+109>       call   0x4004f0
 →   0x400d75 <main+114>       test   eax, eax
```

As we can see, `$rdi` and `$rsi` have what we got and what is expected.

The comparison failed as we can see from `$rax`. So, we just make it 0 again.

```gdb
set $rax = 0
```

Later on, when `kisskiss(passw)`is about to be called, `$rdi` has this value:

```gdb
$rax   : 0x00000000006d3ee0  →  "w3th4nds"
$rbx   : 0x00000000004a86a4  →  "~#*$w3t&69420!"
...             
$rdi   : 0x00000000006d3ee0  →  "w3th4nds"
...
     0x400d7e <main+123>       mov    QWORD PTR [rip+0x2d038b], rax        # 0x6d1110 <passw>
     0x400d85 <main+130>       mov    rax, QWORD PTR [rip+0x2d0384]        # 0x6d1110 <passw>
     0x400d8c <main+137>       mov    rdi, rax
 →   0x400d8f <main+140>       call   0x400c6e <kisskiss>

```

We need `$rdi` to have our desired value of: `~#*$w3t&69420!`.

So, we just change it:

```gdb
set {char [13]} $rdi = "~#*$w3t&69420!"
```

We need to do this for the other functions too ever time they are called.

### Exploit :scroll:

```python
#!/usr/bin/python3
from pwn import *
import os
fname = './hashim0_hronou' # change this
final = 'hashim_hronou'

def pwn():
	os.system('./upx -d ' + fname + ' -o ' + final)
	r = process(final)
	gdb.attach(r,'''
		b *0x400d32
		r
		set $rax = 0
		b *0x400d75
		c
		set $rax = 0
		b *0x400d8f
		c
		set {char [13]} $rdi = "~#*$w3t&69420!"
		b *0x400da0
		c
		set {char [13]} $rdi = "~#*$w3t&69420!"
		b *0x400db8
		c
		set {char [13]} $rdi = "~#*$w3t&69420!"
		c
		''')

if __name__ == '__main__':
	pwn()
```

### PoC:

```console
     0x400da9 <main+166>       mov    rax, QWORD PTR [rip+0x2d0360]        # 0x6d1110 <passw>
     0x400db0 <main+173>       mov    rdi, rax
     0x400db3 <main+176>       mov    eax, 0x0
●→   0x400db8 <main+181>       call   0x400c18 <hashkiss>
   ↳    0x400c18 <hashkiss+0>     push   rbp
        0x400c19 <hashkiss+1>     mov    rbp, rsp
        0x400c1c <hashkiss+4>     mov    QWORD PTR [rbp-0x18], rdi
        0x400c20 <hashkiss+8>     mov    QWORD PTR [rbp-0x8], 0x0
        0x400c28 <hashkiss+16>    jmp    0x400c4d <hashkiss+53>
        0x400c2a <hashkiss+18>    mov    eax, DWORD PTR [rbp-0xc]
─────────────────────────────────────────────────────── arguments (guessed) ────
hashkiss (
   $rdi = 0x00000000006d3ee0 → "~#*$w3t&69420!",
   $rsi = 0x0000000000000000,
   $rdx = 0x00000000006d3eee → 0x0000000000000000,
   $rcx = 0x52cabfef9f9f3119,
   $r8 = 0x0000000000000003
)
─────────────────────────────────────────────────────────────────── threads ────
[#0] Id 1, Name: "hashimo_hronou", stopped 0x400db8 in main (), reason: BREAKPOINT
───────────────────────────────────────────────────────────────────── trace ────
[#0] 0x400db8 → main()
────────────────────────────────────────────────────────────────────────────────

Breakpoint 5, 0x0000000000400db8 in main ()
Flag: INSSEC{472406850985991192}[Inferior 1 (process 68805) exited with code 01]
```

