# pwn--checksec-保护机制学习

了解各种保护机制对我们做栈溢出的题目有很大帮助，能让我们迅速找到方向

## 一、 CANNARY(栈保护)

###  概述

​	当函数存在缓冲区溢出的攻击漏洞时，攻击者可以把shellcode覆盖到栈上的返回地址来让shellcode执行。当启用栈保护时，函数在开始执行时会先在栈中插入cookie信息，在函数返回时就会验证cookie信息是否合法，如果不合法就会停止运行。而攻击者在覆盖返回地址时往往会把cookie信息给覆盖掉。在linux中我们把cookie信息称位cannary。

gcc在4.2版本中添加了-fstack-protector和-fstack-protector-all编译参数以支持栈保护功能，4.9新增了-fstack-protector-strong编译参数让保护的范围更广。

因此在编译时可以控制是否开启栈保护以及程度，例如：

```
gcc -fno-stack-protector -o test test.c  //禁用栈保护
gcc -fstack-protector -o test test.c   //启用堆栈保护，不过只为局部变量中含有 char 数组的函数插入保护代码
gcc -fstack-protector-all -o test test.c //启用堆栈保护，为所有函数插入保护代码
```

### 解决方法

## 二、NX/DEP(堆栈不可执行)

### 概述

NX即No-eXecute(不可执行)的意思，NX（DEP）的基本原理是将数据所在内存页标识为不可执行，当程序溢出成功转入shellcode时，程序会尝试在数据页面上执行指令，此时CPU就会抛出异常，而不是去执行恶意指令。

gcc编译器默认开启了NX选项，如果需要关闭NX选项，可以给gcc编译器添加-z execstack参数。

例如：

```
gcc -z execstack -o test test.c
```

在Windows下，类似的概念为DEP（数据执行保护），在最新版的Visual Studio中默认开启了DEP编译选项

### 解决方法

## 三 、PIE(ASLR) (地址随机化)

### 概述

一般情况下NX（Windows平台上称其为DEP）和地址空间分布随机化（ASLR）会同时工作。

允许程序员在每次启动时将可执行加载到不同的内存地址,攻击者无法预测应用程序的启动位置。

内存地址随机化机制（address space layout randomization)，有以下三种情况

0 - 表示关闭进程地址空间随机化。

1 - 表示将mmap的基址，stack和vdso页面随机化。

2 - 表示在1的基础上增加栈（heap）的随机化。

可以防范基于Ret2libc方式的针对DEP的攻击。ASLR和DEP配合使用，能有效阻止攻击者在堆栈上运行恶意代码。

Built as PIE：位置独立的可执行区域（position-independent executables）。这样使得在利用缓冲溢出和移动操作系统中存在的其他内存崩溃缺陷时采用面向返回的编程（return-oriented programming）方法变得难得多。

liunx下关闭PIE的命令如下：

sudo -s echo 0 > /proc/sys/kernel/randomize_va_space

### 解决方法

## 四、RelRO

### 概述

在Linux系统安全领域数据可以写的存储区就会是攻击的目标，尤其是存储函数指针的区域。 所以在安全防护的角度来说尽量减少可写的存储区域对安全会有极大的好处.

GCC, GNU linker以及Glibc-dynamic linker一起配合实现了一种叫做relro的技术: read only relocation。大概实现就是由linker指定binary的一块经过dynamic linker处理过 relocation之后的区域为只读.

设置符号重定向表格为只读或在程序启动时就解析并绑定所有动态符号，从而减少对GOT（Global Offset Table）攻击。RELRO为” Partial RELRO”，说明我们对GOT表具有写权限。

```
gcc -o test test.c // 默认情况下，是Partial RELRO
gcc -z norelro -o test test.c // 关闭，即No RELRO
gcc -z lazy -o test test.c // 部分开启，即Partial RELRO
gcc -z now -o test test.c // 全部开启，即
```

### 解决方法

## 五、Fortify