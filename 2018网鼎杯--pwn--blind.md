# 2018网鼎杯--pwn--blind

题目有三个功能 new change  release 没有提供show，是真瞎啊，瞎子退团吧，我奶不动你

```
1.new
2.change
3.release
4.exit
Choice:
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

  比较常见的是利用strcpy，strcat等覆盖了文件指针然后进一步利用。

  (参照https://www.anquanke.com/post/id/84987)

