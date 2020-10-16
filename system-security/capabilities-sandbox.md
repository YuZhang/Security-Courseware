#  能力与沙箱


### 哈尔滨工业大学 网络与信息安全 张宇 2016

---

本课程首先学习基于能力安全和沙箱的概念；然后学习一种能力+沙箱方案Capsicum。

## 基于能力的安全

### 糊涂副手问题

[环境权威（ambient authority）](https://en.wikipedia.org/wiki/Ambient_authority)：这是目前主流的访问控制形式，指权威在一个环境中被隐式行使。

访问请求只需要给出对象的名字和操作，是否允许操作依赖于执行程序的全局属性，如身份或角色。例如，C语言里`open("filename", O_RDONLY, 0)`，其中`filename`本身不具有权威信息，这个操作是否可行依赖于环境权威。

- 例如Unix中UID，GID机制
- 防火墙根据IP地址/端口号来过滤流量
- HTTP Cookie

[糊涂副手问题（confused deputy problem）](https://en.wikipedia.org/wiki/Confused_deputy_problem)：在环境权威系统中，一个“糊涂”的特权程序被其他用户/程序“欺骗”来滥用其权利，导致特权扩大。该概念在[The Confused Deputy (or why capabilities might have been invented) (1970)](http://people.csail.mit.edu/alinush/6.858-fall-2014/papers/confused-deputy.pdf)论文中提出。

- 一个计算机安全例子：一个FORTRAN编译服务将用户指定的输入文件编译为指定的输出文件，并在一个账单文件中记录此次服务。一个恶意用户指定账单文件为输出文件来篡改账单，尽管该恶意用户并没有修改账单文件的权限。
- 一个现实安全例子：超市里一个小偷将一个商品的条形码替换成更便宜商品的条形码。“糊涂的收银员“被欺骗直接扫描条码，并按更便宜商品价格收款。小偷的特权被扩大，收银员的特权被滥用。

- 问：是编译器的问题？或收银员的问题？其他问题？
	- 编译器需要检查所有可能写入文件的权限与用户关系；收银员需要检查所有商品标签与商品是否相符；这能做到吗？有可能，但代价太大，容易有其他漏洞
	- 问题本质是难以明确特权：编译器执行承担双重角色：编译器拥有者和用户；超市收银员承担双重工作：根据标签确定价格，检查标签是否和商品相符

### 基于能力的安全

[基于能力（capability）的安全](https://en.wikipedia.org/wiki/Capability-based_security) ：一个能力是一个可交换但不可伪造的权威令牌（token），实现为一个引用（reference）指向一个受保护对象及相关访问权利（right）。

**一个文件访问控制例子：**

- `/etc/passwd` 是一个对象，但未说明权利
- `etc/passwd + O_RDWR ` 是一个带有权利说明的对象，但未说明用户进程是否可以合法访问这些值
- `int fd = open("/etc/passwd", O_RDWR);` 
	- 变量`fd`是在该进程文件描述表中的一个文件描述符索引
	- 文件描述符所在的文件描述表在内核内存中，不能被用户程序直接更改
	- 文件描述符说明该进程确实可合法访问对象，是一个能力

**进程间共享能力：**

- 对于前两个不是能力的例子，若在进程间传递这些信息，会导致糊涂副手问题
- 在基于能力的系统中，能力的传递需要操作系统来保证完整性

**糊涂副手问题的解决方案：**

- 对于糊涂编译器例子：用户向编译服务传递输入/输出文件被打开的文件描述符，而不是文件名；文件描述符可以看做是用户能力的一个凭证
- 对于糊涂收银员例子：商品上的条形码若能被替换（伪造），则不能作为一种能力；一种解决方案是令条形码为包装的一部分，不可替换

注意：Capability-based security不同于[POSIX/Linux capabilities](http://man7.org/linux/man-pages/man7/capabilities.7.html)，后者是对特权的细分。

---

## 沙箱

[沙箱（sandbox）](https://en.wikipedia.org/wiki/Sandbox_(computer_security))：一种隔离运行程序的安全机制，常用于执行未测试或不可信程序，避免对操作系统或主机安全造成威胁，可被看做是虚拟化(virtualization)技术的一个特例。

- [完全虚拟化的虚拟机](https://en.wikipedia.org/wiki/Virtual_machine)：在虚拟硬件上模拟一个真实操作系统，客户机通过模拟器访问宿主机资源。宿主机与客户机操作系统可以不同。
- 容器：一种操作系统级虚拟化实现独立应用容器，例如[LXC](https://en.wikipedia.org/wiki/LXC)和[Docker](https://en.wikipedia.org/wiki/Docker_(software))利用Linux内核的资源分离机制：
	- [namespaces](https://en.wikipedia.org/wiki/Linux_namespaces)：轻量级进程虚拟化，令每个进程有不同系统视图；六个名字空间：
		- 挂载 (mnt)：创建不同的文件系统布局
		- 进程号 (pid)：隔离进程号，父名字空间可以看见子名字空间，兄弟名字空间之间隔离
		- 网络 (net)：隔离网络栈，网络接口，iptables, 路由表等
		- 进程间通信（ipc）：System V IPC， 消息队列
		- Unix时间戳（uts）：主机名，域名
		- 用户ID（user）：隔离UID/GID
		- `SHELL=/bin/sh unshare --fork --pid chroot "${chrootdir}" "$@"`
	- [cgroup (control groups)](https://en.wikipedia.org/wiki/Cgroups)：隔离进程组的资源（CPU，内存，I/O，网络）使用
		- 资源限制：例如内存大小
		- 优先级：CPU份额，I/O吞吐量
		- 记账：测量资源使用
		- 控制：冻结，检查点，重启
	- 优点：轻量级，性能代价小，更多的虚拟机，更快的启动关闭
- [jail](https://en.wikipedia.org/wiki/Operating-system-level_virtualization)：一种操作系统级虚拟化
	- 例如限制文件系统访问的chroot
	- [FreeBSD jail](https://en.wikipedia.org/wiki/FreeBSD_jail)（chroot+网络限制）
		- `jail jail-path hostname IP-addr cmd`
		- 调用增强的chroot (无法用  “../../”  逃离)
		- 只能绑定socket到指定IP地址和授权端口
		- 只能与jail内进程通信
		- root被限制，例如不能载入内核模块
	- 优点：简单，不需要修改程序
	- 缺点：粗粒度，不能阻止访问网络或令宿主操作系统崩溃
- [seccomp (Secure Computing Mode)](https://en.wikipedia.org/wiki/Seccomp)：Linux内核中一种应用沙箱机制
	- 传统seccomp模式：进程只允许执行`exit()`, `sigreturn()`, 以及对已打开的文件描述符执行`read()` and `write()`, 而禁止其他系统调用
	- [seccomp-bpf](https://www.kernel.org/doc/Documentation/prctl/seccomp_filter.txt)：程序自定义允许的系统调用（Linux内核3.5）
	- Mac OS X沙箱("Seatbelt")有类似功能
- 基于规则的执行：通过一个明确的规则集来强制限制用户或程序访问（MAC），例如Linux安全模块（Linux Security Module，LSM）框架下的[SELinux](https://en.wikipedia.org/wiki/SELinux)和[Apparmor](https://en.wikipedia.org/wiki/Apparmor)
	- [基于角色的访问控制](https://en.wikipedia.org/wiki/Role-based_access_control)：加入角色概念，可定义每个角色的权限（类似组的概念）
	- [类型增强（type enforcement）](https://en.wikipedia.org/wiki/Type_enforcement)：加入域(domain），对应主体（如进程），和类型(type），对应客体（如文件）概念，描述域和类型的访问规则
- [capability](https://en.wikipedia.org/wiki/Capability-based_security)：通过token来表示程序所具备能力

---

## Capsicum

参考资料：[Capsicum: practical capabilities for UNIX (USENIX Security 2010) [local]](supplements/Capsicum.pdf)

一种轻量级操作系统能力和沙箱框架（for FreeBSD）

- 通过增加内核组件和用户空间库来扩展UNIX API
- 可逐渐修改应用程序来采用该框架
- 需要微内核体系和纯消息传递设计

### 能力模式
- 通过新的`cap_enter`系统调用设置一个进程凭据标记
- 标记被所有后代进程继承，无法清除
- 能力模式的进程无法访问全局名字空间（例如PID，文件路径，协议地址，IPC，系统时钟等等），例如文件系统和PID名字空间，以及若干系统管理接口（`/dev`, `ioctl`, `reboot`, `kldload`）
- 受限的系统调用（`sysctl`, `shm_open`）只允许创建匿名内存对象；只能操作给定文件描述符下的对象

###  能力
- 通过文件描述符（fd）表示
- fd是不可伪造的授权token, 可被子进程继承或IPC传递
- `cap_new`系统调用在一个存在的fd和一个权力（right）掩码上创建一个能力
- 能力的权力通过内核`fget`检查，该函数负责将fd参数转换为系统调用时内核中引用
- 能力通过fd作为`openat`等系统调用参数来传递，禁止绝对路径，“..”路径，`AT_FDCWD`
- 通过`fexecve`使用setuid和setgid来禁止特权提升

### 运行时环境：
- 通过`libcapsicum`库API创建沙箱
- 通过`cap_enter`来切断对全局名字空间的访问
- 关闭未授权的文件描述符
- 通过`fexecve`来清洗地址空间
- 沙箱返回一个UNIX domain套接字用于与主机通信，或获得额外权利

### 应用于TCPDUMP例子
- `tcpdump`将一个模式编译为一个BPF过滤器，配置一个BPF设备为输入源，将捕到的包输出为文本
- 沙箱化：先以环境特权获得资源，之后进入能力模式

```c
+       if (cap_enter() < 0)
+               error("cap_enter: %s", pcap_strerror(errno));
        status = pcap_loop(pd, cnt, callback, pcap_userdata);
```

- 进一步改进，阻止从`stdin`读取，但允许输出


```c
+ + + + + +
if (lc_limitfd(STDIN_FILENO, CAP_FSTAT) < 0)
        error("lc_limitfd: unable to limit STDIN_FILENO");
if (lc_limitfd(STDOUT_FILENO, CAP_FSTAT | CAP_SEEK | CAP_WRITE) < 0)
        error("lc_limitfd: unable to limit STDOUT_FILENO");
if (lc_limitfd(STDERR_FILENO, CAP_FSTAT | CAP_SEEK | CAP_WRITE) < 0)
        error("lc_limitfd: unable to limit STDERR_FILENO");
```

- `procstat -fC`显示进程能力，`stdin`能力只有`fs`(`fstat()`)

```
 PID COMM            FD T     FLAGS CAPABILITIES PRO NAME
1268 tcpdump          0 v rw------c           fs -   /dev/pts/0
1268 tcpdump          1 v -w------c     wr,se,fs -   /dev/null
1268 tcpdump          2 v -w------c     wr,se,fs -   /dev/null
1268 tcpdump          3 v rw-------            - -   /dev/bpf
```

- `ktrace`显示`tcpdump`使用DNS需要访问文件和网络，而这些在能力模式下已经被禁止，因而出错
	- 这也指出了一个软件设计问题：有些特权是按需的，并不是在程序启动时就需要，因此，沙箱化也需要在软件设计之处就考虑到

```c
  1272 tcpdump CALL  open(0x80092477c,O_RDONLY,<unused>0x1b6)
  1272 tcpdump NAMI  "/etc/resolv.conf"
  1272 tcpdump RET   connect -1 errno 78 Function not implemented
  1272 tcpdump CALL  socket(PF_INET,SOCK_DGRAM,IPPROTO_UDP)
  1272 tcpdump RET   socket 4
  1272 tcpdump CALL  connect(0x4,0x7fffffffe080,0x10)
  1272 tcpdump RET   connect -1 errno 78 Function not implemented
```

### 应用于GZIP的例子

- `gzip`以环境用户特权运行，没有隔离机制
- 分离两部分代码：
	- 需要环境特权的部分（打开文件，建立网络连接）
		- 主循环：读取命令行参数，识别处理和发送结果的流和对象，将输入输出文件描述符交给压缩例程
	- 执行有风险活动的（处理数据，管理缓冲区）
		- 沙箱化压缩例程
			- `gz_compress` - RPC `PROXIED_GZ_COMPRESS`
			- `gz_uncompress` - RPC `PROXIED_GZ_UNCOMPRESS`
			- `unbzip2` - RPC `PROXIED_UNBZIP2`
		- 每个RPC向沙箱传递输入/输出两个能力，以及返回大小，源文件名，修改时间等
- 修改16%的`gzip`代码（409行），主要是与RPC相关
- 其他方案：
	- Principle of Least Authority Shell (PLASH)：shell以环境特权运行，管道组件沙箱化；这适合`gzip`以管道方式运行，但以非管道方式运行时需要一些环境特权
	- 沙箱化库`libz`：问题是`libz`提供基于buffer的API，通过RPC传递代价较高

## Google Chromium沙箱

参考资料：[The Chromium Projects - Sandbox](https://www.chromium.org/developers/design-documents/sandbox)

### 设计原则

- 不要重新发明车轮：利用操作系统现有安全机制
	- 虽然用更好的安全模型来扩展OS内核看上去很诱人，但千万不要！
	- 让操作系统将其安全机制应用于它控制的对象
	- 可以创建应用级对象具有定制的安全模型
- 最小特权原则：
	- 应该应用于沙箱化代码，以及控制沙箱的代码 
- 假设沙箱化代码是恶意代码：
	- 威胁模型是一旦执行路径到达了`main()`函数中前几个调用之后，沙箱中就会运行恶意代码
	- 实践中是在第一个外部输入被接受时，或在进入主循环之前
- 快捷（Be nimble）：
	- 非恶意代码不会访问不能获得的资源，因此沙箱对性能影响接近零
	- 敏感资源被访问时的例外情况有性能损失是可接受的
- 仿真不是安全（Emulation is not security）：
	- 仿真和虚拟机解决方案本身并不提供安全
	- 沙箱不应该依赖于代码仿真，代码转换，或打补丁来提供安全

### Linux沙箱技术

采用多进程模型，为浏览器中不同部分分配不同特权。用于Zygote进程（渲染器，[PPAPI](https://en.wikipedia.org/wiki/Google_Native_Client#Pepper)，[NaCl](https://en.wikipedia.org/wiki/Google_Native_Client)，等）。[[参考]](https://chromium.googlesource.com/chromium/src/+/master/docs/linux_sandboxing.md)


#### 分层法

- Layer-1 (“语义层（semantics）”)： 采用setuid（旧内核）和namespaces（新内核）沙箱阻止进程访问绝大多数资源
	- 用于保证运行不同Seccomp-BPF策略的进程完整性
	- 用于限制网络访问
- Layer-2 (“攻击面缩减层（attack surface reduction）” )：采用Seccomp-BPF限制进程访问内核的攻击面
	- 过滤系统调用接口
	- 难以保证运行不同Seccomp-BPF策略的进程间不相互干扰
	- 与Layer-1一起沙箱化GPU进程 
- 曾经采用，被已废弃的技术：Seccomp-legacy, SELinux, Apparmor

#### 在实现Chromium浏览器时比较（来自[Capsicum 2004](supplements/Capsicum.pdf)）：

```
OS        Model        Loc       Description
————————————————————————————————————————————————————————————————————————————
Windows   ACL          22,350    Windows ACLs and SIDs
Linux     chroot       605       setuid root helper sandboxes renderer
————————————————————————————————————————————————————————————————————————————
Mac OS X  Seatbelt     560       Path-based MAC sandbox
Linux     SELinux      200       Restricted sandbox type enforcement domain
————————————————————————————————————————————————————————————————————————————
Linux     seccomp      11,301    seccomp and userspace syscall wrapper
FreeBSD   Capsicum     100       Capsicum sandboxing using cap_enter

```
---

