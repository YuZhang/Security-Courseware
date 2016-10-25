# 移动系统安全

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

本课程学习Apple iOS中安全机制，以及最近披露的首个用于攻击的远程越狱漏洞“三叉戟”及Pegasus恶意软件。

参考资料：

- [iOS Security Guide (iOS9.3 or later, May 2016) [local]](supplyments/iOS_Security_Guide.pdf) [[online]](http://www.apple.com/business/docs/iOS_Security_Guide.pdf)
- [Analysis and exploitation of Pegasus kernel vulnerabilities [local]](supplyments/Pegasus.pdf) 
[[online]](http://jndok.github.io/2016/10/04/pegasus-writeup/) [[POC]](https://github.com/jndok/PegasusX)
- [iOS Hackers Handbook](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123)

##iOS安全体系结构


```
 +————————————————————————————————+
 | +————————————————————————————+ |
 | | +————————————————————————+ | |
 | | | +————————————————————+ | | |
 | | | |   Data Protection  | | | |
 | | | |       Class        | | | | <———— encrypted by per-file key 
 | | | +————————————————————+ | | |
 | | |       App Sanbox       | | | <———— permission/MAC/entitlement
 | | +————————————————————————+ | |
 | | User Partition (Encrypted) | | <———— encrypted by file system key
 | +————————————————————————————+ |
 | +————————————————————————————+ |
 | |        OS Partition        | | <———— mounted as read-only
 | +————————————————————————————+ |
 |          File system           |
 +————————————————————————————————+  
              Software 
                 |       
        Hardware and Firmware               
 +————————————————————————————————+  
 |             Kernel             | <———— trusted, enforcing security measures
 | +———————————————+  +—————————+ |
 | |    Secure     |  |  Secure | | <——   coprocessor for crypto operations
 | |    Enclave    |  | Element | |   <—— Java Card platform for payment
 | +———————————————+  +—————————+ |   
 +————————————————————————————————+
 +————————————————————————————————+  
 |          Crypto Engine         | <———— hardware AES engine
 +————————————————————————————————+ 
 +————————————————————————————————+  
 |     Device Key,  Group Key     | <———— secret keys for device
 |     Apple Root Certificate     | <———— root public key from Apple
 +————————————————————————————————+
```

安全技术：

盘古团队总结的[iOS主要安全功能时间线](- [Hacking from iOS8 to iOS9 (Pangu Team @ RUXCON 2015 / POC 2015)](http://blog.pangu.io/wp-content/uploads/2015/11/POC2015_RUXCON2015.pdf))：

- 1.x：无保护 
- 2.x：Code Signing：代码签名防止代码被篡改，并禁止非授权应用
- 4.3：ASLR：地址空间布局随机化增加攻击者预测目的地址难度
- 6：KASLR（Kernel ASLR）：随机化内核镜像/`kernel_map`的基地址
- 7：Touch ID：指纹识别，增强认证
- 8：Team ID：程序只能链接同一Team ID的库（阻止将动态库加载到任意App中）
- 9：KPP（Kernel Patch Protection）：防止内核被篡改

其他重要技术：

- 更小的受攻击面：减少系统输入，不支持Java和Flash，支持更少的pdf特性
- 精简过的iOS：减少系统内部，没有shell
- 特权分离：用户、组、文件权限，
- DEP（数据执行保护）：不允许数据被执行
- 沙箱：提供更细粒度的隔离

##系统安全

###安全启动链（Secure Boot Chain）

1. 启动 -- 执行 --> Boot ROM (只读存储，作为硬件信任根)
2. -- 包含 --> Apple Root CA公钥
2. -- 签名验证 --> Low-Level Bootloader (LLB)
	- 若Boot ROM不能载入或验证LLB，进入DFU（Device Firmware Upgrade）模式 
3. -- 签名验证 --> iBoot (the Interactive BOOT menu system)
4. -- 签名验证 --> iOS内核（XNU）
	- 若载入或验证失败，进入“Connect to iTunes”界面 (recovery mode)
 
- 基带子系统和Secure Enclave采用类似的安全启动方案
- [**Pwnage漏洞**](https://www.theiphonewiki.com/wiki/Pwnage)：iPhone，iPod touch和iPhone 3G中，Boot ROM没有检查LLB签名

###系统软件授权（System Software Anthorization）

- SSA保证系统完整性 并 阻止降级安装系统
- iOS更新安装过程中，连接到安装授权服务器，发送:
	- 一个列表包括每个安装组件（例如，LLB，iBoot，内核，OS镜像）的密码学测量值
	- 一个随机防重放值（nonce）
	- 设备的唯一ID（ECID（Exclusive Chip ID））
- 授权服务器比较测量值列表与允许安装版本，若匹配，则将ECID加入测量值并签名，回传 ["SHSH blobs"](https://en.wikipedia.org/wiki/SHSH_blob) 给设备
- 加入ECID是为了“个性化”授权，令一个设备上的旧版本iOS不能拷贝到其他设备
- **漏洞**：iOS 3和4中，没有包括nonce，可被重放攻击来降级恢复到旧版本

###KPP

KPP（Kernel Patch Protection）防止运行时内核被篡改

ARMv8-A架构定义了四个例外层级，分别为EL0到EL3，其中数字越大代表特权(privilege)越大:

- EL0: 无特权模式(unprivileged)
- EL1: 操作系统内核模式(OS kernel mode)
- EL2: 虚拟机监视器模式(Hypervisor mode)
- EL3: TrustZone monitor mode

KPP就是运行在Application Process的EL3中，目的是用来保证：只读的页不可修改、page table不可修改、执行页不可修改。

###安全飞地（Secure Enclave）

- Secure Enclave（SE）是Apple A7及后继处理的协处理器
- 加密存储，硬件随机数产生器，实现Data Protection密钥管理和完整性的全部密码学操作
- 处理Touch ID传感器数据
	- Touch ID数据交给处理器，处理器转发数据给SE
	- 处理器不能读取数据，因为采用了一个会话密钥来加密并认证数据（密码学方案[AES-CCM](https://en.wikipedia.org/wiki/CCM_mode)）
	- 会话密钥来自于Touch ID传感器和Secure Encalve基于共享密钥的协商

###Touch ID

- 用于解锁屏幕，从iTunes Store购物，第三方app认证，Keychain认证
- 比passcode更安全，更方便
- 指纹识别1个手指与其他人随机匹配的概率是1/50,000，只允许连续尝试5次
- 指纹扫描信息临时存储在SE中加密内存，有损处理后丢弃重构指纹所需信息，得到的结果图加密存储在SE中，不会发送给Apple或在iCloud或iTunes中备份
- Touch ID如何锁定设备：
	- 当Touch ID关闭，当设备锁定时，SE中Data Protection中Complete类的密钥集合C被丢弃，该类中的文件和keychain都不可访问；直到用户用passcode来解锁，重新获得C
	- 当Touch ID启动 (监测到有手指)
		- 当设备锁定时，密钥集合C并不丢弃，而是用另一个密钥K来封装，K交给SE中的Touch ID子系统
		- 当用户解锁设备时，用K来解密C
	- Touch ID解锁设备所需K将丢失，若
		- 设备重启
		- 被SE在48小时后丢弃
		- Touch ID识别失败5次

##加密和数据保护

###硬件安全特征

为提高速度并节能，iOS设备中包含一个专用AES256密码学引擎，位于闪存和主系统内存之间DMA路径上

设备UID和GID是AES 256比特密钥，在制造过程中融合（UID）或编译（GID）到应用处理器和SE，没有软硬件可以读取这些密钥

- UID（唯一ID）密钥： 每个设备唯一，未被Apple或制造商记录
	- UID令数据与设备绑定，若将一台设备内存芯片移植到另一台设备，也不能访问其中文件
- GID（组ID）密钥： 一类设备（例如所有Apple A8处理器设备）共用一个GID

- 其他密钥来自于随机数生成器
	- 熵来自于启动时计时变量，以及启动之后的中断时刻
	- 密钥在SE内生成，使用基于多环震荡器与CTR_DRB算法的硬件随机数生成器
- 密钥删除：可抹去存储器（Effaceable Storage）直接访问底层存储技术来删除少量块数据

###文件数据保护

数据保护（Data Protection，DP）通过构造和管理一个密钥层级实现，在硬件加密技术之上构建。

- 文件元数据用一个随机文件系统密钥FSK加密
	- FSK在iOS首次安装或用户冲刷系统时创建，用UID封装
	- FSK存储在可抹去存储器中，其目的不是保密数据，而是在删除所有用户内容和设定时使用
- 每次在数据分区中创建文件时，DP创建一个新的256位密钥FK（per-file key）
	- 利用硬件AES引擎以AES CBC（或A8处理器的[AES-XTS](https://en.wikipedia.org/wiki/Disk_encryption_theory#XTS)）模式来加密文件
	- 初始向量（IV）根据块偏移量计算，用FK的SHA-1哈希值来加密
- 为文件分配class，用一个class密钥CK来封装FK（RFC3394并存储在文件元数据中
	- CK用UID来封装；部分CK也需要用Passcode封装
- 打开文件时，用FSK解密元数据，用CK解密封装的FK，用FK解密文件
	- 所有封装FK处理在SE中执行，FK从来不暴露给应用处理器
	- 启动时，SE和AES引擎协商一个临时密钥EK，用EK来封装FK，再传递给应用处理器

```
+————————————+                    +———————————————+
|Hardware Key|———————————————————>|File System Key|
|   (UID)    |                    |     (FSK)     |
+————————————+                    +———————————————+
      |                                   |
      +—————————>+—————————+      +———————v———————+      +————————+
                 |Class Key|—————>| File Metadata |—————>|File    |
      +—————————>|  (CK)   |      | File Key (FK) |      |Contents|
      |          +—————————+      +———————————————+      +————————+
+————————————+
|Passcode Key|
+————————————+
```

优点：层次化密钥方案提供了灵活性，改变passcode只需重新封装CK，改变文件class只需重新封装FK。

###Passcode

- 一旦设定passcode，自动启用数据保护功能
- passcode与UID混合
- 每次尝试需要80ms，破解6个字符（数字与小写字母）passcode需要5年半
- Touch ID是一种更方便，但更强大的passcode
- 可以设定连续10次passcode错误后，删除所有数据

###数据保护类（Data Protection classes）

- 完全保护（Complete Protection）：
	- CK被由UID和passcode得到密钥来加密保护
	- 在设备锁定很短时间后，解密后的CK被丢弃
	- 直到用户输入passcode或用TouchID解锁设备，此前该类数据无法访问
- Protected Unless Open（PUO）：
	- 一些文件需要在设备锁定时创建，例如后台下载的电子邮件附件
	- 问题：在创建文件时，因为没解锁，不能获得加密FK用的CK，该怎么办？
	- 用非对称密码ECDH over Curve25519实现（[NIST SP 800-56A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar2.pdf)）：创建文件时不需要CK，打开文件时才需要CK
		- 为类生成一个静态公私钥对C-PK/SK，C-PK不需要保密，C-SK未解锁时需要保密
		- 创建文件时，为文件生成临时公私钥F-PK/SK；用F-SK + C-PK协商出一个共享密钥SK
		- SK将FK加密封装；F-PK与封装的FK一起存储；F-SK可以丢弃
		- 需打开文件时，解锁系统获得C-SK，用C-SK + F-PK重新生成相同的SK，解密FK
- Protect Until First User Anthentication（PUFUA） ：
	- 与完全保护类一样，除了当设备锁定后，并不从内存中丢弃CK
	- 用于系统软件Calendar, Contacts, Reminders, Notes, Messages, Photos
	- 用于所有未分配DP类的第三方应用数据
- 无保护（No Protection）：
   - 若文件没有分配DP类，仍然以加密形式存储
	- 只使用UID来保护CK，并将封装的CK存储在ES中
	- 主要目的是方便实现快速删除

###密钥链数据保护（Keychain Data Protection）

许多应用需要处理口令和小块的敏感数据，例如密钥和登录令牌。Keychain提供了一种安全存储方案。

- Keychain实现为文件系统中的一个SQLite数据库，只有一个
- `securityd`精灵进程确定每个进程或App能够访问的Keychain条目
- 访问组允许Keychain条目在同一开发者的App间共享
- Keychain数据采用与文件DP类似的类结构
	- iOS创建的一些条目，例如Wi-Fi口令，邮箱账户，社交网络账号令牌，采用PUFUA类
- Keychain可以采用ACL来设置访问和认证策略

###密钥包（Keybags）

在Keybag中管理文件和Keychain DP类密钥。

- 5个Keybag：user，device，backup，escrow，iCloud Backup
	- user：设备正常操作所用的类密钥，通常被passcode保护
	- device：设备相关数据所用类密钥，单用户时，与user是同一个Keybag
	- backup：当iTunes做加密备份时创建，存储在计算机上；备份数据用新生成的密钥来重新加密
	- escrow：用于iTunes同步，允许iTunes在用户不输入passcode时备份和同步，存储在计算机上
	- iCloud backup：与backup类似，其中的类密钥都是非对称的，类似PUO类
		- 为什么用非对称？因为假设iCloud上不可信的

##App安全

###App代码签名

- 强制代码签名将信任链概念从操作系统扩展到App
- 设备自带应用，例如Mail和Safari，由Apple签名
- 所有第三方App可执行代码需要用Apple颁发的证书来签名，防止使用未签名代码资源或使用自更改代码
- 所有开发者需要注册，加入开发者计划，用Apple颁发证书来签名App，提交到App Store
- [开发者证书滥用漏洞](https://www.theiphonewiki.com/wiki/Misuse_of_enterprise_and_developer_certificates)：用于运行盗版软件，或越狱程序
	- Apple Developer Enterprise Program (ADEP)允许企业开发内部App，用户安装苹果颁发的企业Provisioning Profile来运行内部App

[Sandjacking攻击](https://threatpost.com/sandjacking-attack-puts-ios-devices-at-risk-to-rogue-apps/118375/)：

###运行时进程安全

- 所有第三方App被沙箱化，被随机分配一个唯一目录，只能访问自己的文件
- 基于TrustedBSD框架的强制访问控制（类似seccomp）
	- 只能或通过iOS服务访问其他信息，后台运行通过系统API
- iOS的绝大部分和所有第三方App以非特权用户“mobile”来运行
	- 漏洞：2009年的iOS2，短信处理以“root”运行；该问题在iOS3.0.1中修复，短信处理以“_wireless”用户运行
- iOS系统分区是只读的，禁止篡改
- 访问特权信息或行使其他特权都通过声明权利（entitlement）来实现
	- 权利是Key-Value对，被签名，不能更改
	- 第三方App访问用户信息，iCloud或扩展需要声明权利
	- 系统App和精灵进程执行特权操作通过申明特权，而不需要以root来运行
- 采用地址空间布局随机化（ASLR）来防御内存破坏，Xcode采用ASLR来编译第三方App
- 采用ARM Excute Never (XN)来令内存页不可执行
- 采用Apple-only dynamic code-signing权利来令内存页可写与可执行
	- Safari以此实现JavaScript JIT编译器
- 沙箱（访问控制）不能完全阻止软件恶意行为：
	- [XcodeGhost攻击](https://en.wikipedia.org/wiki/XcodeGhost)：2015年9月，阿里巴巴发现国内下载的Xcode中被插入恶意代码，凡是用篡改后的Xcode编译的App都会将设备和用户信息上传到攻击者服务器。防御方法是检查Xcode真伪并开启[Gatekeeper](https://en.wikipedia.org/wiki/Gatekeeper_(macOS))

###扩展（Extension）

iOS允许一个App通过Extension为其他App提供功能，扩展是一个专用被签名的可执行文件。

- 系统之支持扩展的部分称作“扩展点（extension point）”，系统根据规则按需启动扩展进程
- 扩展在自己地址空间运行，扩展和调用它的App间通过IPC通信，不能访问彼此文件或内存空间
- 授权给App的隐私控制访问也会被其扩展继承，但不会扩大到调用扩展的App

定制键盘是一种特殊扩展，应用于整个系统的文本域，除了passcode输入和其他安全文本视图。

- 定制键盘在一个更受限的沙箱内运行
	- 不能访问网络
	- 不能代替一个进程来访问网络操作服务
	- 不能访问运行撤销键入数据的API
- 定制键盘开发者可以申请开放访问（Open Access），在用户同意后可在缺省沙箱内运行 

###附件

MFi（Made for iPhone/iPod/iPad）许可计划为附件制造商提供了iAP（iPod Accessories Protocol）和必要的支撑硬件组件。

- MFi附件与iOS设备通过Lightning接口或蓝牙通讯时，需提供Apple颁发的证书
- 验证过程通过定制继承电路实现，由Apple提供给制造商，对附件本身透明
- 若附件不能提供认证，则只能访问模拟音频，和串行音频播放控制的一个子集
- AirPlay/CarPlay利用授权IC来验证接收者是否被Apple批准
- AirPlay音频/CarPlay视频流利用MFi-SAP（Secure Associateion Protocol）实现加密通信
	- 采用AES-128 CTR模式加密
	- 临时密钥采用ECDH密钥交换（Curve25519），用认证IC的1024位RSA密钥来签名

---

##“三叉戟”攻击与Pegasus

参考资料：

- [The Million Dollar Dissident: NSO Group’s iPhone Zero-Days used against a UAE Human Rights Defender](https://citizenlab.org/2016/08/million-dollar-dissident-iphone-zero-day-nso-group-uae/)
- [Technical Analysis of Pegasus Spyware (lookout.com)](https://info.lookout.com/rs/051-ESQ-475/images/lookout-pegasus-technical-analysis.pdf)

[Pegasus](https://en.wikipedia.org/wiki/Pegasus_(spyware))是第一个被发现的用于定向攻击的远程越狱软件。该间谍软件通过诱骗用户点击一个网址（或利用[WAP Push](https://en.wikipedia.org/wiki/Wireless_Application_Protocol#WAP_Push)无须用户点击）发动攻击，能够读取短消息，邮件，口令，通讯录，窃听通话，录音，以及追踪位置，监测Gmail, Facebook, Skype, WhatsApp, Facetime, 微信等应用。在漏洞发现10天后，2016年8月25日Apple发布的iOS 9.3.5更新移除了该软件所利用的3个漏洞。

该软件被认为是以色列网络军火商NSO Group制作，一份授权卖25000美元。锁定NSO的线索在攻击负载中库文件里发现“_kPegasusProtocol”字段，而Pegasus是NSO集团产品。Pegasus相关信息出现在2015年[Hacking Team 数据泄露](https://en.wikipedia.org/wiki/Hacking_Team)之中。

- 持久化：每次启动使用JavaScriptCore重新运行三叉戟攻击；并禁止自动更新，检测并删除其他越狱软件
- 记录活动：基于Cydia Substrate实现对手机活动的全面记录
- 数据渗漏（Exfiltration）：攻击负载灯塔与C&C服务器间通过HTTPS伪装gmail信息来通信；窃取的数据通过PATN (Pegasus Anonymizing Transmission Network）回传给Pegasus数据服务器

###三叉戟漏洞

参考资料：[Analysis and exploitation of Pegasus kernel vulnerabilities](supplyments/Pegasus.pdf) 
[[online]](http://jndok.github.io/2016/10/04/pegasus-writeup/) [[POC]](https://github.com/jndok/PegasusX)

1. CVE-2016-4657：Safari的Webkit内核上的内存漏洞执行远程代码
- CVE-2016-4655：内核信息泄露漏洞获得内核基址，绕过KASLR
- CVE-2016-4656：内核UAF漏洞导致越狱

下面介绍攻击原理，具体代码和攻击细节与实际情况不一定相符。

####CVE-2016-4657 —— Webkit内存漏洞

点击攻击链接，打开Safari并下载恶意JavaScript，触发Safari WebKit中内存漏洞来在Safari上下文环境里执行任意代码。目前（截止20161024），该漏洞尚未完全披露。

####CVE-2016-4655 –– 内核信息泄露（Kernel Info-Leak）

[KASLR](https://www.theiphonewiki.com/wiki/Kernel_ASLR)用于抵御ROP攻击，由iBoot实现内核映像基址（base）的随机化：

`base=0x01000000+(slide_byte*0x00200000)`

在进行越狱之前，利用内核信息泄露来获取的内核栈中“函数返回地址”，进而计算KASLR中随机滑动量（slide）来确定内核基址。

漏洞发生在内核中[`OSUnserializeBinary`](https://github.com/jndok/xnu/blob/aea2bdfb13661311a23bc0659dd5104d48a10081/libkern/c%2B%2B/OSSerializeBinary.cpp#L258-L476)函数中，该函数将二进制格式数据转换为内核数据结构，输入为一串整型`unit32_t`：

- 以`0x000000d3`开头
- 后面是若干TLV（类型，大小，值），类型+大小在一个整数中
- 类型字段中`0x80000000U`表示当前集合（collection）结束
- 例如：下面包含两个集合，在最外层的集合包含一个dict，dict内的集合包含一个string（key）和一个布尔值（value）

```xml
<beginning>  <end of 1st collection>  <end of dict (2nd collection)>
         |      |                                |
   0x000000d3 0x81000000 0x09000004 0x00414141 0x8b000001
                 |          |     |      |        |     |
<dict>     <—————+          |     |      |        |     |
    <string>AAA</string>   <+  length  value      |     |
    <boolean>1</boolean>     <————————————————————+   value
</dict>
```

内核信息泄露漏洞源于没有检查`OSNumber`输入长度：

```cpp
case kOSSerializeNumber:
...
    o = OSNumber::withNumber(value, len); <-- NO CHECK ON len
    next += 2;
    break;
```

攻击者通过在内核中注册一个包含恶意长度`OSNumber`的对象，从`OSNumber`边界之外读取内核栈中信息：

1. 构造一个包含过长`OSNumber`的序列化字典
2. 用该字典设定内核中的某些的属性
3. 读取该属性中`OSNumber`会触发去序列化函数
4. 导致邻接数据泄露，以此计算内核滑动量

字典示例：

```xml
<dict>
    <symbol>AAA</symbol>
    <number size=0x200>0x4141414141414141</number>
</dict>
```

计算内核随机滑动量S的方法：

- 从内核二进制映像中读取触发信息泄露的函数返回地址X
- 在实际运行时，KASLR会将整个映像随机滑动S，返回地址X也同步滑动S
- 利用内核信息泄露，读取运行时栈中该函数返回地址Y
- 计算滑动量S=Y-X

为触发漏洞，向内核写入和读取数据采用[`IOUserClient`](https://developer.apple.com/library/content/samplecode/SimpleUserClient/Listings/User_Client_Info_txt.html)（[中文资料](http://www.tanhao.me/pieces/1547.html/)），该类负责应用程序与内核驱动程序间连接。具体触发漏洞的函数为`io_registry_entry_get_property_bytes`，其中读取过长缓冲的代码如下：

```cpp
...else if( (off = OSDynamicCast( OSNumber, obj )))
{	offsetBytes = off->unsigned64BitValue(); 
	len = off->numberOfBytes(); /* reads out malformed length, 0x200 */ 
	bytes = &offsetBytes; /* bytes* ptr points to a stack variable */... 
}...
       *dataCnt = len;		bcopy( bytes, buf, len ); /* data leak */ }...
```

从泄露的内存中读取函数返回地址后，计算滑动量。

####CVE-2016-4656 –– 内核释放后使用（Kernel Use-After-Free）

[UAF（也称为“Dangling pointer”）](https://en.wikipedia.org/wiki/Dangling_pointer)漏洞是指堆中一块内存被释放后，指向该内存的指针仍被后续程序使用，导致异常。例如利用伪造C++中虚表（vtable）指针来夺取控制流。

- 将一个已序列化的`OSString`字典key类型转换到`OSSymbol`时，一个`OSString`对象在被引用时未执行引用计数
- 虽然之后该对象表面上被释放，但仍有指向该对象的指针并调用了方法（`retain()`）
- 通过在释放后内存写入一个指向伪造的OSString`对象虚表的指针，在调用方法时夺取控制流

在一个`objsArray`队列里添加了一个引用，但未计数：

```cpp
define setAtIndex(v, idx, o)  
...
	if (ok) v##Array[idx] = o;   <-- WITHOUT REF_COUNT++
```

下面的`o->release()`释放一个`OSSString`对象，引用数减一：

```cpp
...
else
{
    sym = OSDynamicCast(OSSymbol, o);
    if (!sym && (str = OSDynamicCast(OSString, o))) {
        sym = (OSSymbol *) OSSymbol::withString(str);
        o->release(); <-- FREE OBJ; REF_COUNT--
        o = 0;
    }
    ok = (sym != 0);
}
```
此后该对象被使用，并调用一个方法`retain`（功能是引用数加1）：

```cpp
case kOSSerializeObject:
    if (len >= objsIdx) break;
    o = objsArray[len]; <-- TO A FREED OBJ
    o->retain();  <-- USE; REF_COUNT++
    isRef = true;
    break;
```
C++中，对象方法通过虚表来调用父类实现，通过伪造一个假虚表可以夺取控制流。对于`retain()`函数，`OSString`是`OSBbject`的子类，`retain()`实际是在`OSBbject`实现的。虚表指针位于对象的开头；在`OSData`对象开头放置假虚表指针，会覆盖`OSString`对象的虚表指针。

攻击者构造一个序列化的字典：

```xml
<dict>
    <string>AAA</string>
    <boolean>true</boolean>

    <symbol>BBB</symbol>
    <data>
        00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
    </data>

    <symbol>CCC</symbol>
    <reference>1</reference> <!-- referring to object 1, the string -->
</dict>
```
用信息泄露中基于`IOUserClient`的类似方法，来触发UAF漏洞：

1. `OSString`对象“AAA”被分配32字节，被去序列化后立即被`release()`
- 序列化一个32字节的`OSData`对象（内容全0）时，分配了刚刚释放的空间
	- `kalloc()`分配最近被释放的相同大小空间
	- `OSString`对象原来内容，包括虚表指针，被置0
- 序列化一个指向对象1，即`OSString`的引用，调用`retain()`

利用UAF漏洞越狱过程如下（堆中地址从低到高增长）：

```
+————————————————————————+
|                        | "_thread_exception_return"
+                        + 
|                        | "_bzero"
+                        + 
|                        | "_posix_cred_get"
+                        +
|                        | "_proc_ucred"
+                        +
|                        | "_current_proc"  
+————————————————————————+      <——————————————————+
~          ...           ~                         |
+————————————————————————+                         |
|      retain() ptr      |———> (1)stack pivot —+   |
+——————————0x20——————————+                     |   |
|                        |———> (2)main chain ——————+
+————————————————————————+                     |
|       vtable ptr       |———> pop rsp; ret    |
+——————————0x00——————————+           <—————————+

```

1. 触发UAF后并将被释放的`OSString`空间重新分配给以0填充的`OSData`
	- `OSString`的虚表指针为前8字节（64位）= 全0
	- `retain`指针在虚表内的偏移量为0x20字节
	- 调用`retain`时，`RIP`（64位指令指针）= [0x20]
- 映射NULL页
	- 禁止__PAGEZERO段，将NULL页留作布置ROP链
- 在NULL页中偏移量0x20字节处放置一个[stack pivot（栈轴）](https://blogs.mcafee.com/mcafee-labs/emerging-stack-pivoting-exploits-bypass-common-security/)： (转移到转移链)
	- stack pivoting: 将栈指针指向一个攻击者控制的缓冲
	- gadget：`xchg eax, esp; ret` (二进制`{0x94, 0xC3}`)
		- 先将`esp`设置为`eax`（0），再将栈顶（0）弹出到`RIP`
- 在NULL页中偏移量0x00字节处放置一个小的转移链（转移到提升特权的主链）
	- 0x00处gadget：`pop rsp; ret` (二进制`{0x5C, 0xC3}`)
	- 0x10处：指向主链中第一个gadget的指针
	- 使用该转移链的原因：从0x0到0x20之间空间（32字节）不够放置主链
- 执行主链来提升特权，模仿`setuid(0)`来越狱
	1. 获取内存中当前进程的凭证结构体（credentials）
		1. `"_current_proc"` 获取当前进程结构体
		2. `"_proc_ucred"` 获取其中的凭证结构体
		3. `"_posix_cred_get"` 获取其中的posix凭证结构体指针
	- 将整个凭证结构体置0，其中UID/GID都被置0（root），实现越狱！
		- `"_bzero"` 将目标内存（3个int型）置0
	- 最后从内核态中正常退出
		- `"_thread_exception_return"`

至此，完成特权提升。后面还需将越狱持久化，清理痕迹，以及插入恶意代码。

---

