# 移动系统安全


###哈尔滨工业大学 网络与信息安全 张宇 2016

---

本课程学习Apple iOS中安全机制。

参考资料：

- [iOS Security Guide (iOS9.3 or later, May 2016) [local]](supplyments/iOS_Security_Guide.pdf) [[online]](http://www.apple.com/business/docs/iOS_Security_Guide.pdf)
- [The iPhone Wiki](https://www.theiphonewiki.com/wiki/Main_Page)
- [Hacking from iOS8 to iOS9 (Pangu Team @ RUXCON 2015 / POC 2015)](http://blog.pangu.io/wp-content/uploads/2015/11/POC2015_RUXCON2015.pdf)


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
 | |    Secure     |  |  Secure | | <———— coprocessor for crypto operations
 | |    Enclave    |  | Element | | <———— Java Card platform for payment
 | +———————————————+  +—————————+ |   
 +————————————————————————————————+
 +————————————————————————————————+  
 |          Crypto Engine         | <———— hardware AES engine
 +————————————————————————————————+ 
 +————————————————————————————————+  
 |      Device Key,  Group Key    | <———— secret keys for device
 |      Apple Root Certificate    | <———— root public key from Apple
 +————————————————————————————————+
```

盘古团队总结的iOS主要安全功能时间线：

- 1.x：无保护
- 2.x：Code Signing
- 4.3：ASLR
- 6：KASLR（Kernel ASLR）
- 7：Touch ID
- 8：Team ID：Apple颁发证书中一部分，程序可链接同一Team ID的库
- 9：KPP（Kernel Patch Protection）

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
- **漏洞**：iOS 3和4中，没有包括nonce，可被重放攻击来恢复到旧版本

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

文件和Keychain DP类密钥在Keybag中管理。

- iOS有5个Keybag：user，device，backup，escrow，iCloud Backup
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
- Apple Developer Enterprise Program (ADEP)允许企业开发内部App，用户安装苹果颁发的企业Provisioning Profile来运行内部App
- [**开发者证书滥用漏洞**](https://www.theiphonewiki.com/wiki/Misuse_of_enterprise_and_developer_certificates)：用于运行盗版软件，或越狱程序

###运行时进程安全

- 所有第三方App被沙箱化，被随机分配一个唯一目录，只能访问自己的文件
- 基于TrustedBSD框架的强制访问控制，或通过iOS服务访问其他信息，后台运行通过系统API
- iOS的绝大部分和所有第三方App以非特权用户“mobile”来运行
- iOS系统分区是只读的
- 访问特权信息或行使其他特权都通过声明权利（entitlement）来实现
	- 权利是Key-Value对，被签名，不能更改
	- 第三方App访问用户信息，iCloud或扩展需要声明权利
	- 系统App和精灵进程执行特权操作通过申明特权，而不需要以root来运行
- 采用地址空间布局随机化（ASLR）来防御内存破坏，Xcode采用ASLR来编译第三方App
- 采用ARM Excute Never (XN)来令内存页不可执行
- 采用Apple-only dynamic code-signing权利来令内存页可写与可执行
	- Safari以此实现JavaScript JIT编译器


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
