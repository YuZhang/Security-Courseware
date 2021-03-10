# 介绍

### 哈尔滨工业大学 网络与信息安全 张宇 2016-2018

---

## 课程评价

1. 期末考试：60%
2. 完成实验1：20%
3. 阅读论文并撰写报告：20%

### 计算机与网络安全4大学术会议

- NDSS (The Network and Distributed System Security Symposium) [2016](http://www.internetsociety.org/events/ndss-symposium-2016/ndss-2016-programme) [2017](https://www.ndss-symposium.org/ndss2017/) [2018](http://www.ndss-symposium.org/ndss2018/)
- USENIX Security (Symposium) [2016](https://www.usenix.org/conference/usenixsecurity16/technical-sessions) [2017](https://www.usenix.org/conference/usenixsecurity17) [2018](https://www.usenix.org/conference/usenixsecurity18/technical-sessions)
- CCS (ACM SIGSAC Conference on Computer and Communications Security) [2016](https://www.sigsac.org/ccs/CCS2016/wp-content/uploads/2016/08/Open-TOC-CCS.html) [2017](https://www.sigsac.org/ccs/CCS2017/) [2018](https://www.sigsac.org/ccs/CCS2018/)
- S&P (IEEE Symposium on Security and Privacy) (Oakland) [2016](http://www.ieee-security.org/TC/SP2016/program-papers.html) [2017](http://www.ieee-security.org/TC/SP2017/program-papers.html) [2018](https://www.ieee-security.org/TC/SP2018/)

从上面4个会议本年度论文中选取一篇，将论文PDF文件以 "学号-姓名-题目.pdf" 格式命名，并发给我。撰写一篇文字报告，并准备课堂报告。

## 安全概述

### 计算机安全（Computer Security）[[参考](https://en.wikipedia.org/wiki/Computer_security)]

也称为网络空间安全（cybersecurity）或IT安全，保护信息系统中软件、硬件、信息及服务。

- 信息安全（InfoSec）：保护信息的机密性，完整性，可用性，不可抵赖等等
- 网络安全（Network security）：计算机网络及网络可访问资源的安全
- 网络战（Cyberwarfare）：一国入侵另一国计算机或网络
- 互联网安全（Internet security）：互联网相关安全，包括浏览器安全以及网络安全等等
- 移动安全（Mobile security）：移动计算安全，特别是智能手机

典型漏洞与攻击：后门（Backdoor），拒绝服务（DoS），直接访问（Direct-access），窃听（Eavesdropping），伪装欺骗（Spoofing），篡改（Tampering），特权提升（Privilege escalation），钓鱼（Phishing），点击劫持（Clickjacking），社交工程（Social engineering），木马（Trojan），僵尸网络（Zombie/botnet），病毒/蠕虫/恶意软件（virus/worm/malware），高级持续性威胁（Advanced Persistent Threat）

典型安全机制：认证（Authentication），授权（Authorization），访问控制（Access Control），防火墙（Firewall），反病毒（Antivirus），入侵检测/阻止系统（Intrusion detection/prevention system），移动安全网关（Mobile secure gateway），沙箱（Sandboxing），纵深防御（Defense in depth），设计出安全（Security by design）

互联网安全术语表：[RFC4949: Internet Security Glossary, Version 2](https://tools.ietf.org/html/rfc4949)


### 安全事件统计

Verizon Data Breach Investigations Report [2016](http://www.verizonenterprise.com/resources/reports/rp_dbir-2016-executive-summary_xg_en.pdf), [2018](https://www.verizonenterprise.com/resources/reports/rp_DBIR_2018_Report_execsummary_en_xg.pdf)

2018年统计：

- 数据包含53,308起安全事故，2,216起数据泄露，65个国家。
- 73%的攻击来自外部，其中一半的泄露背后涉及组织犯罪成员，12%涉及国家/政府。
- 78%的人不会点击钓鱼链接，4%的人会点击任何钓鱼链接，通常会在16分钟内点击。
- 68%的数据泄露事故在数月之后发现。
- 勒索软件首次在2013年发现，在2018年已占被识别恶意软件的39%，例如[WannaCry](https://en.wikipedia.org/wiki/WannaCry_ransomware_attack)。
- 9大安全事故分类：
	- Web App (414), Misc. Errors (347), Point of Sale (324), Everything Else (308), Privilege Misuse (276), Cyber-Espionage (171), Lost and Stolen Assets (145), Crimeware (140), Payment Card Skimmers (111), Denial of Service (0).

2016年的事故分类统计：

- 已确认的数据泄露中63%与弱口令，缺省口令和口令被盗相关
- 95%的泄露和86%的事故，可分为9中模式：
	- Miscellaneous errors - 17.7% (事故%)
		- 除损失资产之外，破坏安全的无意行为或错误
	- Insider and Privilege misuse - 16.3%
		- 内部人员滥用，以及赋予系统特权的共谋外部人员和合作人员
	- Phyical theft and loss - 15.1%
		- 笔记本，U盘，打印纸等丢失或盗窃
	- Denial of service - 15.0%
		- 使用僵尸网络来产生恶意流量
	- Crimeware - 12.4%
		- 没有进一步归类的恶意软件
	- Web app attacks - 8.3%
		- 例如内容管理系统或电子商务平台
	- Point-of-sale intrusions - 0.8%
		- 攻击者攻破运行POS应用的计算机或服务器，来获取付费信息
	- Cyber-espionage - 0.4%
		- 国家相关的间谍活动，通常获取知识产权
	- Payment card skimmers - 0.2%
		- 在ATM，加油站，POS终端上安装物理设备获取消费卡数据
	- 其他 - 13.8%

CWE (Common Weakness Enumberation, 通用弱点列表)中[2011年Top25最危险软件错误](http://cwe.mitre.org/top25/index.html)中前10：

1. CWE-89: 不正确地无害化（neutralize）SQL命令中特殊元素 ('SQL注入')
- CWE-78: 不正确地无害化操作系统命令中特殊元素 ('操作系统命令注入')
- CWE-120: 未检查输入大小的缓冲区拷贝 ('经典缓冲区溢出')
- CWE-79: 不正确地无害化（neutralize）生成网页的输入 ('跨站点脚本' XSS)
- CWE-306: 关键功能缺乏认证(authentication)
- CWE-862: 缺乏授权(authorization)
- CWE-798: 采用硬编码的凭证（credentials)
- CWE-311: 敏感数据缺乏加密
- CWE-434: 危险类型文件无限制上传
- CWE-807: 安全决策中相信不可信输入

CVE （Common Vulnerabilities & Exposures，通用漏洞披露）2018统计

- [50个产品](https://www.cvedetails.com/top-50-products.php?year=2018)中Top5：Debian Linux (472), Android (388), Firefox (303), Ubuntu (232), Sd 650 Firmware (197)
- [50个厂商](https://www.cvedetails.com/top-50-vendors.php?year=2018)中Top5：Oracle (492), Debian (472), Google (421), Microsoft (401), IBM (343)

CVE（Common Vulnerabilities & Exposures，通用漏洞披露）中2016弱点最多的:

- [50个产品](http://www.cvedetails.com/top-50-products.php?year=2016)中前五名：Andriod（385个漏洞），Debian（290），Ubuntu（254），Flash（226），Opensuse（220）
- [50个厂商](http://www.cvedetails.com/top-50-vendors.php?year=2016)中前五名：Oracle (569)，Google (546)，Adobe (418)，Microsoft（348），Novell（347）

### 漏洞买卖

1. 漏洞赏金计划：
 - Google: < $20k
 - Microsoft: < $100k
 - Mazilla: $7.5k
 - Pwn2Own竞赛：$15k
- Zero day initiative (ZDI), iDefense: $2k-$25k
- 黑市：
	- iOS: $100k - $250k
	- Chrome/IE: $80k - $200k
	- Firefox/Safari: $60k-$150k
	- Windows: $60-120k

### 僵尸网络：

[史上最大规模DDoS](http://arstechnica.com/security/2016/09/botnet-of-145k-cameras-reportedly-deliver-internets-biggest-ddos-ever/)：根据2016年9月19日报道，超过14.5万被劫持摄像头发动了1.1Tbps的DDoS攻击 (2018年2月Github.com遭受1.3Tbps的DDoS攻击，但是反射攻击，而非由僵尸网络攻击。)


[2015年Level3 Botnet Research Report](http://www.level3.com/~/media/files/white-paper/en_secur_wp_botnetresearchreport.pdf)：

- C&C流量最高国家：美国，乌克兰，俄罗斯，荷兰，德国，土耳其，法国，英国，越南，罗马尼亚
- 平均大小1700，平均存活38天
- 1000个bots，美国\$190/月，英国\$120/月

[PPI (Pay-per-install) (USENIX Security 2011)](http://www.icir.org/vern/papers/ppi-usesec11.pdf) ：

- 美国/英国：$100-180 / 千台
- 亚洲：$7-8 / 千台

### 安全概念

- **安全**：在敌手出现时实现目标，或者说在敌手出现时，系统可正常工作
- 安全思维：
	- Policy（策略）：欲达成的目标，例如CIA：机密性（Confidentiality），完整性（Integrity），可用性（Availability）
	- Threat model（威胁模型）：关于敌手能力的假设
	- Mechianism（机制）：系统中用于实现政策的组件
	- Resulting goal（结果目标）：在**威胁模型**下，攻击者无法违反**策略**
- 安全是一个**否定**目标（保证不存在攻击）
	- 难以考虑到攻击者所有可能的攻击方式
	- 真实的威胁模型是开放的
- 若无法做到**完美安全**，为什么还要做安全？
	- 了解系统的安全边界
	- 每个系统可能都有可利用弱点，理解系统能做的和不能做的
	- 管理安全风险 vs. 收益

### 威胁，漏洞与风险

- 资产（Asset）：是要被保护的，例如我的钱包
- 威胁（Threat）：是要保护来避免的，例如小偷要偷我的钱包
- 漏洞（Vulnerability）：保护中的弱点，例如我的钱包在书包里，但书包忘记拉锁
- 风险（Risk）：=  资产 + 威胁 + 漏洞 （的概率函数）。威胁利用漏洞来获得、损害或摧毁资产的概率函数，例如存在小偷从忘记拉锁的书包中偷走我的钱包的可能性
	- 没有威胁或漏洞时无法分析风险

---
## 安全问题1：违背政策

### Sarah Palin的email账号破解

2008年9月，美国共和党副总统候选人莎拉·佩林的雅虎私人电子邮箱遭黑客入侵。黑客可能是一名田纳西州民主党议员正在念大学的儿子戴维·克内尔。[[相关报道]](https://en.wikipedia.org/wiki/Sarah_Palin_email_hack)

攻击者利用雅虎密码遗忘提示功能和网络搜索引擎：佩林的邮箱密码提示问题包括她的生日，以及她和丈夫托德在何处相识。为副总统候选人的佩林已无太多隐私可言，可在谷歌上轻松找到答案。

FBI发现了攻击者在代理服务器上的踪迹。

**政策违背：真正用户需要知道用户名与口令 --> 知道密码提示问题答案**

### Mat Honan的Apple和Amazon账号破解
2012年一位网站主编Mat Honan的Google，Twitter, Apple账号都被破解。攻击者用这些账号发表种族言论，并删除了其iPhone等设备上数据。[[相关报道]](https://www.wired.com/2012/08/apple-amazon-mat-honan-hacking/all/)


- Twitter账号：采用Gmail邮箱
- Gmail密码重置：发送一个验证链接到备份邮箱。Mat的备份邮箱是Apple的me.com账号
- Apple密码重置：需要账单地址（个人住址可以查到），信用卡末4位（未知）
- Amazon密码重置：提供用户的任意一张信用卡账号（以及用户名，账单地址等）。在一个账号上添加信用卡，不需要密码（电话服务）。登录后，Amazon会显示所有信用卡末4位。

**政策违背：邮箱安全-->备份邮箱-->账单地址+信用卡末4位-->Amazon密码-->任意信用卡**

### Twitter上@N 账号劫持

2014年，Twitter上的 @N 账号（有人出价$50000）被劫持。账号所有者（受害者）Naoki Hiroshima在尝试夺回账号失败后，将用户名改为@N\_is\_stolen。Naoki通过与攻击者的邮件交流了解了其攻击过程。[[相关报道]](https://medium.com/@N/how-i-lost-my-50-000-twitter-username-24eb09e026dd#.d7lhyudko)

- @N 账号邮箱是受害者在GoDaddy上个人域名
- 个人域名被劫持，因而邮件服务器被更改，账号邮箱也就被劫持
- GoDaddy账号恢复需要提供信用卡末6位
- 攻击者打电话给PayPal，获得了信用卡末4位
- 攻击者打电话给GoDaddy，说信用卡丢了，但记得末4位；GoDaddy让攻击者来回忆前2位，可以一直猜，直到猜对（攻击者只猜了两次就蒙对了）

**政策违背：账号安全-->邮箱安全-->域名安全-->信用卡末6位-->信用卡末4位**

### 2003年Linux后门事件
2003年时，Linux采用代码维护系统BitKeeper，提交代码需经过审查。部分开发者为了方便另建立了一个CVS来维护源代码。攻击者在CVS所维护源码中插入如下代码，将无效调用`wait4()`的进程赋予root权限。

```c
if ((options == (__WCLONE|__WALL)) && (current->uid = 0))
			retval = -EINVAL;
```
不过，由于这个修改未经过审批流程，随后被发现。[[相关报道]](https://freedom-to-tinker.com/2013/10/09/the-linux-backdoor-attempt-of-2003/)

**政策违背：BitKeeper --> CVS**

---

## 安全问题2：违背威胁模型/假设

### 未考虑人的因素

- 通过邮件/电话的电信诈骗
- 攻击者通过致电客服来重置密码
- 胶皮管密码分析

2016年3月，希拉里竞选主席[波德斯塔（Podesta）电子邮件泄露](https://en.wikipedia.org/wiki/Podesta_emails)。攻击者俄罗斯黑客组织Fancy Bear（奇幻熊）采用鱼叉式网络钓鱼攻击，向波德斯塔发送一封伪造的Gmail警告邮件，其中包含一个链接指向一个伪造的登录页面。同年10月，[维基解密公开了泄露的邮件](https://wikileaks.org/podesta-emails/)。


### 1983年图灵演说

[Reflections on Trusting Trust by Ken Thompson](http://www.ece.cmu.edu/~ganger/712.fall02/papers/p761-thompson.pdf)
> To what extent should one trust a statement that a program is free of Trojan horses? Perhaps it is more important to trust the people who wrote the software.

- 在发明C语言过程中，有一个“鸡生蛋，蛋生鸡”问题，即如何用C语言来实现C语言的编译器。
- 原理上，需要一个程序，能够复制自己，并在每次复制时‘学习’一点新特性，逐渐演化成一个“产生编译器的程序”。
- Ken在该程序中植入了一个木马，能够用特定密码来‘通过’`Login`函数检查。
- 即使有人发现了木马并更改了代码，但若用有木马的编译器编译，则新编译器中仍有木马！

### 随时间变化的计算假设

- 自80年代中期，MIT Kerberos系统使用56比特DES密钥
- 但目前2^56已经不够大了，1天之内就能破解

### 所有SSL证书CA都可信？

- 连接SSL支持的站点（HTTPS）需要验证CA颁发的证书（身份和公钥的数字签名）
- 多数浏览器相信上百个CA，任何一个CA被攻破，可伪造任何站点证书
- 2011年，两个CA，[DigiNotar](http://en.wikipedia.org/wiki/DigiNotar)和[Comodo](http://en.wikipedia.org/wiki/Comodo_Group)，发布了包括google, yahoo等的假证书
- 2012年，一个CA，[Trustwave](http://www.h-online.com/security/news/item/Trustwave-issued-a-man-in-the-middle-certificate-1429982.html)发布了一个对任意网站都有效的根证书
- 2015年，埃及MSC Holding使用CNNIC签发的中级证书签发gmail假证书，导致Chrome和Firefox移除的CNNIC根证书 [[相关报道]](https://en.wikipedia.org/wiki/China_Internet_Network_Information_Center)
- 后面我们会介绍[CA增强方案](web-security/tls.md)

### 假设硬件是可信的

- 若NSA要干坏事，则该假设很可能不成立。NSA下属的网络攻击部门TAO(Office of Tailored Access Operations，定制接入行动办公室)掌握大量硬件攻击手段，详见[NSA ANT目录](https://en.wikipedia.org/wiki/NSA_ANT_catalog)
- 2016年9月，Cisco在一个关于路由器故障报告中提到宇宙辐射可能是原因之一。这类故障称为[“Single event upset (单粒子翻转)”](https://en.wikipedia.org/wiki/Single_event_upset)。[[英文报道]](http://www.networkworld.com/article/3122864/hardware/cisco-says-router-bug-could-be-result-of-cosmic-radiation-seriously.html)，与[[中文报道]](http://www.leiphone.com/news/201609/AtW1F5zt6GS1ru9Y.html)

### 假设密码学中充分的随机性

- 由于产生密钥或签名时熵不足，研究者发现0.75%的TLS证书共享密钥，获得0.5%的TLS主机和0.03%的SSH主机的RSA私钥，1.03%的SSH主机的DSA私钥，详见[Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices (USENIX Security 2012)](https://factorable.net/weakkeys12.extended.pdf)

### 认为自主开发软件/系统更安全

- [XcodeGhost](https://en.wikipedia.org/wiki/XcodeGhost)在Apple的Xcode开发环境中注入恶意代码，并感染超过4000个应用，包括微博和网易云音乐。这些应用开发者从百度云和迅雷下载Xcode。尽管软件是自主开发的，但开发系统不是。

### 不上网/隔离就安全了？

- 攻击伊朗核设施的[震网蠕虫（Stuxnet）](https://en.wikipedia.org/wiki/Stuxnet)通过U盘传播 -> Windows感染 -> Siemens PCS 7 SCADA工控软件 -> Siemens设备控制器

### 没有电就安全了？

- [金唇 (The Thing，the Great Seal bug)](https://en.wikipedia.org/wiki/The_Thing_(listening_device))：1945年前苏联在赠送给美国大使馆的一个国徽礼物中安装了窃听器，该窃听器利用外部电磁波来获取能量，并将窃听到的信息发送出去（一种射频技术，是RFID的前身）

---

##安全问题3：机制问题（bug）

### Apple iCloud 口令猜测速率限制

- 人们通常采用弱密码，可以通过1K-1M次猜测得到
- iCloud有速率限制功能，但iCloud有许多API，其中“Find my iPhone”服务中的API忘了实现速率限制 [[详情]](https://github.com/hackappcom/ibrute)

### 在花旗集团信用卡站点缺失访问控制检查

- 花旗集团允许信用卡用户来在线访问其信用卡账户（用户名+口令）
- 账户信息页的URL中包括一些数字，这些数字与账号有关，而服务器不检查用户是否真的已经登录
- 攻击者尝试不同的数字，来获得不同人的账户信息
- 错误威胁模型？
	- 若攻击者通过浏览器访问站点，则系统是安全的
	- 若攻击者自己构造新的URL，则系统不安全
- 很难说是错误威胁模型，还是bug [[详情]](https://bitcoin.org/en/alert/2013-08-11-android)

### 安卓Java SecureRandom弱点导致比特币盗窃

- 在安卓中许多比特币钱包应用使用Java的SecureRandom API
- 系统有时忘记给PRNG设定种子
- 导致用户私钥容易被猜中，攻击者将用户的比特币转给自己 [[详情]](https://bitcoin.org/en/alert/2013-08-11-android)

### 心脏出血（Heartbleed）

- TLS的心跳扩展中，一方（客户端）发送心跳请求，包含一个负载+负载长度，另一方（服务器）用相同内容做应答
- CVE-2014-0160: 服务器未检查长度是否正确，过长的长度会导致服务器内存中数据被当做负载传递给客户端 [[详情]](https://en.wikipedia.org/wiki/Heartbleed)

### Shellshock

- 2014年9月24日公开的Bash shell中一系列安全漏洞，利用处理环境变量中函数定义之后的命令，攻击者可执行任意代码 [[详情]](https://en.wikipedia.org/wiki/Shellshock_(software_bug))
- CVE-2014-6271: 环境变量声明中，函数之后命令会被执行
	- `env x='() { :;}; echo vulnerable' bash -c "echo test"`
	- 有漏洞Bash会输出`vulnerable`；否则，输出`test`
	- [[代码解释]](https://unix.stackexchange.com/questions/157329/what-does-env-x-command-bash-do-and-why-is-it-insecure)

### 缓冲区溢出（buffer overflow）

- 下节课学习[缓冲区溢出](buffer-overflow/buffer-overflow-1.md)

---


