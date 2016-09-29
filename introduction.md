#介绍

###哈尔滨工业大学 网络与信息安全 张宇 2016

课件：https://github.com/YuZhang/Security-Courseware

参考课程: 

- [MIT 6.858 Computer Systems Security](http://ocw.mit.edu/courses/electrical-engineering-and-computer-science/6-858-computer-systems-security-fall-2014/index.htm)
- [Stanford CS155 Computer and Network Security](https://crypto.stanford.edu/cs155/)

---

##安全概述

- **安全**：在敌手出现时实现目标，或者说在敌手出现时，系统可正常工作
- 安全思维：
	- Policy（政策）：欲达成的目标，例如CIA：机密性（Confidentiality），完整性（integrity），可用性（availability）
	- Threat model（威胁模型）：关于敌手能力的假设
	- Mechianism（机制）：系统中用于实现政策的组件
	- Resulting goal（结果目标）：在**威胁模型**下，攻击者无法违反**政策**
- 安全是一个**否定**目标（保证不存在攻击）
	- 难以考虑到攻击者所有可能的攻击方式
	- 真实的威胁模型是开放的
- 若无法做到**完美安全**，为什么还要做安全？
	- 了解系统的安全边界
	- 每个系统可能都有可利用弱点，理解系统能做的和不能做的
	- 管理安全风险 vs. 收益

###计算机安全（Computer Security）

也称为网络空间安全（cybersecurity）或IT安全，保护信息系统中软件、硬件、信息及服务。

- 信息安全（InfoSec）：保护信息的机密性，完整性，可用性，不可抵赖等等
- 网络安全（Network security）：计算机网络及网络可访问资源的安全
- 网络战（Cyberwarfare）：一国入侵另一国计算机或网络
- 互联网安全（Internet security）：互联网相关安全，包括浏览器安全以及网络安全等等
- 移动安全（Mobile security）：移动计算安全，特别是智能手机


典型漏洞与攻击：后门（Backdoor），拒绝服务（DoS），直接访问（Direct-access），窃听（Eavesdropping），伪造（Spoofing），篡改（Tampering），特权提升（Privilege escalation），钓鱼（Phishing），点击劫持（Clickjacking），社交工程（Social engineering），木马（Trojan），僵尸网络（Zombie/botnet），病毒/蠕虫/恶意软件（virus/worm/malware）

###不同产品上漏洞统计

CVE（Common Vulnerabilities & Exposures，通用漏洞披露）中[2016弱点最多的50个产品](http://www.cvedetails.com/top-50-products.php?year=2016):

- 前五名：Andriod（385个漏洞），Debian（290），Ubuntu（254），Flash（226），Opensuse（220）

###漏洞买卖

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

###肉鸡市场：

[PPI (Pay-per-install)](http://www.icir.org/vern/papers/ppi-usesec11.pdf) ：

- 美国：$100-180 / 千台
- 亚洲：$7-8 / 千台

---
##安全问题1：违背政策

###Sarah Palin的email账号破解 [[详情](https://en.wikipedia.org/wiki/Sarah_Palin_email_hack)]

2008年9月，美国共和党副总统候选人莎拉·佩林的雅虎私人电子邮箱遭黑客入侵。黑客可能是一名田纳西州民主党议员正在念大学的儿子戴维·克内尔。

攻击者利用雅虎密码遗忘提示功能和网络搜索引擎：佩林的邮箱密码提示问题包括她的生日，以及她和丈夫托德在何处相识。为副总统候选人的佩林已无太多隐私可言，可在谷歌上轻松找到答案。

FBI发现了攻击者在代理服务器上的踪迹。

**政策违背：真正用户需要知道用户名与口令 --> 知道密码提示问题答案**

###Mat Honan的Apple和Amazon账号破解 [[详情](https://www.wired.com/2012/08/apple-amazon-mat-honan-hacking/all/)]

2012年一位网站主编Mat Honan的Google，Twitter, Apple账号都被破解。攻击者用这些账号发表种族言论，并删除了其iPhone等设备上数据。

- Twitter账号：采用Gmail邮箱
- Gmail密码重置：发送一个验证链接到备份邮箱。Mat的备份邮箱是Apple的me.com账号
- Apple密码重置：需要账单地址（个人住址可以查到），信用卡末4位（未知）
- Amazon密码重置：提供用户的任意一张信用卡账号（以及用户名，账单地址等）。在一个账号上添加信用卡，不需要密码（电话服务）。登录后，Amazon会显示所有信用卡末4位。

**政策违背：邮箱安全-->备份邮箱-->账单地址+信用卡末4位-->Amazon密码-->任意信用卡**

###Twitter上@N 账号劫持 [[详情](https://medium.com/@N/how-i-lost-my-50-000-twitter-username-24eb09e026dd#.d7lhyudko)]

2014年，Twitter上的 @N 账号（有人出价$50000）被劫持。账号所有者（受害者）Naoki Hiroshima在尝试夺回账号失败后，将用户名改为@N\_is\_stolen。Naoki通过与攻击者的邮件交流了解了其攻击过程。

- @N 账号邮箱是受害者在GoDaddy上个人域名
- 个人域名被劫持，因而邮件服务器被更改，账号邮箱也就被劫持
- GoDaddy账号恢复需要提供信用卡末6位
- 攻击者打电话给PayPal，获得了信用卡末4位
- 攻击者打电话给GoDaddy，说信用卡丢了，但记得末4位；GoDaddy让攻击者来回忆前2位，可以一直猜，直到猜对（攻击者只猜了两次就蒙对了）


**政策违背：账号安全-->邮箱安全-->域名安全-->信用卡末6位-->信用卡末4位**


###2003年Linux后门事件 [[详情](https://freedom-to-tinker.com/2013/10/09/the-linux-backdoor-attempt-of-2003/)]

2003年时，Linux采用代码维护系统BitKeeper，提交代码需经过审查。部分开发者为了方便另建立了一个CVS来维护源代码。攻击者在CVS所维护源码中插入如下代码，将无效调用`wait4()`的进程赋予root权限。

```c
if ((options == (__WCLONE|__WALL)) && (current->uid = 0))                  			retval = -EINVAL;        
```
不过，由于这个修改未经过审批流程，随后被发现。

**政策违背：BitKeeper --> CVS**

---

##安全问题2：违背威胁模型/假设

###未考虑人的因素

- 通过邮件/电话的电信诈骗
- 攻击者通过致电客服来重置密码
- 胶皮管密码分析

###1983年图灵演说

Reflections on Trusting Trust by Ken Thompson
> To what extent should one trust a statement that a program is free of Trojan horses? Perhaps it is more important to trust the people who wrote the software.

- 在发明C语言过程中，有一个“鸡生蛋，蛋生鸡”问题，即如何用C语言来实现C语言的编译器。
- 原理上，需要一个程序，能够复制自己，并在每次复制时‘学习’一点新特性，逐渐演化成一个“产生编译器的程序”。
- Ken在该程序中植入了一个木马，能够用特定密码来‘通过’`Login`函数检查。
- 即使有人发现了木马并更改了代码，但若用有木马的编译器编译，则新编译器中仍有木马！

###随时间变化的计算假设

- 自80年代中期，MIT Kerberos系统使用56比特DES密钥
- 但目前2^56已经不够大了，1天之内就能破解

###所有SSL证书CA都可信？

- 连接SSL支持的站点（HTTPS）需要验证CA办法的证书（身份和公钥的数字签名）
- 多数浏览器相信上百个CA，任何一个CA被攻破，可伪造任何站点证书
- 2011年，两个CA，[DigiNotar](http://en.wikipedia.org/wiki/DigiNotar)和[Comodo](http://en.wikipedia.org/wiki/Comodo_Group)，发布了包括google, yahoo等的假证书
- 2012年，一个CA，[Trustwave](http://www.h-online.com/security/news/item/Trustwave-issued-a-man-in-the-middle-certificate-1429982.html)发布了一个对任意网站都有效的根证书
- 2015年，埃及MSC Holding使用CNNIC签发的中级证书签发gmail假证书，导致Chrome和Firefox移除的CNNIC根证书 [[详情](https://en.wikipedia.org/wiki/China_Internet_Network_Information_Center)]

###假设硬件是可信的

- 若NSA要干坏事，则该假设很可能不成立。NSA下属的网络攻击部门TAO(Office of Tailored Access Operations，定制接入行动办公室)掌握大量硬件攻击手段，详见[NSA ANT目录](https://en.wikipedia.org/wiki/NSA_ANT_catalog)


###假设密码学中充分的随机性

- 由于产生密钥或签名时熵不足，研究者发现0.75%的TLS证书共享密钥，获得0.5%的TLS主机和0.03%的SSH主机的RSA私钥，1.03%的SSH主机的DSA私钥，详见[Mining Your Ps and Qs: Detection of Widespread Weak Keys in Network Devices](https://factorable.net/weakkeys12.extended.pdf)

###认为自主开发软件/系统更安全

- [XcodeGhost](https://en.wikipedia.org/wiki/XcodeGhost)在Apple的Xcode开发环境中注入恶意代码，并感染超过4000个应用，包括微博和网易云音乐。这些应用开发者从百度云和迅雷下载Xcode。

###不上网/隔离就安全了？

- 攻击伊朗核设施的[震网蠕虫（Stuxnet）](https://en.wikipedia.org/wiki/Stuxnet)通过U盘传播 -> Windows感染 -> Siemens PCS 7 SCADA工控软件 -> Siemens设备控制器

---

##安全问题3：机制问题（bug）


###Apple iCloud 口令猜测速率限制 [[详情](https://github.com/hackappcom/ibrute)]

- 人们通常采用弱密码，可以通过1K-1M次猜测得到
- iCloud有速率限制功能，但iCloud有许多API，其中“Find my iPhone”服务中的API忘了实现速率限制

###在花旗集团信用卡站点缺失访问控制检查 [[详情](https://bitcoin.org/en/alert/2013-08-11-android)]

- 花旗集团允许信用卡用户来在线访问其信用卡账户（用户名+口令）
- 账户信息页的URL中包括一些数字，这些数字与账号有关，而服务器不检查用户是否真的已经登录
- 攻击者尝试不同的数字，来获得不同人的账户信息
- 错误威胁模型？
	- 若攻击者通过浏览器访问站点，则系统是安全的
	- 若攻击者自己构造新的URL，则系统不安全
- 很难说是错误威胁模型，还是bug

###安卓Java SecureRandom弱点导致比特币盗窃 [[详情](https://bitcoin.org/en/alert/2013-08-11-android)]

- 在安卓中许多比特币钱包应用使用Java的SecureRandom API
- 系统有时忘记给PRNG设定种子
- 导致用户私钥容易被猜中，攻击者将用户的比特币转给自己


###心脏出血（Heartbleed）[[详情](https://en.wikipedia.org/wiki/Heartbleed)]
- TLS的心跳扩展中，一方（客户端）发送心跳请求，包含一个负载+负载长度，另一方（服务器）用相同内容做应答
- 实现中，服务器未检查长度是否正确，过长的长度会导致服务器内存中数据被当做负载传递给客户端

###缓冲区溢出（buffer overflow）

- 下面开始学习[缓冲区溢出课程](buffer-overflow/buffer-overflow-1.md)
