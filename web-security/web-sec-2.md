#Web安全：Phishing、Clickjacking与Tracking

###哈尔滨工业大学 网络与信息安全 张宇 2016

---

本课程学习Web用户所面临的安全问题，所涉及的攻击都是通过欺骗用户（通过浏览器）来实现的。

##1. Phishing

[Phishing（钓鱼）](https://en.wikipedia.org/wiki/Phishing)：通常通过电邮和短信等手段，诱骗受害者来访问攻击者所伪装的可信实体。

著名钓鱼攻击事件：

- 1995年，在针对AOL用户的攻击工具[AOHell](https://en.wikipedia.org/wiki/AOHell)中首次出现"phishing"这个词
- 2011年3月，RSA内部员工遭受钓鱼攻击，导致RSA SecureID安全令牌的主密钥被盗取；之后美国国防部供应商被攻破
- 2013年11月，分包公司账号被攻击，美国零售商Target的1.1亿条顾客和信息卡记录被盗取，CEO和IT安全员工被解职
- 2014年8月，iCloud中的许多名人的照片通过email钓鱼被泄露
- 2014年11月，ICANN的Centralized Zone Data System的管理权限被盗取，系统用户信息被泄露
- 2016年3月，希拉里竞选主席[波德斯塔（Podesta）电子邮件泄露](https://en.wikipedia.org/wiki/Podesta_emails)。攻击者俄罗斯黑客组织Fancy Bear（奇幻熊）采用鱼叉式钓鱼攻击，向波德斯塔发送一封伪造的Gmail警告邮件，其中包含一个链接指向一个伪造的登录页面。同年10月，[维基解密公开了泄露的邮件](https://wikileaks.org/podesta-emails/)。

根据[APWG Phishing Activity Trends Report](http://www.antiphishing.org/resources/apwg-reports/)对2016年第2季度钓鱼攻击的统计，

- 发现事件46万，比2015年第4季度高出61%
- 47%针对零售/服务商
- 每个月受攻击品牌约400个

钓鱼攻击类型：

- Phishing（钓鱼）：伪装为可信实体获取信息
- Spear phishing（鱼叉式钓鱼）：针对特定目标
- Clone phishing（克隆钓鱼）：将一个合法邮件中包含附件或链接替换为恶意内容，其他与原邮件一样
- Whaling（鲸钓）：以高层人士为目标（钓大鱼）
- 高级钓鱼攻击：
	- Social phishing：攻击者伪装为熟人（70%用户被骗）
	- Context-aware phishing：钓鱼邮件中包含用户相关信息，例如最近的购物交易信息（10%用户被骗）
	- 两者结合：一个对西点军校学员的实验中，在学期末发送一封邮件“There was a prolbem with your last grade report; click here to resolve it.”，80%的学员点击

攻击技术：

- 链接操纵（Link manipulation）：一个恶意链接看起来像来自可信网站
	- `http://www.yourbank.example.com`
	- [`http://google.com`](http://attacker.com)
	- `http://www.bankofamerca.com`
	- `http://bankofthevvest.com`
	- `http://paypal.com` (first `p` in Cyrillic)，[IDN homograph attack](https://en.wikipedia.org/wiki/IDN_homograph_attack)
- 过滤器绕过（Filter evasion）：一些反钓鱼过滤器可以识别上述操纵链接攻击；攻击者转而将文字改为图片；为此，过滤器使用OCR来识别图片中文字
- 网站伪造（Website forgery）：
	- 操纵地址栏，例如`window.location.href=window.location.href+"#phishing"`，或`history.pushState(null, null, 'phishing');`
	- XSS利用可信网站中的漏洞 
	- 中间人攻击将网站内容替换
- 隐蔽重定向（Covert redirect）：
	- 钓鱼链接模式：http://认证网站URL/第三方应用URL/恶意重定向URL
	- 开放认证协议[OAuth](https://en.wikipedia.org/wiki/OAuth)和[OpenID](https://en.wikipedia.org/wiki/OpenID)的提供商（例如微博，QQ，Facebook，Google）未对回调URL进行验证，导致用户在登录一个第三方网站时，在认证提供商处认证后，跳会到第三方网站时，又跳转到攻击者指定恶意URL
	- 这属于一种[Open Redirector（RFC6819）](https://tools.ietf.org/html/rfc6819#section-4.2.4)漏洞
	- 例子：[QQ OAuth2.0 漏洞详情](http://tetraph.com/security/covert-redirect/tencent-qq-oauth-2-0-covert-redirect-vulnerabiliy-information-leakage-open-redirect/)，[POC链接](http://openapi.qzone.qq.com/oauth/show?which=Login&display=pc&client_id=100261282&redirect_uri=http%3A%2F%2Fuc.cjcp.com.cn%2F%3Fm%3Duser%26a%3DotherLogin%26type%3Dqq%26furl%3Dhttp%253A%252F%252Ftetraph.com%252Fessayjeans%252Fseasons%252F%2525E7%2525A2%25258E%2525E5%2525A4%25258F.html&response_type=code&scope=get_user_info%2Cadd_share)，POC代码：

```
http://openapi.qzone.qq.com/oauth/show?          <--Auth Provider URL
which=Login&display=pc&client_id=100261282&
redirect_uri=http%3A%2F%2Fuc.cjcp.com.cn         <--3rd-party App URL
%2F%3Fm%3Duser%26a%3DotherLogin%26type%3Dqq%26
furl%3Dhttp%253A%252F%252Ftetraph.com%           <--Destination URL
252Fessayjeans%252Fseasons%252F%2525E7%2525A2%25258E%2525E5%2525A4%25258F.html&
response_type=code&scope=get_user_info%2Cadd_share
```

- 其他类型phishing：
	- [Tabnabbing](https://en.wikipedia.org/wiki/Tabnabbing)：并不直接引导用户到钓鱼网站，而是在浏览器上偷偷地打开一个新的Tab等待用户访问
	- [Phone phishing](https://en.wikipedia.org/wiki/Voice_phishing)：也称为“vishing”，通过伪造来电号码实施电信诈骗
	- [Evil twin](https://en.wikipedia.org/wiki/Evil_twin_(wireless_networks))：伪装为可信的Wifi热点

- 防御：
	- HTTPS降低被钓鱼风险，并不能彻底防御钓鱼
	- 白名单，收藏夹，导航网站，搜索引擎认证
	- 改进安全UI
		- 登录时需用户确认留在网站上的一个线索（sitekey）（单词，或图片）
	- 过滤垃圾邮件和短信
	- 监测并取缔钓鱼网站
	- 通过另外的手段验证交易，例如短信验证
	- 钓鱼攻击本质是用技术来攻击人的弱点，从技术角度无法彻底消除。最好的防御————多加小心！

##2. Clickjacking

[Clickjacking](https://en.wikipedia.org/wiki/Clickjacking)：也称作“User Interface redress attack”，欺骗用户鼠标点击一个对象，该对象与用户本以为要点击的不同。

攻击效果：

- 欺骗用户一键购物
- 偷偷通过Flash开启摄像头/麦克风
- 公开社交网络账户信息
- 下载或运行恶意软件
- 关注某人，分享链接，点赞
- 点击广告来产生pay per click收入

一个例子，看上去是谷歌，点击打开百度，[源文件](supplyments/clickjacking-1.html)：

```html
<html><head>
<title>Google</title>
<script>
function win_open() {
    window.open("http://www.baidu.com");
}
</script></head>
<body>
<a onMouseUp="win_open()" href=http://www.google.com/>
Go to Google</a>
</body></html>
```

一个基于`iframe`的例子：




##3. Tracking

---

