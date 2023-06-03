# trzsz-ssh

你是否曾经因为服务器太多记不住，而喜欢的 ssh 终端又没有服务器管理功能而苦恼？

tssh 支持搜索选择 `~/.ssh/config` 中配置的服务器进行登录，支持酷炫的 vim 操作习惯。

tssh 内置支持 [trzsz](https://trzsz.github.io/) ( trz / tsz ) ，一并解决了 Windows 中使用 `trzsz ssh` 上传速度慢的问题。

## 安装方法

- 用 go 直接安装（ 要求 go 1.20 以上 ）

  ```sh
  go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest
  ```

  安装后，`tssh` 程序一般位于 `~/go/bin/` 目录下（ Windows 一般在 `C:\Users\your_name\go\bin\` ）。

- 从 [Releases](https://github.com/trzsz/trzsz-ssh/releases) 中直接下载适用的版本。

## 使用方法

_`~/` 代表 HOME 目录。在 Windows 中，请将下文的 `~/` 替换成 `C:\Users\your_name\`。_

- 在客户端生成密钥对，一般存放在 `~/.ssh/` 下：

  - `ssh-keygen -t rsa -b 4096` 生成 RSA 的，私钥 `~/.ssh/id_rsa`，公钥 `~/.ssh/id_rsa.pub`。

- 登录服务器，将公钥（ 即前面生成密钥对时 `*.pub` 后缀的文件内容 ）追加写入服务器上的 `~/.ssh/authorized_keys` 文件中。

  一行代表一个客户端的公钥，注意设置正确的权限 `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys`。

- 在客户端配置好 `~/.ssh/config` 文件，举例：

```
Host alias1
    HostName 192.168.0.1
    Port 22
    User your_name
Host alias2
    HostName 192.168.0.2
    Port 22
    User your_name
```

- 使用 `tssh` 命令登录服务器，`tssh alias1` 命令登录在 `~/.ssh/config` 中 `alias1` 对应的服务器。

  `tssh` 命令不带参数，可以搜索并选择 `~/.ssh/config` 中配置好的服务器并登录。

## 录屏演示

![tssh登录演示](https://trzsz.github.io/images/tssh.gif)

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/trzsz/issues) 。欢迎加入 QQ 群：318578930。

请作者喝一杯咖啡 ☕ ?

![sponsor wechat qrcode](https://trzsz.github.io/images/sponsor_wechat.jpg)
![sponsor alipay qrcode](https://trzsz.github.io/images/sponsor_alipay.jpg)
