# trzsz-ssh ( tssh )

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/trzsz-ssh)](https://github.com/trzsz/trzsz-ssh/releases)

你是否曾经因为服务器太多记不住，而喜欢的 ssh 终端又没有服务器管理功能而苦恼？

tssh 支持选择（ 搜索 ） `~/.ssh/config` 中配置的服务器进行登录，支持酷炫的 vim 操作习惯。

tssh 内置支持 [trzsz](https://trzsz.github.io/) ( trz / tsz ) ，一并解决了 Windows 中使用 `trzsz ssh` 上传速度很慢的问题。

_在作者的 MacOS 上，使用 `trzsz ssh` 的上传速度在 10 MB/s 左右，而使用 `tssh` 可以到 80 MB/s 以上。_

## 安装方法

_服务器上要安装 [trzsz](https://trzsz.github.io/cn/) 才能使用 `trz / tsz` 上传和下载，三个版本可任选其一：
[Go 版](https://github.com/trzsz/trzsz-go)、[Py 版](https://github.com/trzsz/trzsz)、[Js 版](https://github.com/trzsz/trzsz.js)。_

_如果服务器不安装 [trzsz](https://trzsz.github.io/cn/)，也能用 `tssh`，只是不使用 `trz / tsz` 上传和下载而已。_

客户端安装 `tssh` 的方法如下（ 任选其一 ）：

- Windows 可用 [scoop](https://scoop.sh/) 安装

  ```sh
  scoop bucket add extras
  scoop update
  scoop install tssh
  ```

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

- 登录服务器，将公钥（ 即前面生成密钥对时 `.pub` 后缀的文件内容 ）追加写入服务器上的 `~/.ssh/authorized_keys` 文件中。

  一行代表一个客户端的公钥，注意 `~/.ssh/authorized_keys` 要设置正确的权限：

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
  ```

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

- 直接执行 `tssh` 命令（ 不带参数 ），可以选择（ 搜索 ） `~/.ssh/config` 中配置好的服务器并登录。

## 记住密码

- 为了兼容标准 ssh ，密码配置项独立放在 `~/.ssh/password` 中，其他配置项依然放在 `~/.ssh/config` 中。

- 推荐使用前面密钥认证的方式，密码的安全性弱一些。如果必须要用，建议设置好 `~/.ssh/password` 的权限：

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/password
  ```

- 下面 `~/.ssh/password` 配置 `test2` 的密码是 `123456`，其他以 `test` 开头的密码是 `111111`：

  ```
  Host test2
      Password 123456

  # ~/.ssh/config 和 ~/.ssh/password 是支持通配符的，tssh 会使用第一个匹配到的值。
  # 这里希望 test2 使用区别于其他 test* 的密码，所以将 test* 放在了 test2 的后面。

  Host test*
      Password 111111
  ```

## 录屏演示

![tssh登录演示](https://trzsz.github.io/images/tssh.gif)

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/trzsz/issues) 。欢迎加入 QQ 群：318578930。

请作者喝一杯咖啡 ☕ ?

![sponsor wechat qrcode](https://trzsz.github.io/images/sponsor_wechat.jpg)
![sponsor alipay qrcode](https://trzsz.github.io/images/sponsor_alipay.jpg)
