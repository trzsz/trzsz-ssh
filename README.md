# trzsz-ssh ( tssh )

支持 [trzsz](https://trzsz.github.io/cn/) ( trz / tsz ) 的 ssh 客户端，支持搜索和选择服务器进行批量登录，支持记住密码。

An ssh client that supports [trzsz](https://trzsz.github.io/), supports searching and selecting servers for batch login.

Website: [https://trzsz.github.io/ssh](https://trzsz.github.io/ssh) ( English ) 　中文文档：[https://trzsz.github.io/cn/ssh](https://trzsz.github.io/cn/ssh)

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/trzsz-ssh)](https://github.com/trzsz/trzsz-ssh/releases)

## tssh 简介

你喜欢的 ssh 终端是否有好用的服务器管理功能？是否支持记住密码？是否有好用的文件传输工具？

tssh 支持选择或搜索 `~/.ssh/config` 中配置的服务器，支持 vim 操作习惯，解决 ssh 终端的服务器管理问题。

tssh 支持一次选择多台服务器，批量登录，并支持批量执行预先指定的命令，方便快速完成批量服务器操作。

tssh 支持配置服务器登录密码，解决每次手工输入密码的麻烦（ 在自己能控制的服务器，推荐使用公私钥登录 ）。

tssh 内置支持 [trzsz](https://trzsz.github.io/cn/) ( trz / tsz ) 文件传输工具，一并解决了 Windows 中使用 `trzsz ssh` 上传速度很慢的问题。

_在作者的 MacOS 上，使用 `trzsz ssh` 的上传速度在 10 MB/s 左右，而使用 `tssh` 可以到 80 MB/s 以上。_

## 安装方法

**_客户端安装 `trzsz-ssh ( tssh )` 的方法如下（ 任选其一 ）：_**

- Windows 可用 [scoop](https://scoop.sh/) / [winget](https://learn.microsoft.com/zh-cn/windows/package-manager/winget/) / [choco](https://community.chocolatey.org/) 安装

  <details><summary><code>scoop install tssh</code> / <code>winget install tssh</code> / <code>choco install tssh</code></summary>

  ```sh
  scoop install tssh
  ```

  ```sh
  winget install tssh
  ```

  ```sh
  choco install tssh
  ```

  </details>

- MacOS 可用 [homebrew](https://brew.sh/) 安装

  <details><summary><code>brew install trzsz-ssh</code></summary>

  ```sh
  brew update
  brew install trzsz-ssh
  ```

  </details>

- Ubuntu 可用 apt 安装

  <details><summary><code>sudo apt install tssh</code></summary>

  ```sh
  sudo apt update && sudo apt install software-properties-common
  sudo add-apt-repository ppa:trzsz/ppa && sudo apt update

  sudo apt install tssh
  ```

  </details>

- Debian 可用 apt 安装

  <details><summary><code>sudo apt install tssh</code></summary>

  ```sh
  sudo apt install curl gpg
  curl -s 'https://keyserver.ubuntu.com/pks/lookup?op=get&search=0x7074ce75da7cc691c1ae1a7c7e51d1ad956055ca' \
    | gpg --dearmor -o /usr/share/keyrings/trzsz.gpg
  echo 'deb [signed-by=/usr/share/keyrings/trzsz.gpg] https://ppa.launchpadcontent.net/trzsz/ppa/ubuntu jammy main' \
    | sudo tee /etc/apt/sources.list.d/trzsz.list
  sudo apt update

  sudo apt install tssh
  ```

  </details>

- Linux 可用 yum 安装

  <details><summary><code>sudo yum install tssh</code></summary>

  - 国内推荐使用 [wlnmp](https://www.wlnmp.com/install) 源，安装 tssh 只需要添加 wlnmp 源（ 配置 epel 源不是必须的 ）：

    ```sh
    curl -fsSL "https://sh.wlnmp.com/wlnmp.sh" | bash

    sudo yum install tssh
    ```

  - 也可使用 [gemfury](https://gemfury.com/) 源（ 只要网络通，所有操作系统通用 ）

    ```sh
    echo '[trzsz]
    name=Trzsz Repo
    baseurl=https://yum.fury.io/trzsz/
    enabled=1
    gpgcheck=0' | sudo tee /etc/yum.repos.d/trzsz.repo

    sudo yum install tssh
    ```

  </details>

- ArchLinux 可用 [yay](https://github.com/Jguer/yay) 安装

  <details><summary><code>yay -S tssh</code></summary>

  ```sh
  yay -Syu
  yay -S tssh
  ```

  </details>

- 用 Go 直接安装（ 要求 go 1.20 以上 ）

  <details><summary><code>go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest</code></summary>

  ```sh
  go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest
  ```

  安装后，`tssh` 程序一般位于 `~/go/bin/` 目录下（ Windows 一般在 `C:\Users\your_name\go\bin\` ）。

  </details>

- 可从 [Releases](https://github.com/trzsz/trzsz-ssh/releases) 中直接下载适用的版本

  <details><summary><code>或者用 Go 编译（ 要求 go 1.20 以上 ）</code></summary>

  ```sh
  git clone https://github.com/trzsz/trzsz-ssh.git
  cd trzsz-ssh
  make
  sudo make install
  ```

  </details>

**_服务器上要安装 [trzsz](https://trzsz.github.io/cn/) 才能使用 `trz / tsz` 上传和下载，可任选其一安装：
[Go 版](https://trzsz.github.io/cn/go)（ ⭐ 推荐 ）、[Py 版](https://trzsz.github.io/cn/)、[Js 版](https://trzsz.github.io/cn/js)。_**

_如果服务器不安装 [trzsz](https://trzsz.github.io/cn/)，也能用 `tssh`，只是不使用 `trz / tsz` 上传和下载而已。_

## 使用方法

_`~/` 代表 HOME 目录。在 Windows 中，请将下文的 `~/` 替换成 `C:\Users\your_name\`。_

- 在客户端生成密钥对，一般存放在 `~/.ssh/` 下（ 只要一种就可以了 ）：

  - `ssh-keygen -t ed25519` 生成 ED25519 的，私钥 `~/.ssh/id_ed25519`，公钥 `~/.ssh/id_ed25519.pub`。
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

## 批量登录

- 支持在 `iTerm2`（ 要开启 [Python API](https://iterm2.com/python-api-auth.html)，但不需要`Allow all apps to connect` ），`tmux` 和 `Windows Terminal` 中一次选择多台服务器，批量登录，并支持批量执行预先指定的命令。

- 按下 `Space`、`Ctrl+X` 等可以选中或取消当前服务器，若不能选中说明还不支持当前终端，请先运行 `tmux`。

- 按下 `Ctrl+P` 会以分屏的方式批量登录，`Ctrl+W` 会打开新窗口批量登录，`Ctrl+T` 会打开新 tab 批量登录。

- `tssh` 不带参数启动可以批量登录服务器，若带 `-o RemoteCommand` 参数启动则可以批量执行指定的命令。支持执行指定命令之后进入交互式 shell，但 `Windows Terminal` 不支持分号 `;`，可以用 `|cat&&` 代替。举例：

  ```sh
  tssh -t -o RemoteCommand='ping -c3 trzsz.github.io ; bash'
  tssh -t -o RemoteCommand="ping -c3 trzsz.github.io |cat&& bash"
  ```

## 分组标签

- 如果服务器数量很多，分组标签 `GroupLabels` 可以在按 `/` 搜索时，快速找到目标服务器。

- 按 `/` 输入分组标签后，`回车`可以锁定；再按 `/` 可以输入另一个分组标签，`回车`再次锁定。

- 在非搜索模式下，按 `E` 可以清空当前搜索标签；在搜索模式下按 `Ctrl + E` 也是同样效果。

- 支持在一个 `GroupLabels` 中以空格分隔，配置多个分组标签；支持配置多个 `GroupLabels`。

- 支持以通配符 \* 的形式，在多个 Host 节点配置分组标签，`tssh` 会将所有的标签汇总起来。

  ```
  # 以下 testAA 具有标签 group1 group2 label3 label4 group5，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test*
      #!! GroupLabels group1 group2
      #!! GroupLabels label3
  Host testAA
      #!! GroupLabels label4 group5
  ```

## 自动交互

- 支持类似 `expect` 的自动交互功能，可以在登录服务器之后，自动匹配服务器的输出，然后自动输入。

  ```
  Host auto
      #!! ExpectCount 2  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectTimeout 30  # 配置自动交互的超时时间（单位：秒），默认是 30 秒
      #!! ExpectPattern1 *password  # 配置第一个自动交互的匹配表达式
      # 配置第一个自动输入（密文），填 tssh --enc-secret 编码后的字符串，会自动发送 \r 回车
      #!! ExpectSendPass1 d7983b4a8ac204bd073ed04741913befd4fbf813ad405d7404cb7d779536f8b87e71106d7780b2
      #!! ExpectPattern2 $  # 配置第二个自动交互的匹配表达式
      #!! ExpectSendText2 echo tssh expect\r  # 配置第二个自动输入（明文），需要指定 \r 才会发送回车
      # 以上 ExpectSendPass? 和 ExpectSendText? 只要二选一即可，若都配置则 ExpectSendPass? 的优先级更高
  ```

## 记住密码

- 为了兼容标准 ssh ，密码可以单独配置在 `~/.ssh/password` 中，也可以在 `~/.ssh/config` 中加上 `#!!` 前缀。

- 推荐使用前面密钥认证的方式，密码的安全性弱一些。如果必须要用密码，建议设置好 `~/.ssh/password` 的权限，如：

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/password
  ```

- 下面配置 `test1` 和 `test2` 的密码是 `123456`，其他以 `test` 开头的密码是 `111111`：

  ```
  # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      #!! Password 123456

  # 如果配置在 ~/.ssh/password 中，则不需要考虑是否兼容标准 ssh
  Host test2
      Password 123456

  # ~/.ssh/config 和 ~/.ssh/password 是支持通配符的，tssh 会使用第一个匹配到的值。
  # 这里希望 test2 使用区别于其他 test* 的密码，所以将 test* 放在了 test2 的后面。

  Host test*
      Password 111111
  ```

- 支持记住私钥的`Passphrase`（ 推荐使用 `ssh-agent` ）。支持与 `IdentityFile` 一起配置, 支持使用私钥文件名代替 Host 别名设置通用密钥的 `Passphrase`。举例：

  ```
  # IdentityFile 和 Passphrase 一起配置，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      IdentityFile /path/to/id_rsa
      #!! Passphrase 123456

  # 在 ~/.ssh/config 中配置通用私钥 ~/.ssh/id_ed25519 对应的 Passphrase
  # 可以加上通配符 * 以避免 tssh 搜索和选择时，文件名出现在服务器列表中。
  Host id_ed25519*
      #!! Passphrase 111111

  # 在 ~/.ssh/password 中配置则不需要通配符*，也不会出现在服务器列表中。
  Host id_rsa
      Passphrase 111111
  ```

## 记住答案

- 除了私钥和密码，还有一种登录方式，英文叫 keyboard interactive ，是服务器返回一些问题，客户端提供正确的答案就能登录，很多自定义的一次性密码就是利用这种方式实现的。

- 如果答案是固定不变的，`tssh` 支持“记住答案”。大部分都是只有一个问题，只要配置 `QuestionAnswer1` 即可。对于有多个问题的，每个问题答案可按序号进行配置，也可以按问题的 hex 编码进行配置。

- 使用 `tssh --debug` 登录，会输出问题的 hex 编码，从而知道该如何使用 hex 编码进行配置。配置举例：

  ```
  # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      QuestionAnswer1 答案一
  Host test2
      QuestionAnswer1 答案一
      QuestionAnswer2 答案二
      QuestionAnswer3 答案三
  Host test3
      6e616d653a20 my_name  # 其中 `6e616d653a20` 是问题 `name: ` 的 hex 编码
      636f64653a20 my_code  # 其中 `636f64653a20` 是问题 `code: ` 的 hex 编码
  ```

## 可选配置

- 支持在 `~/.tssh.conf`（ Windows 是 `C:\Users\your_name\.tssh.conf` ）中进行以下自定义配置：

  ```
  # SSH 配置路径，默认为 ~/.ssh/config
  ConfigPath = ~/.ssh/config

  # 扩展配置路径，默认为 ~/.ssh/password
  ExConfigPath = ~/.ssh/password

  # trz 上传时，对话框打开的路径，为空时打开上次的路径， 默认为空
  DefaultUploadPath = ~/Downloads

  # tsz 下载时，自动保存的路径，为空时弹出对话框手工选择，默认为空
  DefaultDownloadPath = ~/Downloads

  # tssh 搜索和选择服务器时，每页显示的记录数，默认为 10
  PromptPageSize = 10

  # tssh 搜索和选择服务器时，详情中显示的配置列表，默认如下：
  PromptDetailItems = Alias Host Port User GroupLabels IdentityFile ProxyCommand ProxyJump RemoteCommand
  ```

## 其他功能

- 使用 `-f` 后台运行时，可以一并加上 `--reconnect` 参数，这样在后台进程因连接断开等而退出时，会自动重新连接。

- 使用 `--dragfile` 启用拖拽上传功能，想默认启用则可以在 `~/.ssh/config` 或扩展配置 `ExConfigPath` 中配置：

  ```
  Host *
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableDragFile Yes
  ```

- 使用 `--zmodem` 启用 `rz / sz` 功能，想默认启用则可以在 `~/.ssh/config` 或扩展配置 `ExConfigPath` 中配置：

  ```
  Host server0
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableZmodem Yes
  ```

  - 需要在客户端（ 本地电脑 ）上安装 `lrzsz`，Windows 可以从 [lrzsz-win32](https://github.com/trzsz/lrzsz-win32/releases) 下载解压并加到 `PATH` 中，也可以如下安装：

  ```
  scoop install https://trzsz.github.io/lrzsz.json

  choco install lrzsz --version=0.12.21
  ```

  - 关于进度条，己传文件大小和传输速度不是精确值，会有一些偏差，它的主要作用只是指示传输正在进行中。

- 使用 `-oEnableTrzsz=No` 禁用 trzsz 功能，想默认禁用则可以在 `~/.ssh/config` 或扩展配置 `ExConfigPath` 中配置：

  ```
  Host server1
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableTrzsz No
  ```

- 上文说的“记住密码”和“记住答案”，只要在配置项前面加上 `enc` 则可以配置密文，防止被人窥屏。密文可以解决密码含有`#`的问题。

  运行 `tssh --enc-secret`，输入密码或答案的明文，可得到用于配置的密文（ 相同密码每次加密的结果不同 ）：

  ```
  Host server2
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    encPassword de88c4dbdc95d85303682734e2397c4d8dd29bfff09ec53580f31dd40291fc8c7755
    encQuestionAnswer1 93956f6e7e9f2aef3af7d6a61f7046dddf14aa4bbd9845dbb836fe3782b62ac0d89f
  ```

- 运行 `tssh --new-host` 可以在 TUI 界面轻松添加 SSH 配置，并且完成后可以立即登录。

- 运行 `tssh --install-trzsz` 可以自动安装 [trzsz](https://github.com/trzsz/trzsz-go) 到服务器的 `~/.local/bin/` 目录。若获取 `trzsz` 的最新版本号失败，可以通过 `--trzsz-version x.x.x` 参数自行指定。若下载 `trzsz` 的安装包失败，可以自行下载并通过 `--trzsz-bin-path /path/to/trzsz.tar.gz` 参数指定。

## 快捷键

| 操作      | 全局快捷键                      | 非搜索快捷键 | 快捷键描述      |
| --------- | ------------------------------- | ------------ | --------------- |
| Confirm   | Enter                           |              | 确认并登录      |
| Quit/Exit | Ctrl+C Ctrl+Q                   | q Q          | 取消并退出      |
| Move Prev | Ctrl+K Shift+Tab ↑              | k K          | 往上移光标      |
| Move Next | Ctrl+J Tab ↓                    | j J          | 往下移光标      |
| Page Up   | Ctrl+H Ctrl+U Ctrl+B PageUp ←   | h H u U b B  | 往上翻一页      |
| Page Down | Ctrl+L Ctrl+D Ctrl+F PageDown → | l L d D f F  | 往下翻一页      |
| Goto Home | Home                            | g            | 跳到第一行      |
| Goto End  | End                             | G            | 跳到最尾行      |
| EraseKeys | Ctrl+E                          | e E          | 擦除搜索关键字  |
| TglSearch | /                               |              | 切换搜索功能    |
| Tgl Help  | ?                               |              | 切换帮助信息    |
| TglSelect | Ctrl+X Ctrl+Space Alt+Space     | Space x X    | 切换选中状态    |
| SelectAll | Ctrl+A                          | a A          | 全选当前页      |
| SelectOpp | Ctrl+O                          | o O          | 反选当前页      |
| Open Wins | Ctrl+W                          | w W          | 新窗口批量登录  |
| Open Tabs | Ctrl+T                          | t T          | 新 Tab 批量登录 |
| Open Pane | Ctrl+P                          | p P          | 分屏批量登录    |

## 故障排除

- 在 Warp 终端，分块 Blocks 的功能需要将 `tssh` 重命名为 `ssh`，推荐建个软链接（ 对更新友好 ）：

  ```
  sudo ln -sv $(which tssh) /usr/local/bin/ssh
  ```

  - `--dragfile` 参数可能会让 Warp 分块功能失效，请参考前文配置 `EnableDragFile` 来启用拖拽功能。

  - 拖拽文件或目录进入 Warp 终端后，可能不会立即触发上传，需要多按一次`回车`键，才会上传。

- 如果你在使用 Windows7 或者旧版本的 Windows10 等，遇到 `enable virtual terminal failed` 的错误。

  - 可以尝试在 [Cygwin](https://www.cygwin.com/)、[MSYS2](https://www.msys2.org/) 或 [Git Bash](https://www.atlassian.com/git/tutorials/git-bash) 内使用 `tssh`。

- 如果在 `~/.ssh/config` 中配置了 `tssh` 特有的配置项后，标准 `ssh` 报错 `Bad configuration option`。

  - 可以在出错配置项中加上前缀 `#!!`，标准 `ssh` 会将它当作注释，而 `tssh` 则会认为它是有效配置之一。

## 录屏演示

![tssh登录演示](https://trzsz.github.io/images/tssh.gif)

![tssh批量执行](https://trzsz.github.io/images/batch_ssh.gif)

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/trzsz-ssh/issues) 。欢迎加入 QQ 群：318578930。

## 赞助打赏

[❤️ 赞助 trzsz ❤️](https://github.com/trzsz)，请作者喝杯咖啡 ☕ ? 谢谢您们的支持！
