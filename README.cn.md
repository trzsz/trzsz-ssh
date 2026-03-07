# trzsz-ssh ( tssh ) - 满足您所需的 ssh 客户端

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/trzsz-ssh)](https://github.com/trzsz/trzsz-ssh/releases)
[![WebSite](https://img.shields.io/badge/WebSite-https%3A%2F%2Ftrzsz.github.io%2Fssh-blue?style=flat)](https://trzsz.github.io/ssh)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87%E6%96%87%E6%A1%A3-https%3A%2F%2Ftrzsz.github.io%2Fcn%2Fssh-blue?style=flat)](https://trzsz.github.io/cn/ssh)

trzsz-ssh ( tssh ) 设计为 ssh 客户端的直接替代品，提供与 openssh 完全兼容的基础功能，同时实现其他有用的扩展功能。

trzsz-ssh ( tssh ) 与 [tsshd](https://github.com/trzsz/tsshd) 一起，适用于高延迟的弱网连接，切换网络、休眠与唤醒都不会掉线，让 ssh 会话永远保持。

## 为什么做

- 服务器太多，记不住所有别名，`tssh` 内置登录界面，支持搜索和选择服务器登录。

- `tssh` 登录服务器后，内置支持 [trzsz](https://trzsz.github.io/cn/) ( trz / tsz ) 工具，传文件无需另外新开窗口。

- 有时需要同时登录一批机器，`tssh` 支持多选并批量登录，同时支持执行预设的命令。

- 有些服务器不支持公钥登录，`tssh` 支持记住密码，支持自动交互，提升登录的效率。

- 在 Windows 中使用 `tssh` 代替 `trzsz ssh`，可以解决 `trz` 上传速度很慢的问题。

- `tssh` 与 [tsshd](https://github.com/trzsz/tsshd) 类似于 mosh，解决了部分 mosh 的问题，例如 SSH 转发和 ProxyJump 等。

## 安装方法

**_客户端安装 `trzsz-ssh ( tssh )` 的方法如下（ 任选其一 ）：_**

- Windows 可用 scoop / winget / choco 安装

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

- MacOS 可用 Homebrew 安装

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

- ArchLinux 可用 yay 安装

  <details><summary><code>yay -S tssh</code></summary>

  ```sh
  yay -Syu
  yay -S tssh
  ```

  </details>

- ChromeOS 可用 Chromebrew 安装

  <details><summary><code>crew install tssh</code></summary>

  ```sh
  crew install tssh
  ```

  </details>

- 用 Go 直接安装（ 要求 go 1.25 以上 ）

  <details><summary><code>go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest</code></summary>

  ```sh
  go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest
  ```

  安装后，`tssh` 程序一般位于 `~/go/bin/` 目录下（ Windows 一般在 `C:\Users\your_name\go\bin\` ）。

  </details>

- 用 Go 自己编译（ 要求 go 1.25 以上 ）

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/trzsz-ssh.git
  cd trzsz-ssh
  make
  sudo make install
  ```

  </details>

- 可从 [GitHub Releases](https://github.com/trzsz/trzsz-ssh/releases) 中下载，国内可从 [Gitee 发行版](https://gitee.com/trzsz/tssh/releases) 中下载，然后本地安装。

  <details><summary><code>下载并本地安装</code></summary>

  ```sh
  sudo apt install /tmp/tssh_*.deb

  sudo dpkg -i /tmp/tssh_*.deb

  sudo dnf install /tmp/tssh_*.rpm

  sudo yum install /tmp/tssh_*.rpm

  sudo rpm -i /tmp/tssh_*.rpm

  tar zxvf tssh_*.tar.gz && sudo cp tssh_*/tssh /usr/bin/
  ```

  </details>

## 登录界面

- 使用之前，需要配置好 `~/.ssh/config` ( Windows 是 `C:\Users\xxx\.ssh\config`, `xxx` 换成用户名 )。

- 关于如何配置 `~/.ssh/config`，请参考 [openssh](https://manpages.debian.org/bookworm/openssh-client/ssh_config.5.en.html) ( `Match` 暂时要参考下文配置 `UseOpenSSHConfig` 才支持 )，或参考 tssh wiki [SSH基本配置](https://github.com/trzsz/trzsz-ssh/wiki/SSH%E5%9F%BA%E6%9C%AC%E9%85%8D%E7%BD%AE)。

- 直接无参数运行 `tssh` 命令就会打开登录界面，或者有除目标机器外的其他参数也会打开登录界面。

- 如果目标机器参数是 `~/.ssh/config` 中别名的一部分，不能完全匹配某个别名，也会打开登录界面。

- 如果配置了 `#!! HideHost yes`，或者别名中含有 `*` 或 `?` 通配符时，则不会显示在登录界面中。

- `tssh` 支持很多快捷键，支持搜索，在 `tmux`、`iTerm2` 和 `Windows Terminal` 等中使用时支持多选。

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

## 主题风格

- `tssh` 支持多种主题风格，在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeLayout` 选用。欢迎一起来创造更多更好看的。

- 每种主题风格都支持自定义颜色，在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeColors`，只要配置非默认的颜色即可。

- 请为你喜欢的主题风格[❤️投票❤️](https://github.com/trzsz/trzsz-ssh/issues/75)，得票数最高的主题风格将会在下个版本被设置为默认主题。

### tiny 小巧风

- 在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeLayout = tiny` 选用 `tiny 小巧风`。
  ![tssh tiny](https://trzsz.github.io/images/tssh_tiny.gif)

- 在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeColors`，要求配置成一行。`tiny 小巧风` 支持以下配置项：

  <details><summary><code>tiny 颜色配置项和默认值：</code></summary>

  ```json
  {
    "help_tips": "faint",
    "shortcuts": "faint",
    "label_icon": "blue",
    "label_text": "default",
    "cursor_icon": "green|bold",
    "active_selected": "green|bold",
    "active_alias": "cyan|bold",
    "active_host": "magenta|bold",
    "active_group": "blue|bold",
    "inactive_selected": "green|bold",
    "inactive_alias": "cyan",
    "inactive_host": "magenta",
    "inactive_group": "blue",
    "details_title": "default",
    "details_name": "faint",
    "details_value": "default"
  }
  ```

  </details>

  <details><summary><code>tiny 支持的颜色枚举，可用 `|` 连接多个：</code></summary>

  ```
  default
  black
  red
  green
  yellow
  blue
  magenta
  cyan
  white
  bgBlack
  bgRed
  bgGreen
  bgYellow
  bgBlue
  bgMagenta
  bgCyan
  bgWhite
  bold
  faint
  italic
  underline
  ```

  </details>

### simple 简约风

- 在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeLayout = simple` 选用 `simple 简约风`。
  ![tssh simple](https://trzsz.github.io/images/tssh_simple.gif)

- `simple 简约风` 支持的颜色配置项、默认值和颜色枚举，和 `tiny 小巧风` 完全相同，请参考前文。

### table 表格风

- 在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeLayout = table` 选用 `table 表格风`。
  ![tssh table](https://trzsz.github.io/images/tssh_table.gif)

- 在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中配置 `PromptThemeColors`，要求配置成一行。`table 表格风` 支持以下配置项：

  <details><summary><code>table 颜色配置项和默认值：</code></summary>

  ```json
  {
    "help_tips": "faint",
    "shortcuts": "faint",
    "table_header": "10",
    "default_alias": "6",
    "default_host": "5",
    "default_group": "4",
    "selected_icon": "2",
    "selected_alias": "14",
    "selected_host": "13",
    "selected_group": "12",
    "default_border": "8",
    "selected_border": "10",
    "details_name": "4",
    "details_value": "3",
    "details_border": "8"
  }
  ```

  </details>

- 支持的颜色枚举请参考 [lipgloss](https://github.com/charmbracelet/lipgloss#colors)，除了 `help_tips` 和 `shortcuts` 与前文 `tiny 小巧风` 相同。

## 支持 trzsz

- 在服务器上要安装 [trzsz](https://trzsz.github.io/cn/)，才能使用 `trz / tsz` 上传和下载，可任选其一安装：[Go 版](https://trzsz.github.io/cn/go)（ ⭐ 推荐 ）、[Py 版](https://trzsz.github.io/cn/)、[Js 版](https://trzsz.github.io/cn/js)。

- 在 `~/.ssh/config` 或 `ExConfigPath` 配置文件中，配置 `EnableDragFile` 为 `Yes` 启用拖拽上传功能。

  ```
  Host *
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableDragFile Yes
  ```

- 如果想在拖拽上传时覆盖现有文件，请将 `DragFileUploadCommand` 配置为 `trz -y` ：

  ```
  Host xxx
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    DragFileUploadCommand trz -y
  ```

- 如果只是想临时启用拖拽上传功能，可以在命令行中使用 `tssh --dragfile` 登录服务器。

- 在 `~/.ssh/config` 或 `ExConfigPath` 配置文件中，配置 `EnableTrzsz` 为 `No` 禁用 trzsz 和 zmodem。

  ```
  Host no_trzsz_nor_zmodem
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableTrzsz No
  ```

- 可使用 `--upload-file` 参数在命令行中指定文件或目录直接上传，也可在服务器后面指定 `trz` 上传命令参数和保存路径，如：

  ```sh
  tssh --upload-file /path/to/file1 --upload-file /path/to/dir2 xxx_server '~/.local/bin/trz -d /tmp/'
  ```

- 可在命令行中使用 `tsz` 直接下载文件或目录到本地，可一并使用 `--download-path` 参数指定本地保存的路径，如：

  ```sh
  tssh -t --client --download-path /tmp/ xxx_server 'tsz -d /path/to/file1 /path/to/dir2'
  ```

![tssh trzsz](https://trzsz.github.io/images/tssh_trzsz.gif)

## 支持 zmodem

- 在 `~/.ssh/config` 或 `ExConfigPath` 配置文件中，配置 `EnableZmodem` 为 `Yes` 启用 `rz / sz` 功能。

  ```
  Host *
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableZmodem Yes
  ```

- 如果想在拖拽文件时使用 rz 上传，请将 `DragFileUploadCommand` 配置为 `rz` ：

  ```
  Host xxx
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableDragFile Yes
    DragFileUploadCommand rz
  ```

- 除了服务器，本地电脑也要安装 `lrzsz`，Windows 可以从 [lrzsz-win32](https://github.com/trzsz/lrzsz-win32/releases) 下载，解压并加到 `PATH` 环境变量中，也可以如下安装：

  ```
  scoop install lrzsz / choco install lrzsz / winget install lrzsz
  ```

- 如果只是想临时启用 `rz / sz` 传文件功能，可以在命令行中使用 `tssh --zmodem` 登录服务器。

- 关于 `rz / sz` 进度条，己传大小和传输速度会有一点偏差，它的主要作用只是指示传输正在进行中。

- 可使用 `--upload-file` 参数在命令行中指定文件直接上传，在服务器后面 `cd` 到保存路径再指定 `rz` 命令及参数即可，如：

  ```sh
  tssh --upload-file /path/to/file1 --upload-file /path/to/file2 xxx_server 'cd /tmp/ && rz -yeb'
  ```

- 可在命令行中使用 `sz` 直接下载文件到本地，可一并使用 `--download-path` 参数指定本地保存的路径，如：

  ```sh
  tssh -t --client --zmodem --download-path /tmp/ xxx_server 'sz /path/to/file1 /path/to/file2'
  ```

## 支持 scp sftp

- 使用了 `tssh` 记住密码的功能，登录时不用手工输入密码了，`scp` 和 `sftp` 也一样可以不用手工输入密码。

- 使用了 `tssh` 的 UDP 模式，SSH 通讯走加密的 UDP 通道了，`scp` 和 `sftp` 也一样可以走加密的 UDP 通道。

- 只要 `scp` 和 `sftp` 使用 `-S` 选项指定 `tssh`，或者配置个 alias 即可使用 `tssh` 提供的一些功能，如：

  ```sh
  sftp -S tssh xxx
  scp -S tssh xxx @xxx:/tmp/
  alias tscp='scp -S tssh'
  alias tsftp='sftp -S tssh'
  ```

## 批量登录

- 支持在 `iTerm2`（ 要开启 [Python API](https://iterm2.com/python-api-auth.html)，但不需要`Allow all apps to connect` ），`tmux` 和 `Windows Terminal` 中一次选择多台服务器，批量登录，并支持批量执行预先指定的命令。

- 按下 `Space`、`Ctrl+X` 等可以选中或取消当前服务器，若不能选中说明还不支持当前终端，请先运行 `tmux`。

- 按下 `a` 或 `Ctrl+A` 全选当前页所有机器，`o` 或 `Ctrl+O` 反选当前页所有机器，`d` 或 `l` 翻到下一页。

- 按下 `p` 或 `Ctrl+P` 以分屏的方式登录，`w` 或 `Ctrl+W` 以新窗口登录，`t` 或 `Ctrl+T` 以新 tab 登录。

- `tssh` 不带参数启动可以批量登录服务器，若带 `-o RemoteCommand` 参数启动则可以批量执行指定的命令。支持执行指定命令之后进入交互式 shell，但 `Windows Terminal` 不支持分号 `;`，可以用 `|cat&&` 代替。举例：

  ```sh
  tssh -t -o RemoteCommand='ping -c3 trzsz.github.io ; bash -l'
  tssh -t -o RemoteCommand="ping -c3 trzsz.github.io |cat&& bash -l"
  ```

![tssh batch](https://trzsz.github.io/images/tssh_batch.gif)

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

- 支持类似 `expect` 的自动交互功能，在登录服务器之后，自动匹配服务器的输出，然后自动输入。

  ```
  Host auto
      #!! ExpectCount 2  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectTimeout 30  # 配置自动交互的超时时间（单位：秒），默认是 30 秒
      #!! ExpectPattern1 *assword  # 配置第一个自动交互的匹配表达式
      # 配置第一个自动输入（密文），这是由 tssh --enc-secret 编码得到的字符串，tssh 会自动发送 \r 回车
      #!! ExpectSendPass1 d7983b4a8ac204bd073ed04741913befd4fbf813ad405d7404cb7d779536f8b87e71106d7780b2
      #!! ExpectPattern2 hostname*$  # 配置第二个自动交互的匹配表达式
      #!! ExpectSendText2 echo tssh expect\r  # 配置第二个自动输入（明文），需要指定 \r 才会发送回车
      # 以上 ExpectSendPass? 和 ExpectSendText? 只要二选一即可，若都配置则 ExpectSendPass? 的优先级更高
  ```

- 在每个 `ExpectPattern?` 匹配之前，如果遇到可选的匹配则自动输入，用法如下：

  ```
  Host case
      #!! ExpectCount 1  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectPattern1 hostname*$  # 配置第一个自动交互的匹配表达式
      #!! ExpectSendText1 ssh xxx\r  # 配置第一个自动输入，也可以换成 ExpectSendPass1 然后配置密文
      #!! ExpectCaseSendText1 yes/no y\r  # 在 ExpectPattern1 匹配之前，若遇到 yes/no 则发送 y 并回车
      #!! ExpectCaseSendText1 y/n yes\r   # 在 ExpectPattern1 匹配之前，若遇到 y/n 则发送 yes 并回车
      #!! ExpectCaseSendPass1 token d7... # 在 ExpectPattern1 匹配之前，若遇到 token 则解码 d7... 并发送
  ```

- 在匹配到指定输出时，自动生成 `totp` 2FA 双因子验证码，然后自动输入，用法如下：

  ```
  Host totp
      #!! ExpectCount 2  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectPattern1 token:  # 配置第一个自动交互的匹配表达式
      #!! ExpectSendTotp1 xxxxx  # 配置 totp 的 secret（明文），一般可通过扫二维码获得
      #!! ExpectPattern2 token:  # 配置第二个自动交互的匹配表达式
      # 下面是运行 tssh --enc-secret 输入 totp 的 secret 得到的密文串
      #!! ExpectSendEncTotp2 821fe830270201c36cd1a869876a24453014ac2f1d2d3b056f3601ce9cc9a87023
  ```

- 在匹配到指定输出时，执行指定的命令获取动态密码，然后自动输入，用法如下：

  ```
  Host otp
      #!! ExpectCount 2  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectPattern1 token:  # 配置第一个自动交互的匹配表达式
      #!! ExpectSendOtp1 oathtool --totp -b xxxxx  # 配置获取动态密码的命令（明文）
      #!! ExpectPattern2 token:  # 配置第二个自动交互的匹配表达式
      # 下面是运行 tssh --enc-secret 输入命令 oathtool --totp -b xxxxx 得到的密文串
      #!! ExpectSendEncOtp2 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
  ```

- 可能有些服务器不支持连着发送数据，如输入 `1\r`，要求在 `1` 之后有一点延迟，然后再 `\r` 回车，则可以用 `\|` 间开。

  ```
  Host sleep
      #!! ExpectCount 2  # 配置自动交互的次数，默认是 0 即无自动交互
      #!! ExpectSleepMS 100  # 当要间开输入时，sleep 的毫秒数，默认 100ms
      #!! ExpectPattern1 x>  # 配置第一个自动交互的匹配表达式
      #!! ExpectSendText1 1\|\r  # 配置第一个自动输入，在发送 1 之后，先 sleep 100ms，再发送 \r 回车
      #!! ExpectPattern2 y>  # 配置第二个自动交互的匹配表达式
      #!! ExpectSendText2 \|1\|\|\r  # 先 sleep 100ms，然后发送 1，再 sleep 200ms，最后发送 \r 回车
  ```

- 有些服务器连密码也不支持连着发送，则需要配置 `ExpectPassSleep`，默认为 `no`，可配置为 `each` 或 `enter`：

  - 配置 `ExpectPassSleep each` 则每输入一个字符就 sleep 一小段时间，默认 100 毫秒，可配置 `ExpectSleepMS` 进行调整。
  - 配置 `ExpectPassSleep enter` 则只是在发送 `\r` 回车之前 sleep 一小段时间，默认 100 毫秒，可配置 `ExpectSleepMS` 进行调整。

- 如果不知道 `ExpectPattern2` 如何配置，可以先将 `ExpectCount` 配置为 `2`，然后使用 `tssh --debug` 登录，就会看到 `expect` 捕获到的输出，可以直接复制输出的最后部分来配置 `ExpectPattern2`。把 `2` 换成其他任意的数字也适用。

## 记住密码

- 推荐使用公钥认证登录，可参考 openssh 的文档，或者参考 tssh wiki [公钥认证登录](https://github.com/trzsz/trzsz-ssh/wiki/%E5%85%AC%E9%92%A5%E8%AE%A4%E8%AF%81%E7%99%BB%E5%BD%95)。

- 如果只能使用密码登录，建议至少设置一下配置文件的权限，如：

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/password ~/.ssh/config
  ```

- 下面配置 `test1` 和 `test2` 的密码是 `123456`，其他以 `test` 开头的密码是 `111111`：

  ```
  # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      # 下面是运行 tssh --enc-secret 输入密码 123456 得到的密文串，每次运行结果不同。
      #!! encPassword 756b17766f45bdc44c37f811db9990b0880318d5f00f6531b15e068ef1fde2666550

  # 如果配置在 ~/.ssh/password 中，则不需要考虑是否兼容标准 ssh
  Host test2
      # 下面是运行 tssh --enc-secret 输入密码 123456 得到的密文串，每次运行结果不同。
      encPassword 051a2f0fdc7d0d40794b845967df4c2d05b5eb0f25339021dc4e02a9d7620070654b

  # ~/.ssh/config 和 ~/.ssh/password 是支持通配符的，tssh 会使用第一个匹配到的值。
  # 这里希望 test2 使用区别于其他 test* 的密码，所以将 test* 放在了 test2 的后面。

  Host test*
      Password 111111  # 支持明文密码，但是推荐使用 tssh --enc-secret 简单加密一下。
  ```

- 如果记住密码后还是要求输入密码，可能是需要[记住答案](#%E8%AE%B0%E4%BD%8F%E7%AD%94%E6%A1%88)，可配置`encQuestionAnswer1`试试：

  ```
  Host test1
      # 下面是运行 tssh --enc-secret 输入密码 123456 得到的密文串，每次运行结果不同。
      #!! encQuestionAnswer1 756b17766f45bdc44c37f811db9990b0880318d5f00f6531b15e068ef1fde2666550
  ```

- 如果启用了 `ControlMaster` 多路复用，或者是在旧版本 `Warp` 终端，需要使用前面 `自动交互` 的方式实现记住密码的效果。配置方式请参考前面 `自动交互`，加上 `Ctrl` 前缀即可，如：

  ```
  Host ctrl
      #!! CtrlExpectCount 1  # 配置自动交互的次数，一般只要输入一次密码
      #!! CtrlExpectPattern1 *assword    # 配置密码提示语的匹配表达式
      #!! CtrlExpectSendPass1 d7983b...  # 配置 tssh --enc-secret 编码后的密码
  ```

- 支持记住私钥的`Passphrase`（ 推荐使用 `ssh-agent` ）。支持与 `IdentityFile` 一起配置, 支持使用私钥文件名代替 Host 别名设置通用密钥的 `Passphrase`。举例：

  ```
  # IdentityFile 和 Passphrase 一起配置，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      IdentityFile /path/to/id_rsa
      # 下面是运行 tssh --enc-secret 输入密码 123456 得到的密文串，每次运行结果不同。
      #!! encPassphrase 6f419911555b0cdc84549ae791ef69f654118d734bb4351de7e83163726ef46d176a

  # 在 ~/.ssh/config 中配置通用私钥 ~/.ssh/id_ed25519 对应的 Passphrase
  # 可以加上通配符 * 以避免 tssh 搜索和选择时，文件名出现在服务器列表中。
  Host id_ed25519*
      # 下面是运行 tssh --enc-secret 输入密码 111111 得到的密文串，每次运行结果不同。
      #!! encPassphrase 3a929328f2ab1be0ba3fccf29e8125f8e2dac6dab73c946605cf0bb8060b05f02a68

  # 在 ~/.ssh/password 中配置则不需要通配符*，也不会出现在服务器列表中。
  Host id_rsa
      Passphrase 111111  # 支持明文密码，但是推荐使用 tssh --enc-secret 简单加密一下。
  ```

- `记住密码`之后还提示输入密码？可能服务器的认证方式是 `keyboard interactive`，请参考下文`记住答案`。

## 记住答案

- 除了私钥和密码，还有一种登录方式，英文叫 keyboard interactive ，是服务器返回一些问题，客户端提供正确的答案就能登录，很多自定义的一次性密码就是利用这种方式实现的。

- 对于只有一个问题，且答案（密码）固定不变的，只要配置 `QuestionAnswer1` 即可。对于有多个问题的，可以按问题的序号进行配置，也可以按问题的 hex 编码进行配置。

- 使用 `tssh --debug` 登录，会输出问题的 hex 编码，从而知道该如何使用 hex 编码进行配置。配置举例：

  ```
  # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
  Host test1
      # 下面是运行 tssh --enc-secret 输入答案 `答案一` 得到的密文串，每次运行结果不同。
      encQuestionAnswer1 482de7690ccc5229299ccadd8de1cb7c6d842665f0dc92ff947a302f644817baecbab38601
  Host test2
      # 下面是运行 tssh --enc-secret 输入答案 `答案一` 得到的密文串，每次运行结果不同。
      encQuestionAnswer1 43e86f1140cf6d8c786248aad95a26f30633f1eab671676b0860ecb5b1a64fb3ec5212dddf
      QuestionAnswer2 答案二  # 支持明文答案，但是推荐使用 tssh --enc-secret 简单加密一下。
      QuestionAnswer3 答案三
  Host test3
      # 其中 `6e616d653a20` 是问题 `name: ` 的 hex 编码，`enc` 前缀代表配置的是密文串。
      # 下面是运行 tssh --enc-secret 输入答案 `my_name` 得到的密文串，每次运行结果不同。
      enc6e616d653a20 775f2523ab747384e1661aba7779011cb754b73f2e947672c7fd109607b801d70902d1
      636f64653a20 my_code  # 其中 `636f64653a20` 是问题 `code: ` 的 hex 编码, `my_code` 是明文答案
  ```

- 对于 `totp` 2FA 双因子验证码，则可以如下配置（同样支持按序号或 hex 编码进行配置）：

  ```
  Host totp
      TotpSecret1 xxxxx  # 按序号配置 totp 的 secret（明文），一般可通过扫二维码获得
      totp636f64653a20 xxxxx  # 按 `code: ` 的 hex 编码 `636f64653a20` 配置 totp 的 secret（明文）
      # 下面是运行 tssh --enc-secret 输入命令 xxxxx 得到的密文串，加上 `enc` 前缀进行配置
      encTotpSecret2 8ba828bd54ff694bc8c4619f802b5bed73232e60a680bbac05ba5626269a81a00b
      enctotp636f64653a20 8ba828bd54ff694bc8c4619f802b5bed73232e60a680bbac05ba5626269a81a00b
  ```

- 对于可以通过命令行获取到的动态密码，则可以如下配置（同样支持按序号或 hex 编码进行配置）：

  ```
  Host otp
      OtpCommand1 oathtool --totp -b xxxxx  # 按序号配置获取动态密码的命令
      otp636f64653a20 oathtool --totp -b xxxxx  # 按 `code: ` 的 hex 编码 `636f64653a20` 配置获取动态密码的命令
      # 下面是运行 tssh --enc-secret 输入命令 oathtool --totp -b xxxxx 得到的密文串，加上 `enc` 前缀进行配置
      encOtpCommand2 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
      encotp636f64653a20 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
  ```

- 可以自己实现获取动态密码的程序，指定 `%q` 参数可以得到问题内容，将动态密码输出到 stdout 并正常退出即可，调试信息可以输出到 stderr （ `tssh --debug` 运行时可以看到 ）。配置举例（序号代表第几个问题，一般只有一个问题，只需配置 `OtpCommand1` 即可）：

  ```
  Host custom_otp_command
      #!! OtpCommand1 /path/to/your_own_program %q
      #!! OtpCommand2 python C:\your_python_code.py %q
  ```

- 如果启用了 `ControlMaster` 多路复用，或者是在旧版本 `Warp` 终端，请参考前面 `自动交互` 加 `Ctrl` 前缀来实现。

  ```
  Host ctrl_totp
      #!! CtrlExpectCount 1  # 配置自动交互的次数
      #!! CtrlExpectPattern1 code:  # 配置密码提示语的匹配表达式（这里以 2FA 验证码举例）
      #!! CtrlExpectSendTotp1 xxxxx  # 配置 totp 的 secret（明文），一般可通过扫二维码获得
      #!! CtrlExpectSendEncTotp1 622ada31cf...  # 或者配置 tssh --enc-secret 得到的密文串

  Host ctrl_otp
      #!! CtrlExpectCount 1  # 配置自动交互的次数
      #!! CtrlExpectPattern1 token:  # 配置密码提示语的匹配表达式（这里以动态密码举例）
      #!! CtrlExpectSendOtp1 oathtool --totp -b xxxxx  # 配置获取动态密码的命令（明文）
      #!! CtrlExpectSendEncOtp1 77b4ce85d0...  # 或者配置 tssh --enc-secret 得到的密文串
  ```

## 个性配置

- 支持在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf`，Windows 是 `C:\Users\your_name\.tssh.conf` ）中进行以下自定义配置：

  ```
  # SSH 配置路径，默认为 ~/.ssh/config
  ConfigPath = ~/.ssh/config

  # 扩展配置路径，默认为 ~/.ssh/password
  ExConfigPath = ~/.ssh/password

  # trz 上传时，对话框打开的路径，为空时打开上次的路径， 默认为空
  DefaultUploadPath = ~/Downloads

  # tsz 下载时，自动保存的路径，为空时弹出对话框手工选择，默认为空
  DefaultDownloadPath = ~/Downloads

  # 全局的拖拽文件上传命令，注意 ~/.ssh/config 中配置的优先级更高
  DragFileUploadCommand = trz -y

  # trzsz 进度条将从第一种颜色渐变到第二种颜色。注意不要带 `#`。
  ProgressColorPair = B14FFF 00FFA3

  # tssh 搜索和选择服务器时，配置主题风格和自定义颜色
  PromptThemeLayout = simple
  PromptThemeColors = {"active_host": "magenta|bold", "inactive_host": "magenta"}

  # tssh 搜索和选择服务器时，每页显示的记录数，默认为 10
  PromptPageSize = 10

  # tssh 搜索和选择服务器时，默认是类似 vim 的 normal 模式，想默认进入搜索模式可如下配置：
  PromptDefaultMode = search

  # tssh 搜索和选择服务器时，详情中显示的配置列表，默认如下：
  PromptDetailItems = Alias Host Port User GroupLabels IdentityFile ProxyCommand ProxyJump RemoteCommand UdpMode TsshdPath

  # tssh 搜索和选择服务器时，可以自定义光标和选中的图标：
  PromptCursorIcon = 🧨
  PromptSelectedIcon = 🍺

  # 登录后自动设置终端标题，退出后不会重置，你需要参考下文在本地 shell 中设置 PROMPT_COMMAND
  SetTerminalTitle = Yes

  # 使用 `ssh -G` 解析 OpenSSH 配置，包括 `Match` 规则
  UseOpenSSHConfig = Yes
  ```

## 配置注释

- `tssh` 配置中的注释基本与 `openssh` 一致，额外做了一些扩展支持，详见下表：

  | 注释                  | openssh |  tssh  |
  | :-------------------- | :-----: | :----: |
  | `#` 开头的配置行      | 是注释  | 是注释 |
  | `#!!` 开头的配置行    | 是注释  | 非注释 |
  | `Key Value # Comment` | 看情况  | 是注释 |
  | `Key=Value # Comment` | 看情况  | 非注释 |

- `#` 开头的配置行，`openssh` 一律认为是注释；`tssh` 认为 `#!!` 开头的配置行不是注释，其他以 `#` 开头的配置行是注释。
- `Key Value # Comment` 配置（没有 `=` 号），`openssh` 有些情况认为 `#` 后的内容是注释，有些情况认为不是注释；`tssh` 一律认为 `#` 后的内容是注释。
- `Key=Value # Comment` 配置（有 `=` 号），`openssh` 有些情况认为 `#` 后的内容是注释，有些情况认为不是注释；`tssh` 一律认为 `#` 后的内容不是注释。

## Wayland 集成

- 在 `~/.ssh/config` 或 `ExConfigPath` 配置文件中，配置 `EnableWaypipe` 为 `Yes` 启用 Wayland (waypipe) 集成功能。

  ```
  Host xxx
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableWaypipe Yes
  ```

- 启用 Wayland (waypipe) 集成功能后，无需再显式使用 waypipe 程序，tssh 将在后台自动运行 waypipe 程序。

- 如果客户端 waypipe 程序在 PATH 路径下找不到，可以通过 `WaypipeClientPath` 配置指定 waypipe 程序的路径。

- 如果服务端 waypipe 程序在 PATH 路径下找不到，可以通过 `WaypipeServerPath` 配置指定 waypipe 程序的路径。

- 可以根据需要，通过 `WaypipeClientOption` 和 `WaypipeServerOption` 配置指定 waypipe 程序的一些参数，注意不要指定 `-s`、`--socket`、`--login-shell`、`--display`、`client`、`server` 这些参数，配置举例：

  ```
  Host xxx
    #!! EnableWaypipe Yes
    #!! WaypipeClientPath /usr/bin/waypipe
    #!! WaypipeServerPath /usr/bin/waypipe
    #!! WaypipeClientOption -c lz4
    #!! WaypipeServerOption -c lz4
  ```

## 剪贴板集成

- 在 `~/.ssh/config` 或 `ExConfigPath` 配置文件中，配置 `EnableOSC52` 为 `Yes` 启用剪贴板集成功能。

  ```
  Host *
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    EnableOSC52 Yes
  ```

- 启用剪贴板集成功能后，支持远程服务器通过 OSC52 序列写入本地剪贴板。

- 在 Linux 系统，剪贴板集成功能需要安装 `xclip` 或 `xsel` 命令。

## SSH 控制台

- `tssh` 控制台是类似 OpenSSH escape sequences 的功能，计划提供更友好、更强大的 SSH 控制功能。目前已支持的功能有：

  - 发送转义字符 '~' ( ~ : 相当于输入 `~`，可作为控制台误触发后的补救措施 )。
  - 暂停当前 SSH 进程 ( ^Z : 相当于 `Ctrl + Z`，不是作用于远程服务器上的进程，而是作用于 `tssh` 自身 )。
  - 退出当前 SSH 会话 ( . : 相当于 Exit / Kill，当因为网络等原因导致 `tssh` 卡死时，可通过此功能退出 )。

- 上面 `(` 与 ``:` 之间的字符是快捷键，兼容 OpenSSH escape sequences，例如回车后 `~.` 可以快速退出当前 SSH 会话。

- 可通过 `EscapeChar` 选项配置进入 SSH 控制台的转义字符（ 默认是 `~` ），只支持一个字符，或者 ^ 带一个字母，并且不能与其他快捷键冲突。

- 可通过 `ConsoleEscapeTime` 选项配置按下 `回车` 键后多少秒内按下 `~` 键即进入 SSH 控制台，默认值是 `1` 秒，可以配置为 `0` 禁用控制台功能：

  ```
  Host xxx
    EscapeChar ~
    #!! ConsoleEscapeTime 1
  ```

## 其他功能

- 使用 `-f` 后台运行时，可以加上 `--reconnect` 参数，在后台进程因连接断开等而退出时，会自动重新连接。

- 运行 `tssh --enc-secret`，输入密码或答案，可得到用于配置的密文（ 相同密码每次运行结果不同 ）。

  - 上文说的`记住密码`和`记住答案`等，在配置项前面加上 `enc` 则可以配置成密文，防止被人窥屏。
  - 如果密码中含有 `#` 等特殊字符，直接配置密码明文可能会导致登录失败，此时则必须使用密文配置。

  ```
  Host server2
    # 如果配置在 ~/.ssh/config 中，可以加上 `#!!` 前缀，以兼容标准 ssh
    encPassword de88c4dbdc95d85303682734e2397c4d8dd29bfff09ec53580f31dd40291fc8c7755
    encQuestionAnswer1 93956f6e7e9f2aef3af7d6a61f7046dddf14aa4bbd9845dbb836fe3782b62ac0d89f
  ```

- 运行 `tssh --new-host` 可以在 TUI 界面轻松添加 SSH 配置，并且完成后可以立即登录。

- 运行 `tssh --install-trzsz` 可以将 [trzsz](https://github.com/trzsz/trzsz-go) ( `trz` / `tsz` ) 安装到服务器上。

  - 默认安装到 `~/.local/bin/` 目录，可以通过 `--install-path /path/to/install` 指定安装目录。
  - 若 `--install-path` 安装目录含有 `~/`，则必须加上单引号，如`--install-path '~/path'`。
  - 若获取 `trzsz` 的最新版本号失败，可以通过 `--trzsz-version x.x.x` 参数自行指定。
  - 若下载 `trzsz` 的安装包失败，可以自行下载并通过 `--trzsz-bin-path /path/to/trzsz.tar.gz` 参数指定。
  - 注意：`--install-trzsz` 不支持 Windows 服务器，不支持跳板机（ 除非以 `ProxyJump` 跳过 ）。

- 运行 `tssh --install-tsshd` 可以将 [tsshd](https://github.com/trzsz/tsshd) 安装到服务器上。

  - 默认安装到 `~/.local/bin/` 目录，可以通过 `--install-path /path/to/install` 指定安装目录。
  - 若 `--install-path` 安装目录含有 `~/`，则必须加上单引号，如`--install-path '~/path'`。
  - 若获取 `tsshd` 的最新版本号失败，可以通过 `--tsshd-version x.x.x` 参数自行指定。
  - 若下载 `tsshd` 的安装包失败，可以自行下载并通过 `--tsshd-bin-path /path/to/tsshd.tar.gz` 参数指定。
  - 注意：`--install-tsshd` 不支持 Windows 服务器，不支持跳板机（ 除非以 `ProxyJump` 跳过 ）。

- 关于修改终端标题，其实无需 `tssh` 就能实现，只要在服务器的 shell 配置文件中（如`~/.bashrc`）配置：

  ```sh
  # 设置固定的服务器标题
  PROMPT_COMMAND='echo -ne "\033]0;固定的服务器标题\007"'

  # 根据环境变量动态变化的标题
  PROMPT_COMMAND='echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD}\007"'
  ```

  - 如果在 `$XDG_CONFIG_HOME/tssh/tssh.conf` ( 或 `~/.tssh.conf` ) 中设置了 `SetTerminalTitle = Yes`，则会在登录后自动设置终端标题，但是服务器上的 `PROMPT_COMMAND` 会覆盖 `tssh` 设置的标题。
  - 在 `tssh` 退出后不会重置为原来的标题，你需要在本地 shell 中设置 `PROMPT_COMMAND`，让它覆盖 `tssh` 设置的标题。

- 支持 DNS SRV，假设你家里有多台主机，但你只有一个公网 IP，你可以像下面这样设置 SRV 记录，并在 `~/.ssh/config` 中类似配置：

  ```sh
  $ dig +short _ssh._tcp.myhost.mydomain.com SRV
  1 1 22029 gateway.mydomain.com.
  ```

  ```
  Host xxx
    #!! DnsSrvName myhost.mydomain.com
  ```

## UDP 模式

- 在服务器上安装 [tsshd](https://github.com/trzsz/tsshd?tab=readme-ov-file#installation)，使用 `tssh --udp xxx` 登录服务器（对延迟敏感可指定 `--kcp` 选项），或者在 `~/.ssh/config` 中如下配置以省略 `--udp` 或 `--kcp` 选项：

  ```
  Host xxx
      #!! UdpMode  ( Yes | QUIC | KCP )
  ```

- `tssh` 在客户端扮演 `ssh` 的角色，`tsshd` 在服务端扮演 `sshd` 的角色。

- `tssh` 会先作为一个 ssh 客户端正常登录到服务器上，然后在服务器上启动一个 `tsshd` 进程（每次登录都是一个独立的 `tsshd` 进程）。

- `tsshd` 进程会随机侦听一个 61001 到 61999 之间的 UDP 端口（可通过 `TsshdPort` 配置自定义），并将其端口和几个密钥通过 ssh 通道发回给 `tssh` 进程。登录的 ssh 连接会被关闭，然后 `tssh` 进程通过 UDP 与 `tsshd` 进程通讯。

## UDP 配置

```
Host xxx
    #!! UdpMode Yes
    #!! TsshdPort 61001-61999
    #!! TsshdPath ~/go/bin/tsshd
    #!! UdpAliveTimeout 86400
    #!! UdpHeartbeatTimeout 3
    #!! UdpReconnectTimeout 15
    #!! ShowNotificationOnTop yes
    #!! ShowFullNotifications yes
    #!! UdpProxyMode UDP
    #!! UdpMTU 1400
```

- `UdpMode`: `No` (默认为`No`: tssh 工作在 TCP 模式), `Yes` (默认协议: `QUIC`), `QUIC` ([QUIC](https://github.com/quic-go/quic-go) 协议：速度更快), `KCP` ([KCP](https://github.com/xtaci/kcp-go) 协议：延迟更低).

- `TsshdPort`: 指定 tsshd 监听的端口范围，默认值为 [61001, 61999]。支持指定离散的端口列表(如`6022,7022`)，也支持指定离散的端口范围(如`8010-8020,9020-9030,10080`)，tsshd 会随机监听其中一个空闲的端口。也可在命令行中使用 `--tsshd-port` 指定端口。

- `TsshdPath`: 指定服务器上 tsshd 二进制程序的路径，如果未配置，则在 $PATH 中查找。也可在命令行中使用 `--tsshd-path` 指定路径。

- `UdpAliveTimeout`: 如果断开连接的时间超过 `UdpAliveTimeout` 秒，tssh 和 tsshd 都会退出，不再支持重连。默认值为 86400 秒。

- `UdpHeartbeatTimeout`: 如果断开连接的时间超过 `UdpHeartbeatTimeout` 秒，tssh 将会尝试换条路重新连到服务器。默认值为 3 秒。

- `UdpReconnectTimeout`: 如果断开连接的时间超过 `UdpReconnectTimeout` 秒，tssh 将会显示失去连接的通知公告。默认值为 15 秒。

- `ShowNotificationOnTop`: 是否在屏幕顶部显示失去连接的通知。默认为 yes，这可能会覆盖之前的一些输出。设置为 `No` 在光标当前行显示通知。

- `ShowFullNotifications`: 是显示完整的通知，还是显示简短的通知。默认为 yes，这可能会输出几行通知到屏幕上。设置为 `No` 只输出一行通知。

- `UdpProxyMode`: 默认使用 `UDP` 协议进行传输。如果所在的网络环境有防火墙禁止了 `UDP` 流量，可以配置为 `TCP` 以绕过防火墙限制，但这可能会带来额外的延迟。

- `UdpMTU`: 设置 UDP 数据包的最大传输单元（MTU），默认值为 1400。

## UDP 端口转发

使用 UDP 模式时，支持 UDP 端口转发。

- 命令行 UDP 端口转发，扩展 `-L` / `-R` 参数，增加 `udp/` 前缀 ( 其中 `/` 可以换成 `:`、`_` 或 `-` )：

  ```
  -L udp/[bind_address:]port:host:hostport
  -L udp:[bind_address:]port:/remote_socket
  -L udp_/local_socket:host:hostport
  -L udp-/local_socket:/remote_socket

  -R udp/[bind_address:]port:host:hostport
  -R udp:[bind_address:]port:/local_socket
  -R udp_/remote_socket:host:hostport
  -R udp-/remote_socket:/local_socket
  ```

- 配置文件 UDP 端口转发，类似 `LocalForward` 和 `RemoteForward`，增加 `UDP` 前缀 (不区分大小写)：

  ```
  UdpLocalForward [bind_address:]port host:hostport
  UdpLocalForward [bind_address:]port /remote_socket
  UdpLocalForward /local_socket host:hostport
  UdpLocalForward /local_socket /remote_socket

  UdpRemoteForward [bind_address:]port host:hostport
  UdpRemoteForward [bind_address:]port /local_socket
  UdpRemoteForward /remote_socket host:hostport
  UdpRemoteForward /remote_socket /local_socket
  ```

- `ForwardUdpTimeout`: 设置 UDP 转发会话的空闲超时时间。在指定时间内无数据收发时将自动清理对应的转发会话以释放资源。默认 5 分钟。

## 故障排除

- 在旧版本 Warp 终端，分块 Blocks 的功能需要将 `tssh` 重命名为 `ssh`，推荐建个软链接（ 对更新友好 ）：

  ```
  sudo ln -sv $(which tssh) /usr/local/bin/ssh
  ```

  - 软链后，`ssh -V` 应输出 `trzsz ssh` 加版本号，如果不是，说明软链不成功，或者在 `PATH` 中 `openssh` 的优先级更高，你要软链到另一个地方或者调整 `PATH` 的优先级。

  - 为了让 `tssh` 搜索登录也支持分块 Blocks 功能，需要在 `~/.bash_profile` ( bash ) 或 `~/.zshrc` ( zsh ) 中建一个 `tssh` 函数：

    ```sh
    tssh() {
        if [ $# -eq 0 ]; then
            ssh FAKE_DEST_IN_WARP
        else
            ssh "$@"
        fi
    }
    ```

  - `--dragfile` 参数可能会让 Warp 分块功能失效，请参考前文配置 `EnableDragFile` 来启用拖拽功能。

- 在 Warp 终端，拖拽文件或目录进入 Warp 终端后，可能不会立即触发上传，需要多按一次`回车`键，才会上传。

- 如果你在使用 Windows7 或者旧版本的 Windows10 等，遇到 `enable virtual terminal failed` 的错误。

  - 可以尝试在 [Cygwin](https://www.cygwin.com/)、[MSYS2](https://www.msys2.org/) 或 [Git Bash](https://www.atlassian.com/git/tutorials/git-bash) 内使用 `tssh`。

  - 从 `v0.1.21` 起，默认的 Windows 版本不再支持 Windows7，需要在 [Releases](https://github.com/trzsz/trzsz-ssh/releases) 中下载带有 `win7` 关键字的版本来使用。

- 如果在 `~/.ssh/config` 中配置了 `tssh` 特有的配置项后，标准 `ssh` 报错 `Bad configuration option`。

  - 可以在出错配置项中加上前缀 `#!!`，标准 `ssh` 会将它当作注释，而 `tssh` 则会认为它是有效配置之一。

## 联系方式

有什么问题可以发邮件给作者 <lonnywong@qq.com>，也可以提 [Issues](https://github.com/trzsz/trzsz-ssh/issues) 。欢迎加入 QQ 群：318578930。

## 赞助打赏

[❤️ 赞助 trzsz ❤️](https://github.com/trzsz)，请作者喝杯咖啡 ☕ ? 谢谢您们的支持！
