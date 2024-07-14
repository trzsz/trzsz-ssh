# trzsz-ssh ( tssh ) - an openssh client alternative

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/trzsz-ssh)](https://github.com/trzsz/trzsz-ssh/releases)
[![WebSite](https://img.shields.io/badge/WebSite-https%3A%2F%2Ftrzsz.github.io%2Fssh-blue?style=flat)](https://trzsz.github.io/ssh)
[![中文文档](https://img.shields.io/badge/%E4%B8%AD%E6%96%87%E6%96%87%E6%A1%A3-https%3A%2F%2Ftrzsz.github.io%2Fcn%2Fssh-blue?style=flat)](https://trzsz.github.io/cn/ssh)

trzsz-ssh ( tssh ) is an ssh client designed as a drop-in replacement for the openssh client. It aims to provide complete compatibility with openssh, mirroring all its features, while also offering additional useful features not found in the openssh client.

## Basic Features

trzsz-ssh ( tssh ) works exactly like the openssh client. The following common features have been implemented:

|    Features    |                                                  Support Options                                                   |
| :------------: | :----------------------------------------------------------------------------------------------------------------: |
|     Cipher     |                                                   `-c` `Ciphers`                                                   |
|   Pseudo TTY   |                                               `-t` `-T` `RequestTTY`                                               |
|    Network     |                                             `-4` `-6` `AddressFamily`                                              |
|   SSH Proxy    |                                        `-J` `-W` `ProxyJump` `ProxyCommand`                                        |
|  Multiplexing  |                                   `ControlMaster` `ControlPath` `ControlPersist`                                   |
|    Command     |                               `RemoteCommand`, `LocalCommand`, `PermitLocalCommand`                                |
|   SSH Agent    |                              `-a` `-A` `ForwardAgent` `IdentityAgent` `SSH_AUTH_SOCK`                              |
|  X11 Forward   |                        `-x` `-X` `-Y` `ForwardX11` `ForwardX11Trusted` `ForwardX11Timeout`                         |
|  Known Hosts   |                        `UserKnownHostsFile` `GlobalKnownHostsFile` `StrictHostKeyChecking`                         |
|  Basic Login   |                   `-l` `-p` `-i` `-F` `HostName` `Port` `User` `IdentityFile` `SendEnv` `SetEnv`                   |
| Authentication |                   `PubkeyAuthentication` `PasswordAuthentication` `KbdInteractiveAuthentication`                   |
|  Port Forward  | `-g` `-f` `-N` `-L` `-R` `-D` `LocalForward` `RemoteForward` `DynamicForward` `GatewayPorts` `ClearAllForwardings` |

## Extra Features

trzsz-ssh ( tssh ) offers additional useful features:

|                           English                           |                                   中文                                   |
| :---------------------------------------------------------: | :----------------------------------------------------------------------: |
|          [Login Prompt](README.en.md#login-prompt)          |      [登录界面](README.cn.md#%E7%99%BB%E5%BD%95%E7%95%8C%E9%9D%A2)       |
|          [Custom Theme](README.en.md#custom-theme)          |      [主题风格](README.cn.md#%E4%B8%BB%E9%A2%98%E9%A3%8E%E6%A0%BC)       |
|      [trzsz ( trz / tsz )](README.en.md#support-trzsz)      |       [trzsz ( trz / tsz )](README.cn.md#%E6%94%AF%E6%8C%81-trzsz)       |
|      [zmodem ( rz / sz )](README.en.md#support-zmodem)      |       [zmodem ( rz / sz )](README.cn.md#%E6%94%AF%E6%8C%81-zmodem)       |
|           [Batch Login](README.en.md#batch-login)           |      [批量登录](README.cn.md#%E6%89%B9%E9%87%8F%E7%99%BB%E5%BD%95)       |
|          [Group Labels](README.en.md#group-labels)          |      [分组标签](README.cn.md#%E5%88%86%E7%BB%84%E6%A0%87%E7%AD%BE)       |
| [Automated Interaction](README.en.md#automated-interaction) |      [自动交互](README.cn.md#%E8%87%AA%E5%8A%A8%E4%BA%A4%E4%BA%92)       |
|     [Remember Password](README.en.md#remember-password)     |      [记住密码](README.cn.md#%E8%AE%B0%E4%BD%8F%E5%AF%86%E7%A0%81)       |
|  [Custom Configuration](README.en.md#custom-configuration)  |      [个性配置](README.cn.md#%E4%B8%AA%E6%80%A7%E9%85%8D%E7%BD%AE)       |
|    [Comments of Config](README.en.md#comments-of-config)    |      [配置注释](README.cn.md#%E9%85%8D%E7%BD%AE%E6%B3%A8%E9%87%8A)       |
| [Clipboard Integration](README.en.md#clipboard-integration) | [剪贴板集成](README.cn.md#%E5%89%AA%E8%B4%B4%E6%9D%BF%E9%9B%86%E6%88%90) |
|        [Other Features](README.en.md#other-features)        |      [其他功能](README.cn.md#%E5%85%B6%E4%BB%96%E5%8A%9F%E8%83%BD)       |
|              [UDP Mode](README.en.md#udp-mode)              |             [UDP 模式](README.cn.md#udp-%E6%A8%A1%E5%BC%8F)              |

## Installation

- Install with [scoop](https://scoop.sh/) / [winget](https://learn.microsoft.com/en-us/windows/package-manager/winget/) / [choco](https://community.chocolatey.org/) on Windows

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

- Install with [homebrew](https://brew.sh/) on MacOS

  <details><summary><code>brew install trzsz-ssh</code></summary>

  ```sh
  brew update
  brew install trzsz-ssh
  ```

  </details>

- Install with apt on Ubuntu

  <details><summary><code>sudo apt install tssh</code></summary>

  ```sh
  sudo apt update && sudo apt install software-properties-common
  sudo add-apt-repository ppa:trzsz/ppa && sudo apt update

  sudo apt install tssh
  ```

  </details>

- Install with apt on Debian

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

- Install with yum on Linux

  <details><summary><code>sudo yum install tssh</code></summary>

  - Install with [gemfury](https://gemfury.com/) repository.

    ```sh
    echo '[trzsz]
    name=Trzsz Repo
    baseurl=https://yum.fury.io/trzsz/
    enabled=1
    gpgcheck=0' | sudo tee /etc/yum.repos.d/trzsz.repo

    sudo yum install tssh
    ```

  - Install with [wlnmp](https://www.wlnmp.com/install) repository. It's not necessary to configure the epel repository for tssh.

    ```sh
    curl -fsSL "https://sh.wlnmp.com/wlnmp.sh" | bash

    sudo yum install tssh
    ```

  </details>

- Install with [yay](https://github.com/Jguer/yay) on ArchLinux

  <details><summary><code>yay -S tssh</code></summary>

  ```sh
  yay -Syu
  yay -S tssh
  ```

  </details>

- Install with Go ( Requires go 1.21 or later )

  <details><summary><code>go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest</code></summary>

  ```sh
  go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest
  ```

  The binaries are usually located in ~/go/bin/ ( C:\Users\your_name\go\bin\ on Windows ).

  </details>

- Build from source ( Requires go 1.21 or later )

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/trzsz-ssh.git
  cd trzsz-ssh
  make
  sudo make install
  ```

  </details>

- Download from the [GitHub Releases](https://github.com/trzsz/trzsz-ssh/releases), unzip and add to `PATH` environment.

## Development

The `github.com/trzsz/trzsz-ssh/tssh` can be used as a library, for example:

```go
package main

import (
	"log"
	"os"

	"github.com/trzsz/trzsz-ssh/tssh"
)

func main() {
	// Example 1: execute command on remote server
	client, err := tssh.SshLogin(&tssh.SshArgs{Destination: "root@192.168.0.1"})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	output, err := session.CombinedOutput("whoami")
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("I'm %s", string(output))

	// Example 2: run the tssh program
	code := tssh.TsshMain([]string{"-t", "root@192.168.0.1", "bash -l"})
	os.Exit(code)
}
```

## Contributing

Welcome and thank you for considering contributing. We appreciate all forms of support, from coding and testing to documentation and CI/CD improvements.

- Fork and clone the repository `https://github.com/trzsz/trzsz-ssh.git`.

- Make your changes just ensure that the unit tests `go test ./tssh` pass.

- Build the binary `go build -o ./bin/ ./cmd/tssh` and test it `./bin/tssh`.

- Once you are happy with your changes, please submit a pull request.

## Screenshot

![tssh tiny](https://trzsz.github.io/images/tssh_tiny.gif)

![tssh simple](https://trzsz.github.io/images/tssh_simple.gif)

![tssh table](https://trzsz.github.io/images/tssh_table.gif)

![tssh trzsz](https://trzsz.github.io/images/tssh_trzsz.gif)

![tssh batch](https://trzsz.github.io/images/tssh_batch.gif)

## Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/trzsz-ssh/issues). Welcome to join the QQ group: 318578930.

## Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
