# trzsz-ssh ( tssh )

An ssh client that supports [trzsz](https://trzsz.github.io/), supports searching and selecting servers for batch login.

Website: [https://trzsz.github.io/ssh](https://trzsz.github.io/ssh) ( English ) 　中文文档：[https://trzsz.github.io/cn/ssh](https://trzsz.github.io/cn/ssh)

[![MIT License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://choosealicense.com/licenses/mit/)
[![GitHub Release](https://img.shields.io/github/v/release/trzsz/trzsz-ssh)](https://github.com/trzsz/trzsz-ssh/releases)

## Introduce

- Does your favorite ssh terminal have server management feature? Does it support remembering password? Does it have a cool file transfer tool?

- tssh supports selecting or searching servers configured in `~/.ssh/config`, supports vim operation habit, provides a server management solution.

- tssh supports selecting multiple servers, logging in to them in batches, and executing pre-specified commands in batches.

- tssh supports configuring server login password, solves the trouble of entering password each time ( It's recommended to use the public key to login ).

- tssh supports [trzsz](https://trzsz.github.io/) ( trz / tsz ) natively, solved the issue of slow upload speeds while using `trzsz ssh` in Windows.

- _On the author's MacOS, the upload speed using `trzsz ssh` is about 10 MB/s, while using `tssh` can reach over 80 MB/s._

## Installation

**_Here is how to install `trzsz-ssh (tssh)` on the client side (choose one):_**

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

- Install with Go ( Requires go 1.20 or later )

  <details><summary><code>go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest</code></summary>

  ```sh
  go install github.com/trzsz/trzsz-ssh/cmd/tssh@latest
  ```

  The binaries are usually located in ~/go/bin/ ( C:\Users\your_name\go\bin\ on Windows ).

  </details>

- Build from source ( Requires go 1.20 or later )

  <details><summary><code>sudo make install</code></summary>

  ```sh
  git clone --depth 1 https://github.com/trzsz/trzsz-ssh.git
  cd trzsz-ssh
  make
  sudo make install
  ```

  </details>

- Download from the [Releases](https://github.com/trzsz/trzsz-ssh/releases)

**_[trzsz](https://trzsz.github.io/) needs to be installed on the server to use `trz / tsz` for uploading and downloading files._**

_Choose either the [Go version](https://trzsz.github.io/go) ( ⭐ Recommended ), [Py version](https://trzsz.github.io/), or [Js version](https://trzsz.github.io/js)._

_If trzsz is not installed on the server, you can still use `tssh`, but can't use `trz / tsz` for uploading and downloading._

## How to use

_`~/` represents the HOME directory. Please replace `~/` below with `C:\Users\your_name\` on Windows._

- Generate a key pair on the client, generally stored in `~/.ssh/` ( choose one of the following ):

  - `ssh-keygen -t ed25519` generates a ED25519 key pair, private key `~/.ssh/id_ed25519`, public key `~/.ssh/id_ed25519.pub`.
  - `ssh-keygen -t rsa -b 4096` generates a RSA key pair, private key `~/.ssh/id_rsa`, public key `~/.ssh/id_rsa.pub`.

- Append the public key to the `~/.ssh/authorized_keys` file on the server, and set the correct permissions:

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys
  ```

- Configure the `~/.ssh/config` file on the client, for example:

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

- Use `tssh` command to log in to the server, `tssh alias1` command to log in to the server corresponding to `alias1` in `~/.ssh/config`.

- Execute the `tssh` command without arguments, you can select or search the configured servers in `~/.ssh/config` to log in.

## Batch Login

- tssh supports selecting multiple servers in `iTerm2`( Requires [Python API](https://iterm2.com/python-api-auth.html), no need to `Allow all apps to connect` ),`tmux` and `Windows Terminal`, logging in to them in batches, and executing pre-specified commands in batches.

- Press `Space`, `Ctrl+X` to toggle select the current server. If it cannot be selected, it means that the current terminal is not supported yet. Please run `tmux` first.

- Press `Ctrl+P` will split panes for batch login, `Ctrl+W` will open new windows for batch login, and `Ctrl+T` will open new tabs for batch login.

- Execute the `tssh` command without arguments, you can log in to servers in batches. And you can specify the commands to be executed in batches by `-o RemoteCommand`. And you can switch to an interactive shell after executing the specified command. `Windows Terminal` does not support semicolon `;`, you can use `|cat&&` instead. For example:

  ```sh
  tssh -t -o RemoteCommand='ping -c3 trzsz.github.io ; bash'
  tssh -t -o RemoteCommand="ping -c3 trzsz.github.io |cat&& bash"
  ```

## Group Labels

- If there are a lot of servers, `GroupLabels` can be used to quickly find the target server when searching by `/`.

- After press `/` and search for a group label, press `Enter` to lock it. You can search for another group label by pressing `/` again, and press `Enter` to lock it too.

- In non-search mode, press `E` to erase the current search group labels. In search mode, press `Ctrl + E` to have the same effect.

- Supports configuring multiple group labels separated by spaces in one `GroupLabels`. Supports configuring multiple `GroupLabels`.

- Supports configuring group labels on multiple Host nodes in the form of wildcard \*, and `tssh` will summarize all the group labels.

  ```
  # The following testAA has group labels group1 group2 label3 label4 group5. Add `#!!` prefix to be compatible with openssh.
  Host test*
      #!! GroupLabels group1 group2
      #!! GroupLabels label3
  Host testAA
      #!! GroupLabels label4 group5
  ```

## Automated Interaction

- Supports automated interaction feature similar to `expect`. After logging into the server, it automatically matches the server's output and then enters input accordingly.

  ```
  Host auto
      #!! ExpectCount 5  # Configures the number of automated interactions, default is 0 which means no automated interaction
      #!! ExpectTimeout 30  # Configures the timeout for automated interaction (in seconds), default is 30 seconds
      #!! ExpectPattern1 *assword  # Configures the first automated interaction match expression
      # Configures the first automated input (encrypted). It was encoded by `tssh --enc-secret`, `tssh` will send \r (enter) automatically
      #!! ExpectSendPass1 d7983b4a8ac204bd073ed04741913befd4fbf813ad405d7404cb7d779536f8b87e71106d7780b2
      #!! ExpectPattern2 hostname*$  # Configures the second automated interaction match expression
      #!! ExpectSendText2 echo tssh expect\r  # Configures the second automated input (plaintext), specify \r to send enter
      # Choose either ExpectSendPass? or ExpectSendText? for each interaction; if both are configured, ExpectSendPass? has higher priority
      # --------------------------------------------------
      # Before each ExpectPattern match, one or multiple optional matches can be configured as follows:
      #!! ExpectPattern3 hostname*$  # Configures the third automated interaction match expression
      #!! ExpectSendText3 ssh xxx\r  # Configures the third automated input, can also use ExpectSendPass3 then configure with encrypted text
      #!! ExpectCaseSendText3 yes/no y\r  # Before matching ExpectPattern3, if encountering yes/no, then send y and enter
      #!! ExpectCaseSendText3 y/n yes\r   # Before matching ExpectPattern3, if encountering y/n, then send yes and enter
      #!! ExpectCaseSendPass3 token d7... # Before matching ExpectPattern3, if encountering token, then decode d7... and send
      # --------------------------------------------------
      #!! ExpectPattern4 token:  # Configures the fourth automated interaction match expression (one-time password)
      #!! ExpectSendOtp4 oathtool --totp -b xxxxx  # Configure the command line to obtain the one-time password
      #!! ExpectPattern5 token:  # Configures the fifth automated interaction match expression (one-time password)
      # The following ciphertext was generated by encoding `oathtool --totp -b xxxxx` with `tssh --enc-secret`.
      #!! ExpectSendEncOtp5 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
  ```

  - Login using `tssh --debug` if `ExpectCount` is greater than `0`, you can see the output captured by `expect`.

## Remember Password

- In order to be compatible with openssh, the password can be configured separately in `~/.ssh/password`, or you can add `#!!` prefix in `~/.ssh/config`.

- It's recommended to use the public key authentication. If you have to use the password authentication, it's recommended to set the permissions:

  ```sh
  chmod 700 ~/.ssh && chmod 600 ~/.ssh/password ~/.ssh/config
  ```

- The passwords configured below for `test1` and `test2` are `123456`, and the passwords for other aliases starting with `test` are `111111`:

  ```
  # If configured in ~/.ssh/config, you can add `#!!` prefix to be compatible with openssh.
  Host test1
      # The following ciphertext was generated by encoding `123456` with `tssh --enc-secret`.
      #!! encPassword 756b17766f45bdc44c37f811db9990b0880318d5f00f6531b15e068ef1fde2666550

  # If configured in ~/.ssh/password, there is no need to consider whether it's compatible with openssh.
  Host test2
      # The following ciphertext was generated by encoding `123456` with `tssh --enc-secret`.
      encPassword 051a2f0fdc7d0d40794b845967df4c2d05b5eb0f25339021dc4e02a9d7620070654b

  # ~/.ssh/config and ~/.ssh/password support wildcards, and tssh will use the first matched value.
  # Here we want test2 to use a different password from other test*, so we put test* behind test2.

  Host test*
      Password 111111  # supports plain text, but it is recommended to encrypt with `tssh --enc-secret`.
  ```

- - If `ControlMaster` multiplexing is enabled or using `Warp` terminal, you will need to use the `Automated Interaction` mentioned earlier to achieve remembering password. Please refer to the earlier `Automated Interaction` section, simply add a `Ctrl` prefix as follows:

  ```
  Host ctrl
      #!! CtrlExpectCount 1  # Configure the number of automated interactions, typically only requires entering the password once
      #!! CtrlExpectPattern1 *assword    # Configure the matching expression for the password prompt
      #!! CtrlExpectSendPass1 d7983b...  # Configure the password encoded by `tssh --enc-secret`
  ```

- Support remember `Passphrase` for private keys ( It's recommended to use `ssh-agent` ). Support configuring `Passphrase` together with `IdentityFile`. Support configuring `Passphrase` using private key filename instead of host alias. For example:

  ```
  # Configuring Passphrase together with IdentityFile. Add `#!!` prefix to be compatible with openssh.
  Host test1
      IdentityFile /path/to/id_rsa
      # The following ciphertext was generated by encoding `123456` with `tssh --enc-secret`.
      #!! encPassphrase 6f419911555b0cdc84549ae791ef69f654118d734bb4351de7e83163726ef46d176a

  # Configure the Passphrase corresponding to the private key ~/.ssh/id_ed25519 in ~/.ssh/config
  # The wildcard * can be added to prevent the filename from appearing in the tssh server list.
  Host id_ed25519*
      # The following ciphertext was generated by encoding `111111` with `tssh --enc-secret`.
      #!! encPassphrase 3a929328f2ab1be0ba3fccf29e8125f8e2dac6dab73c946605cf0bb8060b05f02a68

  # If configured in ~/.ssh/password, the wildcard * is not required and will not appear in the server list.
  Host id_rsa
      Passphrase 111111  # supports plain text, but it is recommended to encrypt with `tssh --enc-secret`.
  ```

## Remember Answers

- In addition, there is a keyboard interactive authentication. The server returns some questions, and log in by providing the correct answers. Many custom one-time passwords are implemented by it.

- For those with one question and a fixed answer, just configure `QuestionAnswer1`. For those with multiple questions, the answer to each question can be configured by serial number, or by the hex code of the question.

- Login with `tssh --debug`, the hex code of the questions will be output, so that you will know how to configure with the hex code. For example:

  ```
  # If configured in ~/.ssh/config, add `#!!` prefix to be compatible with openssh.
  Host test1
      # The following ciphertext was generated by encoding `TheAnswer1` with `tssh --enc-secret`.
      encQuestionAnswer1 4f6b79d0e4e48fc56ee29c61bd19559a322cd07f7d27f2a7f33978671be1b522d549252b22ee
  Host test2
      # The following ciphertext was generated by encoding `TheAnswer1` with `tssh --enc-secret`.
      encQuestionAnswer1 09d6936c104f7bbd62e3b4dc43d746496a368776b85d37b1ce8cecc2ace1b920af0ca5a1812b
      QuestionAnswer2 TheAnswer2  # supports plain text, but it is recommended to encrypt with `tssh --enc-secret`.
      QuestionAnswer3 TheAnswer3
  Host test3
      # The `6e616d653a20` is the hex code of `name: `, the `enc` prefix indicates that it's ciphertext.
      # The following ciphertext was generated by encoding `my_name` with `tssh --enc-secret`.
      enc6e616d653a20 775f2523ab747384e1661aba7779011cb754b73f2e947672c7fd109607b801d70902d1
      636f64653a20 my_code  # The `636f64653a20` is the hex code of `code: `, `my_code` is plain answer.
  ```

- For one-time password that can be obtained by the command line, you can configure them as follows (configure by serial number or hex code of the question):

  ```
  Host otp
      OtpCommand1 oathtool --totp -b xxxxx  # Configure the command line to obtain the one-time password by serial number
      otp636f64653a20 oathtool --totp -b xxxxx  # Configure the command line by the hex code of the question `code: ` that is `636f64653a20`
      # The following ciphertext was generated by encoding `oathtool --totp -b xxxxx` with `tssh --enc-secret`. Add the `enc` prefix for configuration.
      encOtpCommand2 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
      encotp636f64653a20 77b4ce85d087b39909e563efb165659b22b9ea700a537f1258bdf56ce6fdd6ea70bc7591ea5c01918537a65433133bc0bd5ed3e4
  ```

- If `ControlMaster` multiplexing is enabled or using `Warp` terminal, you will need to use the `Automated Interaction` mentioned earlier to achieve remembering answers.

  ```
  Host ctrl_otp
      #!! CtrlExpectCount 1  # Configure the number of automated interactions, typically only requires entering the password once
      #!! CtrlExpectPattern1 token:  # Configure the matching expression for the password prompt (one-time password)
      #!! CtrlExpectSendOtp1 oathtool --totp -b xxxxx  # Configure the command line to obtain the one-time password
      #!! CtrlExpectSendEncOtp1 77b4ce85d0...  # Or configure the encrypted command line encoded using `tssh --enc-secret`
  ```

## Configuration

- The following custom configurations are supported in `~/.tssh.conf` (`C:\Users\your_name\.tssh.conf` on Windows):

  ```
  # SSH configuration path, the default is ~/.ssh/config
  ConfigPath = ~/.ssh/config

  # Extended configuration path, the default is ~/.ssh/password
  ExConfigPath = ~/.ssh/password

  # The default path of the file dialog for trz uploading, the default is empty which opening the last path.
  DefaultUploadPath = ~/Downloads

  # The automatically save path for tsz downloading, the default is empty which poping up a folder dialog.
  DefaultDownloadPath = ~/Downloads

  # When searching and selecting servers with tssh, the number of records displayed on each page, the default is 10.
  PromptPageSize = 10

  # When searching and selecting servers with tssh, default is normal mode similar to vim. Configure to search mode as follows:
  PromptDefaultMode = search

  # When searching and selecting servers with tssh, the items displayed in details. The default is as follows:
  PromptDetailItems = Alias Host Port User GroupLabels IdentityFile ProxyCommand ProxyJump RemoteCommand

  # When searching and selecting servers with tssh, you can customize the cursor and selected icon:
  PromptCursorIcon = 🧨
  PromptSelectedIcon = 🍺

  # Auto set terminal title after login. It will not be reset after exiting. Please set PROMPT_COMMAND in local shell.
  SetTerminalTitle = Yes
  ```

## Other Features

- Use `-f` to run in the background, you can add `--reconnect`, it will automatically reconnect when the background process exits.

- Use `--dragfile` to enable the drag and drop to upload feature. If you want to enable it by default, you can configure it in `~/.ssh/config` or in the extended configuration `ExConfigPath`:

  ```
  Host *
    # If configured in ~/.ssh/config, add `#!!` prefix to be compatible with openssh.
    EnableDragFile Yes
  ```

- Use `--zmodem` to enable the `rz / sz` feature. If you want to enable it by default, you can configure it in `~/.ssh/config` or in the extended configuration `ExConfigPath`:

  ```
  Host server0
    # If configured in ~/.ssh/config, add `#!!` prefix to be compatible with openssh.
    EnableZmodem Yes
  ```

  - `lrzsz` needs to be installed on the client ( local computer ). For Windows, you can download and unzip it from [lrzsz-win32](https://github.com/trzsz/lrzsz-win32/releases) and add it to `PATH`, or install it as follows:

    ```
    scoop install https://trzsz.github.io/lrzsz.json

    choco install lrzsz --version=0.12.21
    ```

  - About the progress, the transferred and speed are not precise. It just indicating that the transfer is in progress.

- Use `-oEnableTrzsz=No` to disable the trzsz feature. If you want to disable it by default, you can configure it in `~/.ssh/config` or in the extended configuration `ExConfigPath`:

  ```
  Host server1
    # If configured in ~/.ssh/config, add `#!!` prefix to be compatible with openssh.
    EnableTrzsz No
  ```

- For the "remember password" and "remember answer" mentioned above, add `enc` in front of the configuration item, you can configure the ciphertext to prevent people from snooping on the screen. Cipher text can solve the issue of passwords containing `#` too.

  Run `tssh --enc-secret`, enter the plaintext of the password or answer, and you can get the ciphertext used for configuration (the same password will have different encryption results each time):

  ```
  Host server2
    # If configured in ~/.ssh/config, add `#!!` prefix to be compatible with openssh.
    encPassword de88c4dbdc95d85303682734e2397c4d8dd29bfff09ec53580f31dd40291fc8c7755
    encQuestionAnswer1 93956f6e7e9f2aef3af7d6a61f7046dddf14aa4bbd9845dbb836fe3782b62ac0d89f
  ```

- Run `tssh --new-host` to easily add SSH configuration in the TUI interface, and you can log in immediately after completion.

- Run `tssh --install-trzsz` to install [trzsz](https://github.com/trzsz/trzsz-go) to the server automatically.

  - It is installed to the `~/.local/bin/` directory by default. You can specify the installation directory through `--install-path /path/to/install`.
  - If the `--install-path` installation directory contains `~/`, single quotes must be added, such as `--install-path '~/path'`.
  - If obtaining the latest version of `trzsz` fails, you can specify it through `--trzsz-version x.x.x`.
  - If downloading the `trzsz` installation package fails, you can download and specify it through `--trzsz-bin-path /path/to/trzsz.tar.gz`.
  - Note: `--install-trzsz` does not support Windows server, and does not support jump server (unless using `ProxyJump`).

- About changing the terminal title, it can be achieved without `tssh`. It only needs to be configured in the server's shell configuration file (such as `~/.bashrc`):

  ```sh
  # Set fixed server title
  PROMPT_COMMAND='echo -ne "\033]0;Fixed server title\007"'

  # Dynamically changing title based on environment variables
  PROMPT_COMMAND='echo -ne "\033]0;${USER}@${HOSTNAME}: ${PWD}\007"'
  ```

  - If `SetTerminalTitle = Yes` is set in `~/.tssh.conf`, the terminal title is automatically set after login, but `PROMPT_COMMAND` on the server overrides the title set by `tssh`.
  - `tssh` does not reset to the original title after exiting, you need to set `PROMPT_COMMAND` in the local shell so that it overrides the title set by `tssh`.

## Shortcuts

| Action    | Global shortcuts                | Non search shortcuts | Shortcuts description      |
| --------- | ------------------------------- | -------------------- | -------------------------- |
| Confirm   | Enter                           |                      | Confirm and login          |
| Quit/Exit | Ctrl+C Ctrl+Q                   | q Q                  | Cancel and quit            |
| Move Prev | Ctrl+K Shift+Tab ↑              | k K                  | Move cursor up             |
| Move Next | Ctrl+J Tab ↓                    | j J                  | Move cursor down           |
| Page Up   | Ctrl+H Ctrl+U Ctrl+B PageUp ←   | h H u U b B          | Page up                    |
| Page Down | Ctrl+L Ctrl+D Ctrl+F PageDown → | l L d D f F          | Page down                  |
| Goto Home | Home                            | g                    | Go to the first item       |
| Goto End  | End                             | G                    | Go to the last item        |
| EraseKeys | Ctrl+E                          | e E                  | Erase search keywords      |
| TglSearch | /                               |                      | Toggle search function     |
| Tgl Help  | ?                               |                      | Toggle help information    |
| TglSelect | Ctrl+X Ctrl+Space Alt+Space     | Space x X            | Toggle selection           |
| SelectAll | Ctrl+A                          | a A                  | Select all current items   |
| SelectOpp | Ctrl+O                          | o O                  | Select the opposite items  |
| Open Wins | Ctrl+W                          | w W                  | Batch login in new windows |
| Open Tabs | Ctrl+T                          | t T                  | Batch login in new tabs    |
| Open Pane | Ctrl+P                          | p P                  | Batch login in new panes   |

## Trouble shooting

- In the Warp terminal, the features like Blocks requires renaming `tssh` to `ssh`. It is recommended to create a soft link (friendly for updates):

  ```
  sudo ln -sv $(which tssh) /usr/local/bin/ssh
  ```

  - After the soft link, `ssh -V` should output `trzsz ssh` plus the version number. If not, it means that the soft link is unsuccessful, or `openssh` has a higher priority in `PATH`, and you need to soft link to another path or adjust the priority of `PATH`.

  - After the soft link, you need to use `ssh` directly, which is equivalent to `tssh`. If you still use `tssh`, it will not support the Blocks feature.

  - The `--dragfile` argument may disable the Warp features, please refer to the previous section to configure `EnableDragFile` to enable the drag and drop to upload feature.

  - After dragging files and directories into the Warp terminal, the upload may not be triggered immediately. You need to press the `Enter` key once to make it upload.

- If you are using Windows7 or an older version of Windows10, and getting an error `enable virtual terminal failed`.

  - Try using `tssh` in [Cygwin](https://www.cygwin.com/), [MSYS2](https://www.msys2.org/) or [Git Bash](https://www.atlassian.com/git/tutorials/git-bash).

- If the `tssh` specific configuration items are configured in `~/.ssh/config`, and openssh report an error `Bad configuration option`.

  - You can add `#!!` prefix to the items, openssh will treat it as a comment, while `tssh` will treat it as one of the valid configurations.

## Screenshot

![tssh login demo](https://trzsz.github.io/images/tssh.gif)

![tssh batch login](https://trzsz.github.io/images/batch_ssh.gif)

## Contact

Feel free to email the author <lonnywong@qq.com>, or create an [issue](https://github.com/trzsz/trzsz-ssh/issues). Welcome to join the QQ group: 318578930.

## Sponsor

[❤️ Sponsor trzsz ❤️](https://github.com/trzsz), buy the author a drink 🍺 ? Thank you for your support!
