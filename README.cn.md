# tssh - 带 Auto-Save 功能的 trzsz-ssh Fork 版本

## 关于本项目

本项目 Fork 自 [trzsz-ssh](https://github.com/trzsz/trzsz-ssh)。

## 本 Fork 版本新增功能

### 1. 自动保存主机配置

成功登录服务器后，主机配置会自动保存到 `~/.ssh/config`。无需再手动添加主机配置。

```sh
# 使用完整地址登录
tssh user@192.168.1.100 -p 22

# 下次可以直接使用自动生成的别名登录
tssh user@192.168.1.100
```

### 2. 自动保存密码

成功使用密码认证登录后，密码会自动加密保存，下次登录无需再次输入密码。

### 3. `--no-save` 参数

如果你不想保存某次登录的主机配置或密码，可以使用 `--no-save` 参数：

```sh
tssh --no-save user@192.168.1.100
```

### 4. 本地/远程双栏文件管理器

支持为任意 SSH 主机打开双栏 SFTP 文件管理器。左侧显示执行 `tssh`
时所在的本地目录，右侧显示所选主机上的远程目录。

在交互式主机列表中，选中主机后按 `U` 即可打开文件管理器。也可以通过命令行直接打开：

```sh
tssh --file-manager my-host
```

支持的操作：

- `[Tab]` 切换本地/远程面板
- `[Enter]` 打开选中的目录
- `[Space]` 选择文件或目录
- `[/]` 在当前面板中进行模糊搜索
- `[U]` 将本地选中的文件/目录上传到远程面板当前目录
- `[D]` 将远程选中的文件/目录下载到本地面板当前目录
- `[R]` 刷新两个面板
- `[Q]` 退出文件管理器

文件管理器基于已有 SSH 连接打开 SFTP 子系统，适用于已经支持 SSH/SFTP 的主机。

### 5. 主机分组

支持使用 `--group` 为主机设置分组，方便在主机较多时进行管理和搜索。

```sh
tssh --group production user@192.168.1.100
tssh --group staging user@192.168.1.101
```

分组标签会显示在交互式主机列表中，也可以通过搜索关键字匹配。

## 许可证

[MIT License](https://choosealicense.com/licenses/mit/)

## 致谢

- 原版项目：[trzsz/trzsz-ssh](https://github.com/trzsz/trzsz-ssh)
- 原作者：[lonnywong](https://github.com/lonnywong)
