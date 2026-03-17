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

## 许可证

[MIT License](https://choosealicense.com/licenses/mit/)

## 致谢

- 原版项目：[trzsz/trzsz-ssh](https://github.com/trzsz/trzsz-ssh)
- 原作者：[lonnywong](https://github.com/lonnywong)
