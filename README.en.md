# tssh - Fork of trzsz-ssh with Auto-Save Features

## About

This project is forked from [trzsz-ssh](https://github.com/trzsz/trzsz-ssh).

## What's New in This Fork

### 1. Auto-Save Host Configuration

After successfully logging into a server, the host configuration is automatically saved to `~/.ssh/config`.

```sh
# Login with full address
tssh user@192.168.1.100 -p 22

# Next time, you can use the auto-generated alias
tssh user@192.168.1.100
```

### 2. Auto-Save Password

After a successful password authentication, the password is automatically saved (encrypted) for future logins.

### 3. `--no-save` Option

Disable auto-save for a specific session:

```sh
tssh --no-save user@192.168.1.100
```

### 4. Local/Remote File Manager

Open a two-pane SFTP file manager for any SSH host. The left pane shows the
local directory where `tssh` was started, and the right pane shows the remote
directory on the selected host.

From the interactive host list, press `U` on a host to open the file manager.
You can also open it directly from the command line:

```sh
tssh --file-manager my-host
```

Supported actions:

- `[Tab]` switch between local and remote panes
- `[Enter]` open the selected directory
- `[Space]` select files or directories
- `[/]` fuzzy search in the active pane
- `[U]` upload selected local files/directories to the remote pane
- `[D]` download selected remote files/directories to the local pane
- `[R]` refresh both panes
- `[Q]` quit the file manager

The file manager uses SFTP over the existing SSH connection, so it is designed
for hosts that already support SSH/SFTP.

### 5. Host Groups

Hosts can be assigned to groups with `--group`, making large host lists easier
to organize and search.

```sh
tssh --group production user@192.168.1.100
tssh --group staging user@192.168.1.101
```

Group labels are shown in the interactive host list and can be matched by
search keywords.

## License

[MIT License](https://choosealicense.com/licenses/mit/)

## Credits

- Original project: [trzsz/trzsz-ssh](https://github.com/trzsz/trzsz-ssh)
- Original author: [lonnywong](https://github.com/lonnywong)
