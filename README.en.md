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

## License

[MIT License](https://choosealicense.com/licenses/mit/)

## Credits

- Original project: [trzsz/trzsz-ssh](https://github.com/trzsz/trzsz-ssh)
- Original author: [lonnywong](https://github.com/lonnywong)