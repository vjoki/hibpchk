# Offline Have I Been Pwned (HIBP) check utils

Utils for running fast offline HIBP checks on KeePassXC and possibly other password
manager databases.

- `hibp-fetch`: Downloads all of the [HIBP](https://haveibeenpwned.com/Passwords)
  password hashes to a local SQLite database. Retrying an incomplete download
  will automatically try to resume. Calling with an existing database
  will update the database if out of date.

- `hibpchk`: Simple executable for checking if a password hash is present in the
  local SQLite HIBP database. Mimics [okon-cli](https://github.com/stryku/okon)
  behaviour for `keepassxc-cli` compatibility, allowing for easy checking of
  [KeePassXC](https://keepassxc.org/) compatible databases.


# Usage with KeePassXC

```shell
$ cargo build --release
$ target/release/hibpfetch --workers 8 --path hibp.okon
$ keepassxc-cli analyze --okon target/release/hibpchk --hibp hibp.okon password_db.kdbx
```
