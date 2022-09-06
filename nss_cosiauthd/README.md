# `nss_cosiauthd`

[Name Service Switch](https://www.gnu.org/software/libc/manual/html_node/Name-Service-Switch.html)
module for communication with `authd`.

To enable this module, `cargo build --release`, and then copy `target/release/libnss_cosiauthd.so`
to `/lib/x86_64-unknown-linux-gnu/libnss_cosiauthd.so.2`, or whatever directory contains
`libnss_compat.so.2`. If the number on your `.so` is different, then NSS has changed in ways that
make this software unusable as-is and an ABI upgrade is necessary.

Edit `/etc/nsswitch.conf` to use this module. As an example:

```
passwd:         files cosiauthd systemd
group:          files cosiauthd systemd
shadow:         files cosiauthd
gshadow:        files cosiauthd
```

Write `/etc/auth/nss_authd.toml`, as an example:

```toml
host = 'authd.cosi.clarkson.edu'
port = 8765
```

The module will try very, _very_ hard to make a TLS connection to the server. It will wait forever if it must. If it is taking longer than you expect, maybe the port is wrong?