# authd

## Configuration File Format

Like every auth tool, authd will look first in `/etc/auth` and then in `~/.config/auth` for
its `authd.toml`. Here is an example:

```toml
bind_addrs = ['127.0.0.1:8765']
opaque_server_setup = '$HOME/.auth/opaque'
opaque_cookies = '$HOME/.auth/cookies'
authoritative_name = 'localhost'
passwd_file = '$HOME/.auth/passwd'
shadow_file = '$HOME/.auth/shadow'
cert = '$HOME/Projects/auth/cert.der'
key = '$HOME/Projects/auth/key.der'
```

Obviously you couldn't deploy this example. `$HOME/.auth` stores all of the server state and
secrets. Don't let its contents get out to the world! Generating TLS certs is out of scope here but
there is a demo cert that works in the repo.

opaque_server_setup stores the secret key which is kinda like the list of salts in a hash-based system.

opaque_cookies likewise stores the client cookies, which are kinda like hashed passwords. But really they are sealed keys that clients can open if they remember their password.