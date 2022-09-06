# auth cli

This tool allows for several administrative and maintenance operations on authd.

## Bootstrapping the OPAQUE database

In the beginning, nobody is authorized to edit the database. To bootstrap OPAQUE:

```
# auth generate-opaque-secret --output /etc/auth/opaque
# auth bootstrap-admin --name $username --uid $uid --authd-config /etc/auth/authd.toml
```

## Running authd

Now that we've got that thorny issue out of the way, we can start adding users, so
long as in the last step you decided to name your user ember.

```
# authd
```

It should just sit there quietly. If you would like a lot of colorful confusion whenever
you do any of the next steps, just run it like this:

```
# env RUST_LOG=trace authd
```

... oh, and make sure to consult the authd docs for what to put in `~/.config/auth/authd.toml`.

## Creating users

```
$ auth  create-user
Required options not provided:
    --name
    --uid
    --shell
    --homedir
    --host
    --cert

Run auth --help for more information.
$ auth  create-user --name tj --uid 1003 --shell dash --homedir thajohns --host 127.0.0.1:8765 --cert ~/.auth/cert.der
admin username: ember
admin password: gottem
welcome back to authd, ember
New OPAQUE password: wasspord
Confirm new OPAQUE password: wasspord
registered new user tj!
```