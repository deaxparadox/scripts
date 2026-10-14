### SSH Config

##### Adding a remote connection

```sh
Host <remote server alias>
  HostName <remote server IP>
  User <account username>
  IdentityFile /path/to/file (.pem or private key)
```


### Github 

SSH confguration for github, without adding key to ssh agent

```sh
Host github-<alias>
  HostName github.com
  User <username>
  IdentityFile /path/to/private_key
  IdentitiesOnly yes
  IdentityAgent none
  AddKeysToAgent no
```

### Generate an SSH key

Single command, writes the key pair to a specific path (no prompts):

```sh
ssh-keygen -t ed25519 -C "<email or label>" -f /path/to/destination/<key_name> -N ""
```

Creates `<key_name>` (private) and `<key_name>.pub` (public). Use a passphrase instead of `-N ""` to protect the key; the `.pub` file is what you add to GitHub / the server.
