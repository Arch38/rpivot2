# rpivot2 - reverse SOCKS4 proxy for penetration tests.

Fork of [klsecservices/rpivot](https://github.com/klsecservices/rpivot) by Artem Kondratenko (https://twitter.com/artkond)

Added by me:

- rpivot2 works on Python 2 and Python 3.
- rpivot2 works with host names. Original works only with IPs.
- A shit ton of refactornig.


## Usage

1. Run the server on a pentester's machine and wait for a client to connect to it.

       python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080

2. Run the client on the machine you want to tunnel traffic through.

       python client.py --server-ip <rpivot_server_ip> --server-port 9999

## Usage examples

Start server listener on port 9999, which creates a socks 4 proxy on 127.0.0.1:1080 upon connection from client:

`python server.py --server-port 9999 --server-ip 0.0.0.0 --proxy-ip 127.0.0.1 --proxy-port 1080`

Connect to the server:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999`

To pivot through an NTLM proxy:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --password P@ssw0rd`

Pass-the-hash is supported:

`python client.py --server-ip <rpivot_server_ip> --server-port 9999 --ntlm-proxy-ip <proxy_ip> --ntlm-proxy-port 8080 --domain CONTOSO.COM --username Alice --hashes 9b9850751be2515c8231e5189015bbe6:49ef7638d69a01f26d96ed673bf50c45`

You can use `proxychains` to tunnel traffic through socks proxy.

Edit /etc/proxychains.conf:

```
[ProxyList]
# add proxy here ...
# meanwile
# defaults set to "tor"
socks4 127.0.0.1 1080
```

And you probably disable proxying DNS because SOCKS4 doesn't work with it.

Using single zip file mode:

```
zip rpivot.zip -r *.py ./ntlm_auth/
python rpivot.zip server <server_options>
python rpivot.zip client <client_options> 
```

Pivot and have fun:

`proxychains <tool_name>`

Pre-built Windows client binary available in release section.
