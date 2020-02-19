# About

This project is a fork of v2ray, with tls module replaced by [utls](https://github.com/refraction-networking/utls) in order to simulate the fingerprint of popular web browsers.

***Note: NO WARRANT FOR ANY KIND OF USAGE. DO NOT FILE ANY ISSUE. MAY NOT UPDATE ANYMORE.***

# Windows Build

- Install Go
- ```git clone https://github.com/emc2314/v2ray-core.git```
- ```cd v2ray-core```
- ```go get github.com/emc2314/websocket@master```
- ```mkdir build```
- ```go build -o build\wv2ray.exe -ldflags "-H windowsgui -s -w -X v2ray.com/core.codename=utls -X v2ray.com/core.build=emc2314  -X v2ray.com/core.version=4.22.1" .\main\```

# Usage

Note: Use ONLY on client.

Replace ```wv2ray.exe``` in your V2rayN (or any other GUI client) folder.

For those who use websocket+tls together with an http2 capable server (e.g. cloudflare cdn/caddy/nginx with http2), append "/h2" to your websocket path for client side configuration. For example, if your websocket path is ```/ray```, replace it with ```/ray/h2```. **No need to change your server configuration.**

# Details

For tls in v2ray and ws+tls, [Chrome 72 ClientHello](https://tlsfingerprint.io/id/bbf04e5f1881f506) is used.

However, this fingerprint has http/2 as well as http/1.1 in ALPN. If the server supports http/2, they will negotiate the protocol as http/2, which has not been supoorted by the go websocket yet.

So, if you append "/h2" to your path, v2ray will notice (and remove the trailing "/h2") and use [another popular fingerprint](https://tlsfingerprint.io/id/58b1a38e124153a0) which has no http/2 in ALPN extention.

# License

For v2ray part of code: [The MIT License (MIT)](https://raw.githubusercontent.com/v2ray/v2ray-core/master/LICENSE)

For my part of code: [DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE](http://www.wtfpl.net/txt/copying/)