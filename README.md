# H3C Client For SYSU East Campus

> NOTE: Tested in OSX.

# Installation

1. Download this repository
2. Install `libpcap`
3. Change the username, password, device_name in `main.c`
4. `cd` into this directory and `make`
5. Run `sysuh3c`, you are ready to go


# Sequence Diagram

```
# Login
---> Start
<--- Request, Identity
---> Response, Identity
<--- Request, EAP-MD5-CHALLENGE
---> Response, EAP-MD5-CHALLENGE
<--- Some unknown code
<--- Success

# Then enter random check loop
<--- Request, Identity
---> Response, Identity

# Logoff
# Not responding to random check loop also results in auto-logoff
---> Logoff
<--- Failure
```

> Request ID, `version hash` + `username`
>
> EAP-MD5-CHALLENGE, `num` + `username`
>
> `num` is calculated by ( (first 16 character of case-sensitive password) xor (16 bytes md5 data converted to decimal) )


# Thanks to...

* [华为H3C iNode客户端802.1X协议的分析和破解](https://story.tonylee.name/2016/07/14/hua-wei-h3c-inodeke-hu-duan-802-1xxie-yi-de-fen-xi-he-po-jie/)
* [中山大学东校区校园网认证的客户端（非官方）YaH3C](https://github.com/humiaozuzu/YaH3C)
* [西电北校区校园网客户端Linux CLI版 xd-h3c](https://github.com/godspeed1989/xd-h3c)
* [My Fork of YaH3C](https://github.com/githubutilities/YaH3C)
* [Apple pcap man page](https://developer.apple.com/legacy/library/documentation/Darwin/Reference/ManPages/man3/pcap.3pcap.html)
* [Using libpcap C](http://www.devdungeon.com/content/using-libpcap-c)
