# SOCKS5 Server in Go

```markdown
# Client Initiation

Bytes Length: 257

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

# Server Reply during initiation

Bytes Length: 2

+----+--------+
|VER | METHOD |
+----+--------+
| 1  |   1    |
+----+--------+

# Client Requests

Bytes Length: at least more than 5 bytes, the rest depends on DST.ADDR variable

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

# Server Response (Reply)

Bytes Length: at least more than 6 bytes, the rest depends on BIND.ADDR variable

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+
```

## Scratches

```bash
5 1 0 3 15 115 115 108 46 103 115 116 97 116 105 99 46 99 111 109 1 187

5 => SOCKS Version
1 => CONNECT
0 => RSV (Reserved)
3 => ATYP (DOMAINNAME)
15 => Length for the domain name
115 115 108 46 103 115 116 97 116 105 99 46 99 111 109 => DOMAIN NAME
1 187 => DST.PORT (0x01 + 0xBB) == (256 + 187) => 443


187 187 => (0xBB + 0xBB) == (11 * 16^3) + (11 * 16^2) + (11 * 16^1) + (11 * 16^0)
                            45056 + 2816 + 176 + 11 = 48059
```
