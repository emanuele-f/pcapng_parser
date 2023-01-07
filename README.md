A [pcapng](ttps://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng) file parser.

Features:

- Print common block types and related options
- Print TLS decryption secrets and packet payload (`-v` option)

Current limitations (todos):

- Does not support different byte order
- Only 1 *Interface Description Block* is supported
- Microseconds timestamps are assumed

Example usage: `pcapng_parser samples/chrome-cloudflare-quic-with-secrets.pcapng`

```
[+00000000] Section Header Block (0x0a0d0d0a), Len: 128
  SHB v1.0 - Len: unknown
[+00000080] Decryption Secrets Block (0x0000000a), Len: 1576
  DSB - Type: TLS Key Log (0x544c534b), Len: 1556
[+000006a8] Interface Description Block (0x00000001), Len: 100
  IDB - Linktype: ethernet (1), Snaplen: 524288
[+0000070c] Enhanced Packet Block (0x00000006), Len: 144
[+0000079c] Enhanced Packet Block (0x00000006), Len: 140
[+00000828] Enhanced Packet Block (0x00000006), Len: 132
[+000008ac] Enhanced Packet Block (0x00000006), Len: 648
[+00000b34] Enhanced Packet Block (0x00000006), Len: 132
[+00000bb8] Enhanced Packet Block (0x00000006), Len: 1480
```
