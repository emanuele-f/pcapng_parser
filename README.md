A [pcapng](ttps://datatracker.ietf.org/doc/draft-tuexen-opsawg-pcapng) file parser.

Features:

- Print common block types and related options
- Print TLS decryption secrets and packet payload (`-v` option)

Current limitations (todos):

- Does not support different byte order
- Only 1 *Interface Description Block* is supported
- Microseconds timestamps are assumed
- Blocks options are not parsed

Example usage: `pcapng_parser samples/chrome-cloudflare-quic-with-secrets.pcapng`

```
[Type: 0x0a0d0d0a (Section Header Block), Len: 128]
  SHB v1.0 - Len: unknown
[Type: 0x0000000a (Decryption Secrets Block), Len: 1576]
  DSB - Type: TLS Key Log (0x544c534b), Len: 1556
[Type: 0x00000001 (Interface Description Block), Len: 100]
  IDB - Linktype: ethernet (1), Snaplen: 524288
[Type: 0x00000006 (Enhanced Packet Block), Len: 144]
[Type: 0x00000006 (Enhanced Packet Block), Len: 140]
[Type: 0x00000006 (Enhanced Packet Block), Len: 132]
[Type: 0x00000006 (Enhanced Packet Block), Len: 648]
[Type: 0x00000006 (Enhanced Packet Block), Len: 132]
[Type: 0x00000006 (Enhanced Packet Block), Len: 1480]
```
