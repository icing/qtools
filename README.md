# qtools

A tool collection around tls and quic.

**Status**: highly experimental. For development/debugging purposes. WIP.

# scanhs.py

When you have only a log file, or you are too lazy to fire up Wireshark, `scanhs.py` looks for hex 
dumps of CRYPTO packets, parses and displays their content.

I wrote this to debug my work on integrating wolfSSL into ngtcp2.
(Be aware that in other then dev environments, these packets contain sensitive data.)


### ngtcp2 handshake

The example client/server programs in the ngtcp2 project allow for easy testing of the various 
TLS libraries you build the ngtcp2 crypto libs for. When they fail to finish the handshake, a 
hex dump of the received packets is printed.

`scanhs.py` scans the output of an client or server for CRYPTO dumps and parses the hex data
into a human readable format. For example, a server logging:

```
...
Ordered CRYPTO data in Initial crypto level
00000000  01 00 02 25 03 03 29 ca  b4 1a 5e 93 6c cf df 70  |...%..)...^.l..p|
00000010  09 34 22 1f ed 00 02 f5  eb 7f c3 de 6b 71 ef 42  |.4".........kq.B|
00000020  12 20 8a 61 f0 a1 00 00  08 13 01 13 02 13 03 13  |. .a............|
00000030  04 01 00 01 f4 00 39 00  48 0f 11 ba ca 95 19 96  |......9.H.......|
00000040  e8 ca 74 cd ff 39 a7 cd  93 58 5e 9a 05 04 80 04  |..t..9...X^.....|
...
```

run `scanhs.py server.log` and you get something like:

```
   ClientHello
      id: 0x1
      data(549): ...
      version: 0x303
      random: 29cab41a5e936ccfdf700934221fed0002f5eb7fc3de6b71ef4212208a61f0a1
      session_id:
      ciphers: TLS_AES_128_GCM_SHA256(0x1301), TLS_AES_256_GCM_SHA384(0x1302), TLS_CHACHA20_POLY1305_SHA256(0x1303), TLS_AES_128_CCM_SHA256(0x1304)
      compressions: [0]
      extensions:
        QUIC_TP_PARAMS(0x39)
          initial_source_connection_id(0xf): baca951996e8ca74cdff39a7cd93585e9a
          initial_max_stream_data_bidi_local(0x5): 262144
          initial_max_stream_data_bidi_remote(0x6): 262144
          initial_max_stream_data_uni(0x7): 262144
          initial_max_data(0x4): 1048576
          initial_max_streams_uni(0x9): 100
          max_idle_timeout(0x1): 30000
          active_connection_id_limit(0xe): 7
          QuicTP(0x2ab2):
          QuicTP(0xff73db): 0000000100000001
        EARLY_DATA(0x2a)
        PSK_KEY_EXCHANGE_MODES(0x2d): psk_ke(0x0), psk_dhe_ke(0x1)
        KEY_SHARE(0x33)
...
```

With option `-j` you'd get that in JSON format. Which might come in handy for future tools that evaluate it.



