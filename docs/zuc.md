# ZUC modes

gm-zig implements ZUC-128, ZUC-256, 128-EEA3, and 128-EIA3.

## ZUC-128

ZUC-128 uses a 128-bit key and a 128-bit IV. The raw stream cipher API returns
32-bit keywords in the same word order as GmSSL and the GM/T test vectors.

```zig
const zuc = @import("gmlib").zuc;

const key = [_]u8{0x00} ** 16;
const iv = [_]u8{0x00} ** 16;

var cipher = zuc.ZUC.init(&key, &iv);
var words: [16]u32 = undefined;
cipher.generateKeystream(&words);
```

`ZUC.crypt` XORs a byte buffer with the keystream; it is byte-oriented and does
not reinterpret the input as big-endian words.

## ZUC-256

ZUC-256 uses a 32-byte key and a 23-byte IV.

```zig
var cipher = zuc.ZUC256.init(&key32, &iv23);
cipher.generateKeystream(&words);
```

The 256-bit MAC context supports 32-, 64-, and 128-bit tags:

```zig
var mac = zuc.ZUC256MAC.init(&key32, &iv23, 128);
mac.update(data);
mac.finish(&last_bits, bit_len, &tag);
```

`finish` accepts a byte slice plus a bit length. Only the most significant
`bit_len` bits of `last_bits` are processed.

## 128-EEA3

`eea3Encrypt` follows GM/T 0001.2-2012 and the GmSSL `zuc_eea_encrypt` layout.
It operates on 32-bit words, and `nbits` is the message bit length:

```zig
zuc.eea3Encrypt(input_words, output_words, nbits, &key, count, bearer, direction);
```

- `count`, `bearer`, and `direction` are packed into the IV exactly as in
  GmSSL's `zuc_set_eea_key`.
- If `nbits` is not a multiple of 32, the unused low bits of the last output
  word are cleared.

## 128-EIA3

`eia3GenerateMac` follows GM/T 0001.3-2012 and GmSSL's
`zuc_eia_generate_mac`:

```zig
const tag = zuc.eia3GenerateMac(message_bytes, nbits, &key, count, bearer, direction);
```

`message_bytes` is the message bitstream, most significant bit first. The
returned tag is a 32-bit integer; encode it big-endian for the standard test
vector byte order.

The IV packing matches `zuc_set_eia_iv`:

- `count` is copied into bytes 0, 9, 10, and 11;
- `bearer` is copied into bytes 4 and 12;
- `direction` is folded into bytes 8 and 14.

## ZUC-AEAD

`ZUC_AEAD` is a gm-zig-specific authenticated-encryption construction built on
ZUC and a separate MAC instance. It is not part of GM/T 0001 and has no direct
GmSSL counterpart. Use EEA3/EIA3 when standard 3GPP/LTE mode behavior is
required.

## Tests

- `src/test/zuc256_test.zig`: ZUC-256 draft keystream and MAC vectors, plus
  incremental and partial-bit MAC cases.
- `src/test/zuc_modes_test.zig`: GM/T 0001.2 EEA3 and GM/T 0001.3 EIA3 vectors
  from the GmSSL test suite.
