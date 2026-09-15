---
layout: post
title: "a2 生成算法说明（脱敏版）"
date: 2026-09-16
---

## 1. 文档范围

本文描述 a2 从请求字段到最终小写十六进制字符串的完整行为级算法。

本文有意隐藏以下信息：

- 内部函数名称及函数偏移。
- 实际 HMAC key、key source、B16、MASK16 和固定 profile 字节。
- 样例请求中的设备标识、业务字段值、中间 digest 和最终输出值。

本文保留 APK 载荷恢复所需的偏移、长度、容器格式和白盒表布局。实际运行时常量应作为
独立的二进制 profile 注入实现，不应直接写入公开文档。

## 2. 总体数据流

```text
request fields
    |
    +--> canonical request message
    |
    +--> device id (field a1) + profile key material
             |
             v
        36-byte HMAC key
             |
             v
HMAC-SHA1(key, message) -> 20-byte digest
             |
             +--> digest[0:16] = data16
             |
             v
      white-box transform(data16, table profile)
             |
             v
          A16 (16 bytes)
             |
             v
  a2 core(data16, A16, B16, MASK16)
             |
             v
          mid16
             |
             v
  caller finalization(mid16, MASK16, fixed byte)
             |
             v
          raw16
             |
             v
      lowercase hexadecimal (32 chars)
```

其中，a2 主计算实际只消费 HMAC 输出的前 16 字节。剩余 4 字节仍属于 HMAC-SHA1 的
标准输出，但不进入白盒和 a2 字节循环。

## 3. 输入分类

### 3.1 请求字段

请求由两部分组成：

1. 固定格式的请求前缀，包括 HTTP 方法、路径和规范化 query 参数。
2. 按协议固定字段顺序序列化的紧凑 JSON。

字段名属于业务协议，例如 `a0`、`a1`、`a3`、`a4`、`a5`、`a6`、`a7`、`a8`、`a9`、
`a10` 和 `x0`。本文不记录这些字段的实际值。

JSON 序列化要求：

- 不插入空格和换行。
- 对象使用 `,` 和 `:` 作为紧凑分隔符。
- 保持协议规定的字段顺序，不按字典序重新排序已有字段。
- 需要 ASCII 兼容输出时使用 JSON ASCII escaping；非 ASCII 协议实现应明确采用的字节编码。
- 最终 HMAC 输入是 message 的原始字节，不是十六进制文本或 Base64 文本。

对当前 trace 样例，完整 message 长度为 1120 字节。其它请求的长度可以不同，HMAC
实现不依赖该固定长度。

### 3.2 设备标识

字段 `a1` 同时参与：

- JSON message 的构造。
- 36 字节 HMAC key 的派生。

当前二进制 profile 要求用于 key 派生的 device id 为 36 字节 ASCII 数据。实现应在进入
key loop 前验证长度，不应静默截断或补零。

### 3.3 二进制 profile

以下参数是受保护二进制的固定 profile，而不是随 message 变化的中间状态：

| 参数 | 规格 | 用途 |
|---|---:|---|
| `KEY_SOURCE_EFFECTIVE` | 36 bytes | key loop 中最终会保留下来的 source 字节 |
| `KEY_XOR_BYTE` | 1 byte | key loop 的固定 XOR 操作数 |
| `B16_PROFILE` | 16 bytes | a2 core 的第二个字节操作数 |
| `MASK16_PROFILE` | 16 bytes | a2 core 和 finalize 使用的 mask |
| `FINAL_FIXED_BYTE` | 1 byte | finalize 中的 AND/XOR 操作数 |
| `PERM_PROFILE` | 16 entries | 白盒轮间字节置换 |
| `KT_PROFILE` | 16 x 16 x 32-bit | 白盒轮内 key lookup |
| `NIB_PROFILE` | 16 x 16 x 8-bit | 白盒半字节混合 |
| `KF_PROFILE` | 16 x 16 x 8-bit | 白盒末轮 lookup |
| `WB_TABLE` | `0x2E000` bytes | 白盒主表 |

本文不列出这些 profile 的实际字节值。

## 4. 36 字节 HMAC key 派生

### 4.1 有效算法

原生实现使用一个 64 字节 source、一个 36 字节 device id 和一个 36 字节输出缓冲区。
循环把 source 与 device id 按 36 字节周期异或：

```text
OUTPUT = byte[0x24]

for i = 0 .. 0x3F:
    j = i mod 0x24
    OUTPUT[j] = SOURCE[i] XOR DEVICE_ID[j] XOR KEY_XOR_BYTE
```

这里的 `0x24` 是 36，`0x3F` 是最后一个循环索引 63。

因为循环次数 64 大于输出长度 36，第二遍会覆盖输出的前 28 字节。因此最终输出只
依赖：

```text
SOURCE[0x24:0x40] followed by SOURCE[0x1C:0x24]
```

这 36 个有效 source 字节在实现中可作为 `KEY_SOURCE_EFFECTIVE` 注入，从而避免保存
不会影响最终结果的前 28 个 source 字节。

### 4.2 脱敏实现接口

```python
def derive_key36(device_id, key_source_effective, key_xor_byte):
    require len(device_id) == 0x24
    require len(key_source_effective) == 0x24

    # Reconstruct any 64-byte source whose overwritten prefix is irrelevant.
    source64 = (b"\x00" * 0x1C
                + key_source_effective[-8:]
                + key_source_effective[:0x1C])

    output = bytearray(0x24)
    for i, source_byte in enumerate(source64):
        j = i % 0x24
        output[j] = source_byte ^ device_id[j] ^ key_xor_byte
    return bytes(output)
```

`key_source_effective` 和 `key_xor_byte` 是二进制 profile，不是从本文恢复的公开常量。

## 5. HMAC-SHA1

### 5.1 HMAC 结构

36 字节 key 小于 SHA-1 的 64 字节 block size，因此不需要先做 key hash。标准 HMAC
结构为：

```text
ipad = 64 bytes of 0x36
opad = 64 bytes of 0x5C

inner = SHA1((key padded with zeros to 64 bytes XOR ipad) || message)
outer = SHA1((key padded with zeros to 64 bytes XOR opad) || inner)
digest20 = outer
```

### 5.2 SHA-1 block processing

实现可以使用标准库，也可以使用与原生 trace 等价的纯 Python 实现。纯实现应遵守：

1. message 按字节计算 bit length。
2. 追加一个 `0x80`。
3. 追加零字节，直到长度模 64 等于 56。
4. 以大端 64-bit 写入原始 bit length。
5. 每个 64 字节 block 解析为 16 个大端 32-bit word。
6. 扩展到 80 个 word：

```text
W[t] = rol32(W[t-3] XOR W[t-8] XOR W[t-14] XOR W[t-16], 1)
```

7. 使用 SHA-1 的四组标准 round function 和标准 round constant。
8. 所有加法在 32-bit 模空间内进行。
9. 最终按大端顺序输出 5 个 32-bit state word，即 20 字节 digest。

## 6. 从 APK 恢复白盒表

本节的 APK 参数不脱敏。

### 6.1 外层 raw DEFLATE

受保护 APK 中的白盒载荷位于：

```text
file offset = 0x3DE254
file size   = 0x2927A
```

原生代码先将文件偏移按页对齐：

```text
aligned file offset = 0x3DE000
in-page delta       = 0x254
mapped length       = 0x28FE5
payload address     = mapped_base + 0x254
```

从 `0x3DE254` 开始读取 `0x2927A` 字节后，使用 raw DEFLATE 解压，即 zlib `wbits=-15`：

```python
outer_payload = apk[0x3DE254:0x3DE254 + 0x2927A]
xbt = zlib.decompress(outer_payload, -15)
```

### 6.2 `.XBT` 容器

外层解压结果以 28 字节头开始：

```text
offset +0x00: 4-byte magic, expected `.XBT`
offset +0x04: 32-bit little-endian version, expected 1
offset +0x08: 32-bit little-endian packed size, expected 0x2925E
offset +0x0C: 32-bit little-endian unpacked size, expected 0x2E000
offset +0x10: profile tag/check field
offset +0x14: profile tag/check field
offset +0x18: reserved field
offset +0x1C: inner zlib stream
```

因此内层数据范围为：

```python
packed = xbt[0x1C:0x1C + 0x2925E]
decoded = zlib.decompress(packed)
```

`decoded` 必须正好为 `0x2E000` 字节。

### 6.3 表区最终化

内层 zlib 输出还没有成为白盒运行时实际读取的表。调用方对每个字节执行同一个 XOR：

```python
WB_TABLE = bytes(value ^ 0x61 for value in decoded)
```

最终 `WB_TABLE` 长度仍为 `0x2E000`。实现应检查 `.XBT` magic、版本、packed size、
unpacked size 和最终长度，避免把错误 APK 或错误压缩层静默当作表使用。

## 7. 白盒 A16 变换

### 7.1 输入和置换

白盒阶段输入为 `data16`，长度必须为 16 字节。当前 profile 使用一个 16-entry 字节
置换表 `PERM_PROFILE`：

```python
def permute(value16):
    return bytes(value16[PERM_PROFILE[i]] for i in range(16))
```

先执行一次置换，然后执行 9 个轮：

```python
x = permute(data16)
for round_index in range(9):
    x = round_body(WB_TABLE, round_index, x)
    x = permute(x)
```

### 7.2 轮内四组查表

每轮将 16 字节分成 4 组，每组 4 字节。对组 `g`、组内位置 `k`：

```text
i = 4*g + k
b = x[i]
table_offset = 0xA000 + round_index*0x4000 + g*0x1000 + k*0x400 + b*4
v[k] = load_i32_le(WB_TABLE, table_offset) XOR K(round_index, i, b)
```

其中 `K` 由 16 x 16 的 32-bit profile 表计算：

```text
idx = round_index + i + b + 1
q   = (round_index * i * b) mod 16
r   = (idx * 0x44F + q) mod 16
c   = (idx * 0x70B + q) mod 16
K   = KT_PROFILE[r][c]
```

`load_i32_le` 的结果按有符号或无符号读取都不会改变最终 32-bit XOR 位模式，建议实现
统一使用 masked 32-bit 整数。

### 7.3 半字节混合

每组得到四个 32-bit word `a,b,c,d`。对每个字节位置 `p=0..3`，从四个 word 提取
对应的高、低半字节：

```text
hi_p(w) = (w >> (8*p + 4)) & 0xF
lo_p(w) = (w >> (8*p    )) & 0xF
```

使用 `NIB_PROFILE` 完成两层查表：

```text
hi = NIB_PROFILE[
       NIB_PROFILE[hi_p(a)][hi_p(b)]
    ][
       NIB_PROFILE[hi_p(c)][hi_p(d)]
    ]

lo = NIB_PROFILE[
       NIB_PROFILE[lo_p(a)][lo_p(b)]
    ][
       NIB_PROFILE[lo_p(c)][lo_p(d)]
    ]

group_out[3-p] = (hi << 4) | lo
```

这里的 `3-p` 是实际输出顺序的一部分，不能改为 `p`。

### 7.4 末轮

9 个轮体和轮间置换完成后，执行一个独立的 16 x 256 字节末轮表：

```text
for i = 0 .. 15:
    b = x[i]
    table_byte = WB_TABLE[0x9000 + i*0x100 + b]

    idx = 9 + i + b + 1
    q   = (9 * i * b) mod 16
    r   = (idx * 0x44F + q) mod 16
    c   = (idx * 0x70B + q) mod 16
    x[i] = table_byte XOR KF_PROFILE[r][c]
```

变换结果 `x` 即 `A16`，长度为 16 字节。

### 7.5 白盒表布局

`WB_TABLE` 中与 a2 变换相关的区域为：

```text
0x9000 .. 0x9FFF
    末轮 16 x 256 字节表

0xA000 + round*0x4000 + group*0x1000 + k*0x400
    9 轮 x 4 组 x 4 张 256-entry 32-bit 表
```

轮体表从 `0xA000` 开始，覆盖到 `0x2E000` 末尾。表前部可能包含容器或运行时保留区域，
不要把整个 `0x2E000` 当作一个线性 lookup 表。

## 8. a2 core

### 8.1 输入

a2 core 接收四个 16 字节输入：

- `data16`：HMAC digest 的前 16 字节。
- `A16`：白盒阶段输出。
- `B16_PROFILE`：固定 VM profile。
- `MASK16_PROFILE`：固定 VM profile。

### 8.2 字节公式

所有运算按 8-bit 处理：

```text
mid[i] = MASK16_PROFILE[i]
         XOR B16_PROFILE[i]
         XOR ((data16[i] + A16[i]) mod 256)
```

输出 `mid16` 长度为 16 字节。这里的加法不是 32-bit 加法；只保留低 8 位。

## 9. 调用方 finalize

finalize 使用 `mid16`、`MASK16_PROFILE` 和一个固定的 profile 字节。令：

```text
m = MASK16_PROFILE
k = FINAL_FIXED_BYTE
```

则：

```text
f9  = mid[0] XOR mid[7] XOR m[0] XOR 1
f10 = mid[1] XOR mid[6] XOR m[1]
f11 = mid[2] XOR mid[5] XOR m[2]
f12 = mid[3] XOR mid[4] XOR m[3]
f13 = mid[3] XOR mid[4] XOR m[4]
f14 = (m[5] XOR mid[4] XOR mid[5]) AND k
t   = f14 XOR k
f15 = (m[6] XOR mid[6] XOR mid[5]) OR t
f8  = f15 XOR t
```

最终 16 字节按以下顺序拼接：

```text
raw16 = mid[0:8] || f8 || f9 || f10 || f11 || f12 || f13 || f14 || f15
```

每个中间量均截断为 8-bit。`mid[8:16]` 不直接原样保留，而是由 `f8..f15` 重写。

## 10. 十六进制输出

最终格式化只是逐字节输出小写 `%02x`：

```python
hex_output = raw16.hex()
```

因此：

- 输入长度为 16 字节。
- 输出长度固定为 32 个 ASCII 字符。
- 不添加前缀、空格、换行或大写字母。

## 11. 脱敏版端到端伪代码

```python
def a2_generate(fields, profile, apk_bytes=None):
    # 1. Build the canonical message.
    message = build_canonical_message(fields)

    # 2. Derive the 36-byte HMAC key from field a1.
    device_id = ascii_bytes(fields["a1"])
    hmac_key = derive_key36(
        device_id,
        profile.key_source_effective,
        profile.key_xor_byte,
    )

    # 3. HMAC-SHA1.
    digest20 = hmac_sha1(hmac_key, message)
    data16 = digest20[:16]

    # 4. Recover or load the white-box table.
    if apk_bytes is not None:
        table = recover_wb_table(apk_bytes)
    else:
        table = profile.wb_table

    # 5. White-box stage.
    a16 = white_box_transform(data16, table, profile)

    # 6. a2 core.
    mid16 = bytes(
        profile.mask16[i]
        ^ profile.b16[i]
        ^ ((data16[i] + a16[i]) & 0xFF)
        for i in range(16)
    )

    # 7. Finalize and format.
    raw16 = finalize(mid16, profile.mask16, profile.final_fixed_byte)
    return raw16.hex()
```

## 12. 验证要求

实现至少应执行以下检查：

1. `a1` 的 key-loop 输入长度为 36 字节。
2. HMAC 输出长度为 20 字节。
3. `data16 == digest20[:16]`。
4. APK 外层载荷长度为 `0x2927A`。
5. `.XBT` magic 为 `.XBT`，version 为 1。
6. `.XBT` 内层压缩长度为 `0x2925E`。
7. 内层解压结果和最终白盒表长度均为 `0x2E000`。
8. `data16`、`A16`、`B16_PROFILE`、`MASK16_PROFILE`、`mid16` 和 `raw16` 均为 16 字节。
9. 最终字符串长度为 32，并且只包含小写十六进制字符。
10. 使用同一 binary profile 时，message、key、digest、A16、mid16 和最终 hex 应逐阶段
    与对应 trace 一致。

## 13. 实现边界

本文已经完整描述 a2 的外部可观察计算：

```text
request fields
    -> message and HMAC key
    -> HMAC-SHA1 20 bytes
    -> first 16 bytes
    -> white-box A16
    -> a2 core
    -> finalize
    -> lowercase hex
```

VM 内部的 continuation 状态、ValueSlot C++ 类型名和 native target 业务命名不属于输出
算法本身。它们可以用于解释 profile 常量如何初始化，但不应被误写成新的摘要算法，或
作为 a2 行为级复现的必要步骤。
