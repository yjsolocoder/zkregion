# zkregion

面向区域成员关系的承诺与交互式证明原语。提供哈希承诺、量化坐标的 Pedersen 陷门承诺、素域乘法群上的 Schnorr 交互证明、确定性 SHA-256 Merkle 包含证明，以及量化整数坐标下的矩形区域判定。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`hmac`、`secrets`）。

## 使用

```python
from zkregion import Region, SchnorrProof, SchnorrProver, SchnorrVerifier, commit, verify_opening

commitment, nonce = commit(b"coordinate")
assert verify_opening(commitment, b"coordinate", nonce)

# 量化坐标的 Pedersen 陷门承诺：C = g**m * h**r mod prime，m = value - lower
from zkregion import pedersen_commit, verify_pedersen_opening

pc, blinding = pedersen_commit(500, 0, 1000)
assert verify_pedersen_opening(pc, 500, blinding)
assert not verify_pedersen_opening(pc, 501, blinding)

prover = SchnorrProver(secret=12345)
verifier = SchnorrVerifier(prover.public_key)
t = prover.new_commitment()
c = 987654321
s = prover.respond(c)
assert verifier.verify(t, c, s)

# 非交互 Fiat-Shamir 证明
proof = prover.prove(b"payload", context=b"session-1")
assert verifier.verify_proof(b"payload", proof, context=b"session-1")

# 同一公钥的批量验证
from zkregion import SchnorrBatchEntry

batch = [
    SchnorrBatchEntry(b"alpha", prover.prove(b"alpha", context=b"s1"), context=b"s1"),
    SchnorrBatchEntry(b"beta", prover.prove(b"beta", context=b"s1"), context=b"s1"),
]
assert verifier.verify_batch(batch)

# Merkle 包含证明
from zkregion import merkle_root, prove_inclusion, verify_inclusion

leaves = [b"alpha", b"beta", b"gamma"]
root = merkle_root(leaves)
inclusion = prove_inclusion(leaves, 1)
assert verify_inclusion(b"beta", inclusion, root)

# Merkle 多包含证明（一次证明多片叶子，无需完整叶集即可验证）
from zkregion import prove_multi_inclusion, verify_multi_inclusion

multi = prove_multi_inclusion(leaves, (0, 2))
entries = [(0, b"alpha"), (2, b"gamma")]
assert verify_multi_inclusion(entries, multi, root)

Region(0, 100, 0, 100).contains(50, 50)     # True
```

## 命令行演示

```bash
python3 -m zkregion
```

## 公开接口

- `DEFAULT_PRIME` / `DEFAULT_GENERATOR` — 默认群参数（`2**127 - 1` 与 `3`）
- `commit(value, *, nonce=None) -> (commitment, nonce)` — 哈希承诺，`nonce` 缺省随机 16 字节
- `verify_opening(commitment, value, nonce) -> bool` — 常量时间比对
- `commit_coordinate(x, y, *, nonce=None)` — 对整数坐标对做承诺
- `pedersen_commit(value, lower, upper, prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR, h=None, *, blinding=None, randbelow=secrets.randbelow) -> (PedersenCommitment, blinding)` — 量化坐标的 Pedersen 承诺
- `verify_pedersen_opening(commitment_obj, value, blinding) -> bool` — 复用对象参数验证开合
- `PedersenCommitment(commitment, element, lower, upper, prime, generator, h)` — 不可变承诺对象，不存储盲因子
- `SchnorrProver(secret, *, prime, generator, randbelow)`
  - `public_key` — `g**secret mod prime`
  - `new_commitment()` — 生成一次性随机数并返回 `g**k mod prime`
  - `respond(challenge)` — 返回 `k + challenge * secret`（不取模）
  - `prove(message, *, context=b"") -> SchnorrProof` — Fiat-Shamir 非交互证明
- `SchnorrVerifier(public_key, *, prime, generator)`
  - `verify(commitment, challenge, response)` — 交互式验证
  - `verify_proof(message, proof, *, context=b"") -> bool` — 非交互证明验证
  - `verify_batch(entries, *, randbelow=secrets.randbelow) -> bool` — 同一公钥的批量验证
- `SchnorrProof(commitment, response)` — 不可变证明对象（`t = g**k mod prime`，`s = k + c * secret`）
- `SchnorrBatchEntry(message, proof, context=b"")` — 不可变批量验证条目，字段类型依次为 `bytes`、`SchnorrProof`、`bytes`
- `merkle_root(leaves) -> bytes` — 非空 `bytes` 序列的 Merkle 根
- `prove_inclusion(leaves, index) -> MerkleProof` — 按零基索引生成包含证明
- `verify_inclusion(leaf, proof, root) -> bool` — 验证包含证明
- `MerkleProof(index, siblings)` — 不可变证明对象，`siblings` 为按叶到根排列的 `tuple[bytes, ...]`
- `prove_multi_inclusion(leaves, indices) -> MerkleMultiProof` — 为多片叶子生成紧凑的合并包含证明
- `verify_multi_inclusion(entries, proof, root) -> bool` — 无需完整叶集验证多包含证明；`entries` 按 `proof.indices` 顺序给出 `(index, leaf)`
- `MerkleMultiProof(leaf_count, indices, siblings)` — 不可变多包含证明对象，`indices` 为 `tuple[int, ...]`，`siblings` 为 `tuple[bytes, ...]`
- `Region(min_x, max_x, min_y, max_y)` — 闭区间矩形；`contains(x, y)`

### Merkle 树构造

叶摘要为 `SHA-256(b"\x00" + len4 + leaf)`，其中 `len4` 是叶长的四字节无符号大端编码；内部节点摘要为 `SHA-256(b"\x01" + left + right)`。每层按输入顺序两两合并，奇数节点复制末项后再合并；单叶树的根就是叶摘要，证明路径为空。重复叶按调用方给出的零基索引定位，不按内容搜索。`leaves` 为空抛 `ValueError`，叶或索引类型错误抛 `TypeError`，索引越界抛 `IndexError`。验证时 `leaf`、`root` 与各兄弟摘要须为 `bytes`（后两者恰 32 字节），`proof` 须为 `MerkleProof` 且 `index` 为非负整数；类型错误抛 `TypeError`，摘要长度或索引结构非法返回 `False`。验证按 `index` 奇偶决定左右顺序并逐层整除二；叶、索引、路径或根被篡改均返回 `False`，所有入口均不改写输入。

### Merkle 多包含证明

多包含证明复用同一套哈希与奇数末项复制规则，把多片叶子的路径合并为一个证明。`indices` 须非空、严格递增且无重复；生成时逐层从左到右处理：兄弟节点本身也在被证明之列则直接合并、无需收集，奇数层末项无兄弟则自复制，其余情况才收集兄弟摘要；父层位置按 `position // 2` 去重。证明确定且最小——证明全部叶子时 `siblings` 为空。验证方只需 `entries`（按 `proof.indices` 顺序给出的 `(index, leaf)`）、证明与根，无需完整叶集；按同一规则逐层恢复根，且必须恰好耗尽全部 `siblings`，否则返回 `False`。

生成时 `leaves` 须为非空 `bytes` 序列；`leaf_count` 须为正的非 bool 整数，索引须为范围内的非 bool 整数。类型错误抛 `TypeError`，`indices` 为空、重复或乱序抛 `ValueError`，越界抛 `IndexError`。验证时 `entries` 的索引序列须与 `proof.indices` 完全一致；`entries`、`proof`、`root` 或摘要的类型错误抛 `TypeError`；空项、乱序、越界、数量不符、摘要长度错误及任何篡改均返回 `False`。

### Fiat-Shamir 转录

挑战 `c` 为 SHA-256 摘要的大端整数模 `prime`。转录依次写入固定域 `b"zkregion/schnorr-fs/v1"`、`prime`、`generator`、`public_key`、`t`、`context`、`message`；每项前置四字节无符号大端长度，整数取最短无符号大端编码。证明使用独立的临时随机数 `k`，与交互式 nonce 互不影响；应答 `s` 仍按普通整数计算、不针对群阶取模。

### Schnorr 批量验证

`verify_batch` 验证同一公钥下的一批 Fiat-Shamir 证明。`entries` 须为 `SchnorrBatchEntry` 的非字符串序列（空批返回 `False`）；每个结构合法的条目按既有转录重算挑战 `c`，并恰调用一次 `randbelow(prime - 1)` 得 `r`，取非零系数 `a = r + 1`，最终只检查一次聚合等式 `g**Σ(a*s) == Π(t**a * public_key**(a*c)) (mod prime)`，而非逐项验证的布尔汇总。重复条目合法，各自独立取系数；传入固定的 `randbelow` 结果可重复，缺省为 `secrets.randbelow`。

`entries`、条目字段、`proof` 或 `randbelow` 的类型错误抛 `TypeError`（`bool` 不算整数）；系数来源返回非整数抛 `TypeError`，超出 `[0, prime - 1)` 抛 `ValueError`。commitment 越界、response 为负、消息或 context 不匹配、错误公钥或任一篡改均返回 `False`，无效证明允许短路。验证不改写输入，也不触碰证明方的交互式 nonce。注意：默认群与这里的随机线性组合仅供演示，未做生产级安全分析。

### Pedersen 陷门承诺

对量化坐标 `value`（编码为相对下界的偏移 `m = value - lower`）做 Pedersen 承诺：`C = g**m * h**r mod prime`。`pedersen_commit(value, lower, upper, ...)` 返回冻结的 `PedersenCommitment` 对象与盲因子 `r`；对象保存 `commitment`、`element`、`lower`、`upper`、`prime`、`generator`、`h`，**不保存盲因子**。

- 必须满足 `lower <= value <= upper` 且区间宽 `upper - lower < prime - 1`，否则抛 `ValueError`；
- `prime`、`generator` 缺省取 `DEFAULT_PRIME` / `DEFAULT_GENERATOR`；`h` 缺省为 `g**2 mod prime`；
- 盲因子缺省为 `randbelow(prime - 2) + 1`（即 `secrets.randbelow`），也可用 `blinding=` 显式给出；`r` 必须位于 `[1, prime - 1)`，否则抛 `ValueError`；
- 所有数值参数只接受非 `bool` 整数：`value`、`lower`、`upper`、`prime`、`generator`、`h`、`blinding` 类型错误抛 `TypeError`；`prime > 3`，`generator`、`h` 必须位于 `(1, prime)`，否则抛 `ValueError`；
- `randbelow` 不可调用或返回非整数抛 `TypeError`；

`verify_pedersen_opening(commitment_obj, value, blinding)` 直接复用对象上的群参数与边界，验证方无需另行传入。对象或其任一字段、`value`、`blinding` 类型错误抛 `TypeError`；`element` 或 `value` 越界、盲因子非法、以及任何错误开合（错误 value 或错误 blinding）均返回 `False` 而非异常。验证不改写输入。

**陷门警告（重要）**：默认 `h = g**2 mod prime` 相对 `g` 的离散对数是公开已知的（`log_g(h) = 2`），知道陷门即可对同一承诺给出不同开合（`(m, r)` 与 `(m - 2, r + 1)` 等价），因此默认设置下承诺**不具备绑定性**，仅供演示协议流程；它也**不是范围证明**——承诺本身既不证明也不强制 `value` 落在区间内，范围检查只是开合验证的一部分。需要绑定时应传入离散对数未知的 `h`（由可信设置生成）。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。承诺只支持单点开合，没有范围证明，区域判定也只是朴素的坐标比较，不检查坐标是否经过承诺绑定；批量验证所用的随机线性组合与默认群一样仅供演示。Pedersen 承诺默认 `h = g**2` 的陷门已知、绑定性被破坏，同样仅供演示，且不是范围证明。

## 测试

```bash
python3 -m unittest discover -s tests
```
