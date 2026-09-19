# zkregion

面向区域成员关系的承诺与交互式证明原语。提供哈希承诺、素域乘法群上的 Schnorr 交互证明、确定性 SHA-256 Merkle 包含证明，以及量化整数坐标下的矩形区域判定。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`hmac`、`secrets`）。

## 使用

```python
from zkregion import Region, SchnorrProof, SchnorrProver, SchnorrVerifier, commit, verify_opening

commitment, nonce = commit(b"coordinate")
assert verify_opening(commitment, b"coordinate", nonce)

prover = SchnorrProver(secret=12345)
verifier = SchnorrVerifier(prover.public_key)
t = prover.new_commitment()
c = 987654321
s = prover.respond(c)
assert verifier.verify(t, c, s)

# 非交互 Fiat-Shamir 证明
proof = prover.prove(b"payload", context=b"session-1")
assert verifier.verify_proof(b"payload", proof, context=b"session-1")

# Merkle 包含证明
from zkregion import merkle_root, prove_inclusion, verify_inclusion

leaves = [b"alpha", b"beta", b"gamma"]
root = merkle_root(leaves)
inclusion = prove_inclusion(leaves, 1)
assert verify_inclusion(b"beta", inclusion, root)

# 紧凑 Merkle 多包含证明：一次证明多片叶子，验证无需完整叶集
from zkregion import prove_multi_inclusion, verify_multi_inclusion

multi = prove_multi_inclusion(leaves, [0, 2])
entries = [(0, b"alpha"), (2, b"gamma")]   # 按 proof.indices 顺序给出 (index, leaf)
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
- `SchnorrProver(secret, *, prime, generator, randbelow)`
  - `public_key` — `g**secret mod prime`
  - `new_commitment()` — 生成一次性随机数并返回 `g**k mod prime`
  - `respond(challenge)` — 返回 `k + challenge * secret`（不取模）
  - `prove(message, *, context=b"") -> SchnorrProof` — Fiat-Shamir 非交互证明
- `SchnorrVerifier(public_key, *, prime, generator)`
  - `verify(commitment, challenge, response)` — 交互式验证
  - `verify_proof(message, proof, *, context=b"") -> bool` — 非交互证明验证
- `SchnorrProof(commitment, response)` — 不可变证明对象（`t = g**k mod prime`，`s = k + c * secret`）
- `merkle_root(leaves) -> bytes` — 非空 `bytes` 序列的 Merkle 根
- `prove_inclusion(leaves, index) -> MerkleProof` — 按零基索引生成包含证明
- `verify_inclusion(leaf, proof, root) -> bool` — 验证包含证明
- `MerkleProof(index, siblings)` — 不可变证明对象，`siblings` 为按叶到根排列的 `tuple[bytes, ...]`
- `prove_multi_inclusion(leaves, indices) -> MerkleMultiProof` — 为多个零基索引生成一份紧凑包含证明
- `verify_multi_inclusion(entries, proof, root) -> bool` — 按 `entries` 中的 `(index, leaf)` 对验证多包含证明，无需完整叶集
- `MerkleMultiProof(leaf_count, indices, siblings)` — 不可变多包含证明对象；`indices` 为严格递增的 `tuple[int, ...]`，`siblings` 为按层（叶到根、层内从左到右）排列的 `tuple[bytes, ...]`
- `Region(min_x, max_x, min_y, max_y)` — 闭区间矩形；`contains(x, y)`

### Merkle 树构造

叶摘要为 `SHA-256(b"\x00" + len4 + leaf)`，其中 `len4` 是叶长的四字节无符号大端编码；内部节点摘要为 `SHA-256(b"\x01" + left + right)`。每层按输入顺序两两合并，奇数节点复制末项后再合并；单叶树的根就是叶摘要，证明路径为空。重复叶按调用方给出的零基索引定位，不按内容搜索。`leaves` 为空抛 `ValueError`，叶或索引类型错误抛 `TypeError`，索引越界抛 `IndexError`。验证时 `leaf`、`root` 与各兄弟摘要须为 `bytes`（后两者恰 32 字节），`proof` 须为 `MerkleProof` 且 `index` 为非负整数；类型错误抛 `TypeError`，摘要长度或索引结构非法返回 `False`。验证按 `index` 奇偶决定左右顺序并逐层整除二；叶、索引、路径或根被篡改均返回 `False`，所有入口均不改写输入。

### Merkle 多包含证明

多包含证明复用同一哈希与奇数末项复制规则，用一份证明覆盖多片叶子。`indices` 须非空、严格递增且无重复（非 bool 整数、落在叶数范围内）：类型错误抛 `TypeError`，空、重复或乱序抛 `ValueError`，越界抛 `IndexError`。生成时逐层从左到右处理：被证节点的兄弟本身也被证则直接合并、不收集兄弟；奇数层末项无兄弟则自复制；其余情况收集兄弟摘要；父位置逐层去重。证明确定且最小——证明全部叶子时 `siblings` 为空。验证时 `entries` 按 `proof.indices` 的顺序给出 `(index, leaf)` 对，同法恢复根且必须恰好耗尽 `siblings`；`entries`、`proof`、`root` 或摘要类型错误抛 `TypeError`，空项、乱序、越界、数量或摘要长度不符及任何篡改均返回 `False`。

### Fiat-Shamir 转录

挑战 `c` 为 SHA-256 摘要的大端整数模 `prime`。转录依次写入固定域 `b"zkregion/schnorr-fs/v1"`、`prime`、`generator`、`public_key`、`t`、`context`、`message`；每项前置四字节无符号大端长度，整数取最短无符号大端编码。证明使用独立的临时随机数 `k`，与交互式 nonce 互不影响；应答 `s` 仍按普通整数计算、不针对群阶取模。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。承诺只支持单点开合，没有范围证明、没有批量或聚合验证，区域判定也只是朴素的坐标比较，不检查坐标是否经过承诺绑定。

## 测试

```bash
python3 -m unittest discover -s tests
```
