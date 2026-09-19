# zkregion

面向区域成员关系的承诺与证明原语。提供哈希承诺、素域乘法群上的 Schnorr 证明（交互式与 Fiat-Shamir 非交互式），以及量化整数坐标下的矩形区域判定。

## 环境

Python 3.10+，只依赖标准库（`hashlib`、`hmac`、`secrets`、`struct`）。

## 使用

```python
from zkregion import Region, SchnorrProver, SchnorrVerifier, commit, verify_opening

commitment, nonce = commit(b"coordinate")
assert verify_opening(commitment, b"coordinate", nonce)

prover = SchnorrProver(secret=12345)
verifier = SchnorrVerifier(prover.public_key)
t = prover.new_commitment()
c = 987654321
s = prover.respond(c)
assert verifier.verify(t, c, s)

proof = prover.prove(b"region/42", context=b"session-7")
assert verifier.verify_proof(b"region/42", proof, context=b"session-7")

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
  - `prove(message, *, context=b"") -> SchnorrProof` — Fiat-Shamir 非交互证明；独立取一次性随机数，不读写交互式 nonce
- `SchnorrVerifier(public_key, *, prime, generator)` — `verify(commitment, challenge, response)`；`verify_proof(message, proof, *, context=b"") -> bool`
- `SchnorrProof(commitment, response)` — 不可变数据类，两个字段均为 `int`
- `Region(min_x, max_x, min_y, max_y)` — 闭区间矩形；`contains(x, y)`

## Fiat-Shamir 转录

非交互挑战 `c = SHA-256(transcript) mod prime`，转录依次拼接以下各项，每项前置四字节无符号大端长度；整数采用最短无符号大端编码：

1. 固定域分隔符 `b"zkregion/schnorr-fs/v1"`
2. `prime`、`generator`、`public_key`、承诺 `t = g**k mod prime`
3. `context`（默认 `b""`）、`message`

生成时独立取 `k = randbelow(prime-1) + 1`，应答 `s = k + c*secret`（不按群阶取模）；验证时重算 `c` 并检查 `g**s mod prime == t * public_key**c mod prime`。`message`、`context` 必须是 `bytes`，`proof` 必须是 `SchnorrProof` 且字段为 `int`，否则抛 `TypeError`；`commitment` 不在 `[1, prime)` 或 `response` 为负时返回 `False`。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。交互式流程的挑战仍由验证者直接提供；非交互式流程通过 Fiat-Shamir 转换支持离线验证，但没有强硬性（rogue-key）绑定、随机化设备或前缀防误用措施。承诺只支持单点开合，没有范围证明、没有 Merkle 包含证明、没有批量或聚合验证，区域判定也只是朴素的坐标比较，不检查坐标是否经过承诺绑定。

## 测试

```bash
python3 -m unittest discover -s tests
```
