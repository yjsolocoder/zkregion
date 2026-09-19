# zkregion

面向区域成员关系的承诺与交互式证明原语。提供哈希承诺、素域乘法群上的 Schnorr 交互证明，以及量化整数坐标下的矩形区域判定。

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
- `Region(min_x, max_x, min_y, max_y)` — 闭区间矩形；`contains(x, y)`

### Fiat-Shamir 转录

挑战 `c` 为 SHA-256 摘要的大端整数模 `prime`。转录依次写入固定域 `b"zkregion/schnorr-fs/v1"`、`prime`、`generator`、`public_key`、`t`、`context`、`message`；每项前置四字节无符号大端长度，整数取最短无符号大端编码。证明使用独立的临时随机数 `k`，与交互式 nonce 互不影响；应答 `s` 仍按普通整数计算、不针对群阶取模。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。承诺只支持单点开合，没有范围证明、没有 Merkle 包含证明、没有批量或聚合验证，区域判定也只是朴素的坐标比较，不检查坐标是否经过承诺绑定。

## 测试

```bash
python3 -m unittest discover -s tests
```
