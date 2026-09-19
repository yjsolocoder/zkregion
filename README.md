# zkregion

面向区域成员关系的承诺与交互式证明原语。提供哈希承诺、素域乘法群上的 Schnorr 交互证明、确定性 SHA-256 Merkle 包含证明、量化区间的 Pedersen 陷门承诺及其上的 Schnorr OR 非交互区间证明、二维矩形区域成员非交互证明，以及量化整数坐标下的矩形区域判定。

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

# Pedersen 陷门承诺：对区间 [lower, upper] 内的量化整数值做承诺
from zkregion import pedersen_commit, verify_pedersen_opening

commitment, blinding = pedersen_commit(40, 0, 100)
assert verify_pedersen_opening(commitment, 40, blinding)
assert not verify_pedersen_opening(commitment, 41, blinding)

# Pedersen 非交互区间证明（Schnorr OR）：证明承诺值落在声明区间内
from zkregion import prove_range, verify_range

proof = prove_range(commitment, 40, blinding, context=b"session-1")
assert verify_range(commitment, proof, context=b"session-1")
assert not verify_range(commitment, proof, context=b"other")

# 二维区域成员非交互证明：证明承诺的 (x, y) 落在矩形区域内
from zkregion import RegionProof, prove_region, verify_region

region = Region(0, 100, 0, 100)
x_commitment, x_blinding = pedersen_commit(40, 0, 100)
y_commitment, y_blinding = pedersen_commit(60, 0, 100)
region_proof = prove_region(
    x_commitment, y_commitment, 40, 60, x_blinding, y_blinding, region, context=b"session-1"
)
assert verify_region(x_commitment, y_commitment, region, region_proof, context=b"session-1")
assert not verify_region(x_commitment, y_commitment, region, region_proof, context=b"other")

# 二维区域证明的批量验证（按 (prime, generator, h) 分组做随机线性组合）
from zkregion import RegionBatchEntry, verify_region_batch

batch = [
    RegionBatchEntry(x_commitment, y_commitment, region, region_proof, b"session-1"),
    RegionBatchEntry(x_commitment, y_commitment, region, region_proof, b"session-1"),
]
assert verify_region_batch(batch)

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
- `pedersen_commit(value, lower, upper, *, prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR, h=None, blinding=None, randbelow=secrets.randbelow) -> (PedersenCommitment, blinding)` — 区间量化值的 Pedersen 承诺
- `verify_pedersen_opening(commitment, value, blinding) -> bool` — 复用承诺对象内参数验证开合
- `PedersenCommitment(element, lower, upper, prime, generator, h)` — 不可变承诺对象；承诺值为 `element = g**(value-lower) * h**blinding mod prime`
- `prove_range(commitment, value, blinding, context=b"", *, randbelow=secrets.randbelow) -> RangeProof` — 生成 Pedersen 承诺的非交互区间证明（Schnorr OR）
- `verify_range(commitment, proof, context=b"") -> bool` — 验证区间证明
- `RangeProof(t, e, s)` — 不可变区间证明对象，三个字段均为长度 `upper - lower + 1` 的 `tuple[int, ...]`
- `prove_region(x_commitment, y_commitment, x, y, x_blinding, y_blinding, region, context=b"", *, randbelow=secrets.randbelow) -> RegionProof` — 生成二维矩形区域成员非交互证明
- `verify_region(x_commitment, y_commitment, region, proof, context=b"") -> bool` — 验证区域成员证明，无需坐标或盲因子
- `RegionProof(x_proof, y_proof)` — 不可变区域证明对象，两字段均为 `RangeProof`
- `verify_region_batch(entries, *, randbelow=secrets.randbelow) -> bool` — 区域证明的批量验证，按 `(prime, generator, h)` 分组做一次随机线性组合
- `RegionBatchEntry(x_commitment, y_commitment, region, proof, context=b"")` — 不可变批量验证条目，字段次序与 `verify_region` 入参一致
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

### Pedersen 量化坐标陷门承诺

`pedersen_commit(value, lower, upper, ...)` 对声明在闭区间 `[lower, upper]` 内的量化整数值做 Pedersen 承诺：编码消息为偏移量 `m = value - lower`，承诺元素为

```
element = g**m * h**r mod prime
```

其中 `r` 为盲因子。`prime` 与 `g` 缺省取 `DEFAULT_PRIME` / `DEFAULT_GENERATOR`；`h` 缺省为 `g**2 mod prime`；盲因子缺省由 `randbelow(prime - 2) + 1` 生成（缺省源为 `secrets.randbelow`），也可用 `blinding=` 显式给出。函数返回 `(PedersenCommitment, blinding)`，承诺对象是冻结的 dataclass，携带 `element`、`lower`、`upper`、`prime`、`generator`、`h`，验证方无需其他带外参数。

约束：必须有 `lower <= value <= upper`，且区间宽度 `upper - lower < prime - 1`；盲因子须在 `[1, prime - 1)`；`prime > 3`，`g` 与 `h` 均须位于 `(1, prime)`——无论 `h` 是显式传入还是按缺省 `g**2 mod prime` 计算，都会校验 `1 < h < prime`，不满足抛 `ValueError`。所有数值只接受非 `bool` 整数（`True`/`False` 不算整数）：`value`、边界、`prime`、`g`、`h`、`blinding` 类型错误抛 `TypeError`；`randbelow` 不可调用或其返回值不是整数抛 `TypeError`。非法区间、越界 `value`、非法群参数或盲因子越界抛 `ValueError`；`randbelow` 返回值超出 `[0, prime - 2)` 也抛 `ValueError`。

`verify_pedersen_opening(commitment, value, blinding)` 只复用承诺对象内的群参数与区间，按同一公式重算并比对：`commitment` 不是 `PedersenCommitment` 或其字段、`value`、`blinding` 类型错误时抛 `TypeError`；对象内 `element` 或群参数越界、区间非法、`value` 越界、盲因子越界，或开合错误（错误的 `value`/`blinding`/`element`）一律返回 `False`。验证不改写任何输入。

> **警告：默认 `h = g**2 mod prime` 的离散对数（`log_g(h) = 2`）是公开已知的，因此默认配置下的承诺不具备绑定性**——知道陷门即可对同一 `element` 给出多个开合（例如 `(value, r)` 与 `(value + 2, r - 1)`），演示程序会展示这一点。生产用途必须传入离散对数未知（无可信设置陷门）的 `h`。此外，单独的承诺对象只是带区间声明的承诺；"承诺值属于某区间" 的零知识论断由下文的 `prove_range` / `verify_range` 提供，且同样只是演示级安全强度。

### Pedersen 非交互区间证明

`prove_range(commitment, value, blinding, context=b"")` 在 Pedersen 承诺之上生成 Schnorr OR 风格的非交互区间证明，`verify_range(commitment, proof, context=b"")` 验证。对声明区间 `[lower, upper]` 内的每个偏移 `i`（共 `n = upper - lower + 1` 个，**最多 256 个整数**，超限生成抛 `ValueError`、验证返回 `False`）定义

```
D_i = element * g**(-i) mod prime
```

承诺以 `(value, r)` 开合当且仅当 `D_(value-lower) = h**r`，因此区间证明等价于"至少一个 `D_i` 以 `h` 为底的离散对数等于盲因子 `r`" 的 OR 证明。真实分支走诚实 Schnorr：取随机 `k`，`t = h**k mod prime`，挑战份额 `e = (c - Σ其他 e_i) mod prime`，响应 `s = k + e * r`（非负、不取模）；其余分支模拟：随机取 `e_i ∈ [0, prime)` 与非负 `s_i`，令 `t_i = h**s_i * D_i**(-e_i) mod prime`。证明为冻结的 `RangeProof(t, e, s)`，三个字段都是长度 `n` 的整数元组。

挑战 `c` 为 SHA-256 摘要的大端整数模 `prime`。转录依次写入域 `b"zkregion/pedersen-range/v1"`、承诺六字段（`element`、`lower`、`upper`、`prime`、`generator`、`h`）、`context`、`n` 与全部 `t_i`；每项前置四字节无符号大端长度，整数编码为十进制 ASCII。

验证要求：每个 `t_i ∈ [1, prime)`、`e_i ∈ [0, prime)`、`s_i ≥ 0`，`sum(e) mod prime == c`，且每个分支满足 Schnorr 等式 `h**s_i == t_i * D_i**e_i (mod prime)`。生成前会先复用 `verify_pedersen_opening` 校验开合，开合不符抛 `ValueError`；类型错误（含 `bool` 整数、非元组证明字段、非 `bytes` 的 `context`、不可调用的 `randbelow`）抛 `TypeError`；其他非法结构、篡改或绑定不符（错误的承诺、`context` 或证明）一律返回 `False`。入口均不改写输入。

### 二维区域成员非交互证明

`prove_region(x_commitment, y_commitment, x, y, x_blinding, y_blinding, region, context=b"")` 把"承诺的 `(x, y)` 落在 `Region(min_x, max_x, min_y, max_y)` 内"拆成两条轴上的区间证明：x 承诺的声明区间必须恰好等于 `(region.min_x, region.max_x)`，y 承诺必须恰好等于 `(region.min_y, region.max_y)`，生成时先校验区间匹配，再复用 `prove_range` 验证开合并生成子证明。证明为冻结的 `RegionProof(x_proof, y_proof)`，两字段均为 `RangeProof`；验证方调用 `verify_region(x_commitment, y_commitment, region, proof, context=b"")`，只需两个承诺、区域与证明，无需坐标或盲因子。

每条轴的子证明在派生 context 下进行，派生 context 按以下项目逐项前置四字节无符号大端长度拼接：域 `b"zkregion/region/v1"`、轴标签 `b"x"` 或 `b"y"`、外部 `context`、Region 四边界（`min_x`、`max_x`、`min_y`、`max_y`）、x 承诺六字段、y 承诺六字段（均按数据类字段顺序）；整数编码为十进制 ASCII。因此证明同时绑定区域、外部 context、两个承诺与轴分配——更换区域、context、承诺或交换两轴（含交换子证明、交换承诺）都验证失败。

`context` 只接受 `bytes`，所有整数拒绝 `bool`；承诺、区域、证明对象或其字段、数值类型错误抛 `TypeError`。生成时区间不匹配、开合无效或轴区间超过 256 个整数抛 `ValueError`；验证时上述非类型错误、结构非法、篡改或绑定不符一律返回 `False`。入口均不改写输入。

### 二维区域证明批量验证

`verify_region_batch(entries, *, randbelow=secrets.randbelow)` 一次验证一批 `RegionBatchEntry`，每个条目就是 `verify_region` 的五个入参（`x_commitment`、`y_commitment`、`region`、`proof`、`context`，后者缺省 `b""`）冻结成的不可变数据类。`entries` 须为非字符串、非空序列：空批返回 `False`，重复条目合法并各自独立取系数。漏项无法被发现，批次完整性由调用方保证。

每个条目逐字节复用既定的 Region 派生 context 与 RangeProof 转录：x/y 承诺的声明区间必须分别等于区域的 `(min_x, max_x)` / `(min_y, max_y)`，两个子证明必须都是 `RangeProof` 且 `t`/`e`/`s` 元组长度恰为各自轴区间的整数数，逐个校验 `t_i ∈ [1, prime)`、`e_i ∈ [0, prime)`、`s_i ≥ 0`，以及 `sum(e) mod prime` 等于转录挑战。上述结构、区间、挑战和或任何绑定（区域、承诺、外部 `context`、轴分配，含跨条目重组）不符都返回 `False`，允许短路。

通过结构校验后，**每条 RangeProof 分支**（每个条目的每个轴偏移 `i`）恰调用一次 `randbelow(prime - 1)` 得 `r`，取非零系数 `a = r + 1`；`D_i = element * generator**(-i) mod prime` 的定义与单点验证完全一致。所有分支按 `(prime, generator, h)` 分组，每组只检查一次聚合等式

```
h**Σ(a*s) == Π(t**a * D_i**(a*e))   (mod prime)
```

即把该组内所有条目的两条轴、全部分支纳入同一个随机线性组合，而**不是**逐条分支或逐条目验证后做布尔汇总——因此同组内响应误差可以在系数为 1 时相消，而不同 `(prime, generator, h)`（不同群或不同 `h`）之间不能跨组相消。传入固定的 `randbelow` 结果可重复，缺省为 `secrets.randbelow`。

类型错误（含 `bool` 整数、非元组证明字段、非 `bytes` 的 `context`、`randbelow` 不可调用或返回非整数）抛 `TypeError`；系数来源返回值超出 `[0, prime - 1)` 抛 `ValueError`。其余非法结构、篡改、区域/承诺/context 绑定错误、跨项重组、子证明数量错误均返回 `False`；入口不改写任何输入。与 Schnorr 批量验证一样，这里的随机线性组合只供演示。

### Fiat-Shamir 转录

挑战 `c` 为 SHA-256 摘要的大端整数模 `prime`。转录依次写入固定域 `b"zkregion/schnorr-fs/v1"`、`prime`、`generator`、`public_key`、`t`、`context`、`message`；每项前置四字节无符号大端长度，整数取最短无符号大端编码。证明使用独立的临时随机数 `k`，与交互式 nonce 互不影响；应答 `s` 仍按普通整数计算、不针对群阶取模。

### Schnorr 批量验证

`verify_batch` 验证同一公钥下的一批 Fiat-Shamir 证明。`entries` 须为 `SchnorrBatchEntry` 的非字符串序列（空批返回 `False`）；每个结构合法的条目按既有转录重算挑战 `c`，并恰调用一次 `randbelow(prime - 1)` 得 `r`，取非零系数 `a = r + 1`，最终只检查一次聚合等式 `g**Σ(a*s) == Π(t**a * public_key**(a*c)) (mod prime)`，而非逐项验证的布尔汇总。重复条目合法，各自独立取系数；传入固定的 `randbelow` 结果可重复，缺省为 `secrets.randbelow`。

`entries`、条目字段、`proof` 或 `randbelow` 的类型错误抛 `TypeError`（`bool` 不算整数）；系数来源返回非整数抛 `TypeError`，超出 `[0, prime - 1)` 抛 `ValueError`。commitment 越界、response 为负、消息或 context 不匹配、错误公钥或任一篡改均返回 `False`，无效证明允许短路。验证不改写输入，也不触碰证明方的交互式 nonce。注意：默认群与这里的随机线性组合仅供演示，未做生产级安全分析。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。区域判定只是朴素的坐标比较，不检查坐标是否经过承诺绑定；批量验证所用的随机线性组合与默认群一样仅供演示。Pedersen 承诺默认的 `h = g**2 mod prime` 带有公开陷门、破坏绑定性；其上的 Schnorr OR 区间证明与二维区域成员证明同样是演示级构造——区间上限 256 个整数、挑战来自 SHA-256 Fiat-Shamir 转录、群参数与默认 `h` 均未做生产级安全分析，不能用于真实部署。

## 测试

```bash
python3 -m unittest discover -s tests
```
