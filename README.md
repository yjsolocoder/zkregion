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

# 多公钥 / 多群的批量验证（每个条目自带公钥与群参数）
from zkregion import MultiSchnorrEntry, verify_schnorr_batch

other = SchnorrProver(secret=987654321)
multi = [
    MultiSchnorrEntry(prover.public_key, b"alpha", prover.prove(b"alpha", context=b"s1"), context=b"s1"),
    MultiSchnorrEntry(other.public_key, b"beta", other.prove(b"beta", context=b"s1"), b"s1"),
]
assert verify_schnorr_batch(multi)

# Merkle 承诺的 Schnorr 完整批验：整批条目先提交到一棵 Merkle 树
from zkregion import BoundSchnorrBatch, merkle_root, prove_multi_inclusion, verify_bound

def enc(value):
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")

def bound_leaf(entry):
    items = (
        b"zkregion/schnorr-fs/v1",
        enc(entry.prime), enc(entry.generator), enc(entry.public_key),
        enc(entry.proof.commitment), entry.context, entry.message,
        enc(entry.proof.response),
    )
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)

leaves = [bound_leaf(entry) for entry in multi]
root = merkle_root(leaves)
proof = prove_multi_inclusion(leaves, tuple(range(len(leaves))))
batch = BoundSchnorrBatch(tuple(multi), len(multi), proof)
assert verify_bound(batch, root)

# Merkle 包含证明
from zkregion import prove_inclusion, verify_inclusion

leaves = [b"alpha", b"beta", b"gamma"]
root = merkle_root(leaves)
inclusion = prove_inclusion(leaves, 1)
assert verify_inclusion(b"beta", inclusion, root)

# Merkle 多包含证明（一次证明多片叶子，无需完整叶集即可验证）
from zkregion import verify_multi_inclusion

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

# 区间证明的批量验证（按 (prime, generator, h) 分组做随机线性组合）
from zkregion import RangeBatchEntry, verify_range_batch

range_batch = [
    RangeBatchEntry(commitment, proof, b"session-1"),
    RangeBatchEntry(commitment, proof, b"session-1"),
]
assert verify_range_batch(range_batch)

# Merkle 承诺的区间证明完整批验：整批区间条目先提交到一棵 Merkle 树
from zkregion import BoundRangeBatch, verify_range_bound

def bound_range_leaf(entry):
    c = entry.commitment
    items = [b"zkregion/range-bound/v1"]
    items += [str(v).encode("ascii")
              for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)]
    items.append(entry.context)
    for seq in (entry.proof.t, entry.proof.e, entry.proof.s):
        items.append(str(len(seq)).encode("ascii"))
        items += [str(v).encode("ascii") for v in seq]
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)

range_leaves = [bound_range_leaf(entry) for entry in range_batch]
range_root = merkle_root(range_leaves)
range_proof = prove_multi_inclusion(range_leaves, tuple(range(len(range_leaves))))
bound_range = BoundRangeBatch(tuple(range_batch), len(range_batch), range_proof)
assert verify_range_bound(bound_range, range_root)

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

# Merkle 承诺的区域证明完整批验：整批区域条目先提交到一棵 Merkle 树
from zkregion import BoundRegionBatch, verify_region_bound

def bound_region_leaf(entry):
    items = [b"zkregion/region-bound/v1"]
    for c in (entry.x_commitment, entry.y_commitment):
        items += [str(v).encode("ascii")
                  for v in (c.element, c.lower, c.upper, c.prime, c.generator, c.h)]
    r = entry.region
    items += [str(v).encode("ascii") for v in (r.min_x, r.max_x, r.min_y, r.max_y)]
    items.append(entry.context)
    for sub in (entry.proof.x_proof, entry.proof.y_proof):
        for seq in (sub.t, sub.e, sub.s):
            items.append(str(len(seq)).encode("ascii"))
            items += [str(v).encode("ascii") for v in seq]
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)

region_leaves = [bound_region_leaf(entry) for entry in batch]
region_root = merkle_root(region_leaves)
region_proof = prove_multi_inclusion(region_leaves, tuple(range(len(region_leaves))))
bound_region = BoundRegionBatch(tuple(batch), len(batch), region_proof)
assert verify_region_bound(bound_region, region_root)

Region(0, 100, 0, 100).contains(50, 50)     # True

# 实例内防重放：session id 一次性绑定到一条 Schnorr 条目
from zkregion import ReplayGuard, ReplayBinding

guard = ReplayGuard()
entry = MultiSchnorrEntry(
    prover.public_key, b"spend", prover.prove(b"spend", context=b"s"), b"s"
)
binding = guard.bind_once(entry, b"session-1")            # 登记待用绑定
assert guard.check(entry, binding)                         # 验签并消费 session id
assert not guard.check(entry, binding)                     # 二次提交被拒
try:
    guard.bind_once(entry, b"session-1")                   # 待用或已消费 id 不能重绑
except ValueError:
    pass

# 区间证明的实例内一次性绑定
from zkregion import RangeReplayGuard

range_guard = RangeReplayGuard()
range_entry = RangeBatchEntry(commitment, proof, b"session-1")
range_binding = range_guard.bind_once(range_entry, b"session-1")
assert range_guard.check(range_entry, range_binding)       # 验区间证明并消费 session id
assert not range_guard.check(range_entry, range_binding)   # 二次提交被拒

# 二维区域证明的实例内一次性绑定
from zkregion import RegionReplayGuard

region_guard = RegionReplayGuard()
region_entry = RegionBatchEntry(
    x_commitment, y_commitment, region, region_proof, b"session-1"
)
region_binding = region_guard.bind_once(region_entry, b"session-1")
assert region_guard.check(region_entry, region_binding)    # 验区域证明并消费 session id
assert not region_guard.check(region_entry, region_binding)  # 二次提交被拒

# 整批 BoundRegionBatch 与 Merkle 根的实例内一次性绑定
from zkregion import BoundRegionReplayGuard

brg = BoundRegionReplayGuard()
brg_binding = brg.bind_once(bound_region, region_root, b"session-1")
assert brg.check(bound_region, region_root, brg_binding)       # 先验根与整批证明再消费
assert not brg.check(bound_region, region_root, brg_binding)   # 二次提交被拒

# 整批 BoundRangeBatch 与 Merkle 根的实例内一次性绑定
from zkregion import BoundRangeReplayGuard

brr = BoundRangeReplayGuard()
brr_binding = brr.bind_once(bound_range, range_root, b"session-1")
assert brr.check(bound_range, range_root, brr_binding)         # 先验根与整批证明再消费
assert not brr.check(bound_range, range_root, brr_binding)     # 二次提交被拒
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
- `verify_range_batch(entries, *, randbelow=secrets.randbelow) -> bool` — 区间证明的批量验证，按 `(prime, generator, h)` 分组做一次随机线性组合
- `RangeBatchEntry(commitment, proof, context=b"")` — 不可变批量验证条目，字段类型依次为 `PedersenCommitment`、`RangeProof`、`bytes`，字段次序与 `verify_range` 入参一致
- `verify_range_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的区间证明完整批验：先 `verify_multi_inclusion` 验根，再以同一 `randbelow` 调 `verify_range_batch` 验证明
- `BoundRangeBatch(entries, leaf_count, proof)` — 冻结的完整批对象；字段依次为 `tuple[RangeBatchEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变
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
- `verify_schnorr_batch(entries, *, randbelow=secrets.randbelow) -> bool` — 多公钥批量验证，按 `(prime, generator)` 分组做一次随机线性组合
- `MultiSchnorrEntry(public_key, message, proof, context=b"", prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR)` — 不可变多公钥批量验证条目；前三字段依次为 `int`、`bytes`、`SchnorrProof`，均为必填且可位置构造，值相等即相等
- `verify_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的 Schnorr 完整批验：先 `verify_multi_inclusion` 验根，再以同一 `randbelow` 调 `verify_schnorr_batch` 验签
- `BoundSchnorrBatch(entries, leaf_count, proof)` — 冻结的完整批对象；字段依次为 `tuple[MultiSchnorrEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变
- `verify_region_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的区域证明完整批验：先 `verify_multi_inclusion` 验根，再以同一 `randbelow` 调 `verify_region_batch` 验子证明
- `BoundRegionBatch(entries, leaf_count, proof)` — 冻结的完整批对象；字段依次为 `tuple[RegionBatchEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变
- `ReplayBinding(session_id, digest, expires_at=None)` — 冻结的一次性防重放绑定；字段依次为非空 `bytes`、`bytes` 摘要（不限定长度；两个守卫登记的均为 32 字节 SHA-256 摘要）、`None` 或非 `bool` 的 uint64 Unix 秒过期时间；可位置构造、按值相等且不可变
- `ReplayGuard()` — 实例内防重放登记册
  - `bind_once(entry: MultiSchnorrEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记本实例的待用绑定；待用或已消费的 `session_id` 重绑抛 `ValueError`
  - `check(entry, binding, *, now=None) -> bool` — 验本实例的待用等值绑定，以条目的公钥与群参数构造 `SchnorrVerifier` 并以 `message`、`proof`、`context` 调 `verify_proof`；成功才消费 `session_id`，任何拒绝都不消费
- `RangeReplayGuard()` — 区间证明的实例内防重放登记册
  - `bind_once(entry: RangeBatchEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记本实例的待用绑定；待用或已消费的 `session_id` 重绑抛 `ValueError`
  - `check(entry, binding, *, now=None) -> bool` — 验本实例的待用等值绑定，按字段顺序以 `commitment`、`proof`、`context` 调 `verify_range`；成功才消费 `session_id`，任何拒绝都不消费
- `RegionReplayGuard()` — 二维区域证明的实例内防重放登记册
  - `bind_once(entry: RegionBatchEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记本实例的待用绑定；待用或已消费的 `session_id` 重绑抛 `ValueError`
  - `check(entry, binding, *, now=None) -> bool` — 验本实例的待用等值绑定，按字段顺序以 `x_commitment`、`y_commitment`、`region`、`proof`、`context` 调 `verify_region`；成功才消费 `session_id`，任何拒绝都不消费
- `BoundRegionReplayGuard()` — Merkle 承诺区域批与 Merkle 根的实例内防重放登记册
  - `bind_once(batch: BoundRegionBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundRegionBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空值、uint64 越界或重绑抛 `ValueError`，类型错误抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 重算绑定摘要、检查期限后委托 `verify_region_bound` 并透传同一随机源；成功才消费 `session_id`，其余无效一律返回 `False` 且不消费
- `BoundRangeReplayGuard()` — Merkle 承诺区间批与 Merkle 根的实例内防重放登记册
  - `bind_once(batch: BoundRangeBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundRangeBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空值、uint64 越界或重绑抛 `ValueError`，类型错误抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 重算绑定摘要、检查期限后委托 `verify_range_bound` 并透传同一随机源；成功才消费 `session_id`，其余无效一律返回 `False` 且不消费
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

### 区间证明批量验证

`verify_range_batch(entries, *, randbelow=secrets.randbelow)` 一次验证一批 `RangeProof`，每个条目就是 `verify_range` 的三个入参（`commitment`、`proof`、`context`，后者缺省 `b""`）冻结成的不可变数据类 `RangeBatchEntry`；字段类型依次为 `PedersenCommitment`、`RangeProof`、`bytes`。`entries` 须为非字符串、非空序列：空批返回 `False`，重复条目合法并各自独立取系数。漏项无法被发现，批次完整性由调用方保证。

每个条目逐字节复用既定的 RangeProof 转录与结构校验：证明的 `t`/`e`/`s` 元组长度必须恰为承诺声明区间的整数数，逐个校验 `t_i ∈ [1, prime)`、`e_i ∈ [0, prime)`、`s_i ≥ 0`，以及 `sum(e) mod prime` 等于转录挑战——由此把承诺六字段（`element`、`lower`、`upper`、`prime`、`generator`、`h`）、声明区间与 `context` 全部绑定。上述结构、区间、挑战或任何绑定（承诺、`context`）不符都返回 `False`，允许短路。

通过结构校验后，**每条 RangeProof 分支**（每个条目的每个区间偏移 `i`）恰调用一次 `randbelow(prime - 1)` 得 `r`，取非零系数 `a = r + 1`；`D_i = element * generator**(-i) mod prime` 的定义与单点验证完全一致。所有分支按 `(prime, generator, h)` 分组，每组只检查一次聚合等式

```
h**Σ(a*s) == Π(t**a * D_i**(a*e))   (mod prime)
```

即把该组内所有条目的全部分支纳入同一个随机线性组合，而**不是**逐分支或逐条目验证后做布尔汇总——因此同组内响应误差可以在系数为 1 时相消，而不同 `(prime, generator, h)`（不同群或不同 `h`）之间不能跨组相消。传入固定的 `randbelow` 结果可重复，缺省为 `secrets.randbelow`。

类型错误（含 `bool` 整数、非元组证明字段、非 `bytes` 的 `context`、`randbelow` 不可调用或返回非整数）抛 `TypeError`；系数来源返回值超出 `[0, prime - 1)` 抛 `ValueError`。其余非法结构、篡改、承诺/context 绑定错误均返回 `False`；入口不改写任何输入。这里的随机线性组合只供演示。

### Merkle 承诺的区间证明完整批验

`BoundRangeBatch(entries, leaf_count, proof)` 把一批**完整**的区间证明条目与一棵 Merkle 树的多包含证明冻结在一起，三个字段依次为：

1. `entries: tuple[RangeBatchEntry, ...]` —— 必须是元组（不是列表），每项是 `RangeBatchEntry`；
2. `leaf_count: int` —— 正的非 `bool` 整数，且必须同时等于 `len(entries)` 与 `proof.leaf_count`；
3. `proof: MerkleMultiProof` —— 其 `indices` 必须无缺口、无重复、无乱序地恰好覆盖 `0 .. leaf_count - 1`（即等于 `tuple(range(leaf_count))`）。

三字段均可位置构造，对象按值相等且不可变（冻结 dataclass）。空批（`leaf_count < 1` 或 `entries` 为空）、缺项（数量不符）、`leaf_count` 与任一方不一致、索引乱序/重复/有缺口均返回 `False`。

每个条目的 Merkle 叶字节以域 `b"zkregion/range-bound/v1"` 开始，依次拼接：承诺六字段（`element`、`lower`、`upper`、`prime`、`generator`、`h`，按数据类字段顺序）与 `context`，再依次写入证明的 `t`、`e`、`s` 序列——每个序列先写十进制元素数再逐项写值。每个原子项前置四字节无符号大端长度，整数编码为十进制 ASCII（负号保留）。叶摘要仍按 Merkle 树构造一节的 `SHA-256(b"\x00" + len4 + leaf)` 计算。

`verify_range_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` 的验证分两步、次序固定：

1. 先以全部 `(index, leaf)`（`index` 即 0 起的条目位置）调用 `verify_multi_inclusion` 校验 Merkle 根；任一叶字节、proof 或根不符即返回 `False`，且在根校验通过前不消费任何随机数；
2. 根通过后，以**同一个 `randbelow`** 调用 `verify_range_batch(entries, randbelow=randbelow)` 验证明，随机源契约（每结构合法分支恰调用一次 `randbelow(prime - 1)`、非整数返回 `TypeError`、越界返回 `ValueError`）与输入完全沿用后者，不做包装或改动。

类型错误——`batch` 不是 `BoundRangeBatch`、`entries` 不是元组或含非 `RangeBatchEntry`、条目嵌套字段类型错误（含 `bool` 整数、非 `bytes` 的 `context`、非 `RangeProof`、非元组 `t`/`e`/`s`）、`leaf_count` 不是非 `bool` 整数、`proof`/`root` 类型错误、`randbelow` 不可调用——抛 `TypeError`；其余一切无效情形（空批、缺项、数量不符、索引缺口/重复/乱序、错误根、叶字节篡改、证明或转录不符、非随机随机源导致的 `False` 等）均返回 `False`。入口不改写任何输入。与其它批量验证一样，这里的随机线性组合只供演示。

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

### 多公钥 Schnorr 批量验证

`verify_schnorr_batch(entries, *, randbelow=secrets.randbelow)` 一次验证可能分属不同公钥、不同群的一批 Fiat-Shamir 证明：每个条目是冻结数据类 `MultiSchnorrEntry(public_key, message, proof, context=b"", prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR)`，字段依次为 `int`、`bytes`、`SchnorrProof` 及缺省的 `context:bytes`、`prime:int`、`generator:int`，六字段都可位置构造；条目值相等即相等且不可变。`entries` 须为非字符串、非空序列：空批返回 `False`，重复条目合法并各自独立取系数。漏项无法被发现，批次完整性由调用方保证。

每个条目逐字节复用既定的 Fiat-Shamir 转录（域、`prime`、`generator`、`public_key`、`t`、`context`、`message`）重算挑战 `c`，由此把条目六字段全部绑定。通过结构校验后，**每个条目恰调用一次** `randbelow(prime - 1)` 得 `r`，取非零系数 `a = r + 1`。条目按 `(prime, generator)` 分组，每组只检查一次聚合等式

```
g**Σ(a*s) == Π(t**a * public_key**(a*c))   (mod prime)
```

即同组内所有条目（可属不同 `public_key`，各自使用自身公钥）纳入同一个随机线性组合，而**不是**逐条目验证后做布尔汇总；不同 `(prime, generator)` 群之间不能跨组相消。传入固定的 `randbelow` 结果可重复，缺省为 `secrets.randbelow`。

`entries`、条目字段或 `randbelow` 的类型错误抛 `TypeError`（`bool` 不算整数；非 `bytes` 的 `message`/`context` 同样拒绝）；系数来源返回非整数抛 `TypeError`，超出 `[0, prime - 1)` 抛 `ValueError`。群参数非法、公钥或 commitment 越界、response 为负、消息/context 不匹配或任一篡改均返回 `False`，无效条目允许短路。入口不改写任何输入。与单公钥批量验证一样，这里的随机线性组合只供演示。

### Merkle 承诺的 Schnorr 完整批验

`BoundSchnorrBatch(entries, leaf_count, proof)` 把一批**完整**的多公钥 Schnorr 条目与一棵 Merkle 树的多包含证明冻结在一起，三个字段依次为：

1. `entries: tuple[MultiSchnorrEntry, ...]` —— 必须是元组（不是列表），每项是 `MultiSchnorrEntry`；
2. `leaf_count: int` —— 正的非 `bool` 整数，且必须同时等于 `len(entries)` 与 `proof.leaf_count`；
3. `proof: MerkleMultiProof` —— 其 `indices` 必须无缺口、无重复、无乱序地恰好覆盖 `0 .. leaf_count - 1`（即等于 `tuple(range(leaf_count))`）。

三字段均可位置构造，对象按值相等且不可变（冻结 dataclass）。空批（`leaf_count < 1` 或 `entries` 为空）、缺项（数量不符）、`leaf_count` 与任一方不一致、索引乱序/重复/有缺口均返回 `False`。

每个条目的 Merkle 叶字节由既有 Fiat-Shamir 转录的七个四字节无符号大端长度前缀项目构成——域 `b"zkregion/schnorr-fs/v1"`、`prime`、`generator`、`public_key`、`t`（commitment）、`context`、`message`，整数取最短无符号大端编码——末尾再以同样成帧方式追加 response 的最短无符号大端编码（共八个成帧项目；字段顺序沿用 Fiat-Shamir 转录）。叶摘要仍按 Merkle 树构造一节的 `SHA-256(b"\x00" + len4 + leaf)` 计算。

`verify_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` 的验证分两步、次序固定：

1. 先以全部 `(index, leaf)`（`index` 即 0 起的条目位置）调用 `verify_multi_inclusion` 校验 Merkle 根；任一叶字节、proof 或根不符即返回 `False`，且在根校验通过前不消费任何随机数；
2. 根通过后，以**同一个 `randbelow`** 调用 `verify_schnorr_batch(entries, randbelow=randbelow)` 验签，随机源契约（每结构合法条目恰调用一次 `randbelow(prime - 1)`、非整数返回 `TypeError`、越界返回 `ValueError`）与输入完全沿用后者，不做包装或改动。

类型错误——`batch` 不是 `BoundSchnorrBatch`、`entries` 不是元组或含非 `MultiSchnorrEntry`、条目嵌套字段类型错误（含 `bool` 整数、非 `bytes` 的 `message`/`context`、非 `SchnorrProof`）、`leaf_count` 不是非 `bool` 整数、`proof`/`root` 类型错误、`randbelow` 不可调用——抛 `TypeError`；其余一切无效情形（空批、缺项、数量不符、索引缺口/重复/乱序、错误根、叶字节篡改、签名或转录不符、非随机随机源导致的 `False` 等）均返回 `False`。入口不改写任何输入。与其它批量验证一样，这里的随机线性组合只供演示。

### Merkle 承诺的区域证明完整批验

`BoundRegionBatch(entries, leaf_count, proof)` 把一批**完整**的区域证明条目与一棵 Merkle 树的多包含证明冻结在一起，三个字段依次为：

1. `entries: tuple[RegionBatchEntry, ...]` —— 必须是元组（不是列表），每项是 `RegionBatchEntry`；
2. `leaf_count: int` —— 正的非 `bool` 整数，且必须同时等于 `len(entries)` 与 `proof.leaf_count`；
3. `proof: MerkleMultiProof` —— 其 `indices` 必须无缺口、无重复、无乱序地恰好覆盖 `0 .. leaf_count - 1`（即等于 `tuple(range(leaf_count))`）。

三字段均可位置构造，对象按值相等且不可变（冻结 dataclass）。空批（`leaf_count < 1` 或 `entries` 为空）、缺项（数量不符）、`leaf_count` 与任一方不一致、索引乱序/重复/有缺口均返回 `False`。

每个条目的 Merkle 叶字节以域 `b"zkregion/region-bound/v1"` 开始，依次拼接：x 承诺六字段、y 承诺六字段（均按数据类字段顺序）、Region 四边界（`min_x`、`max_x`、`min_y`、`max_y`）与 `context`，再依次写入 x、y 各自子证明的 `t`、`e`、`s` 序列——每个序列先写十进制元素数再逐项写值。每个原子项前置四字节无符号大端长度，整数编码为十进制 ASCII（负号保留）。叶摘要仍按 Merkle 树构造一节的 `SHA-256(b"\x00" + len4 + leaf)` 计算。

`verify_region_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` 的验证分两步、次序固定：

1. 先以全部 `(index, leaf)`（`index` 即 0 起的条目位置）调用 `verify_multi_inclusion` 校验 Merkle 根；任一叶字节、proof 或根不符即返回 `False`，且在根校验通过前不消费任何随机数；
2. 根通过后，以**同一个 `randbelow`** 调用 `verify_region_batch(entries, randbelow=randbelow)` 验子证明，随机源契约（每结构合法分支恰调用一次 `randbelow(prime - 1)`、非整数返回 `TypeError`、越界返回 `ValueError`）与输入完全沿用后者，不做包装或改动。

类型错误——`batch` 不是 `BoundRegionBatch`、`entries` 不是元组或含非 `RegionBatchEntry`、条目嵌套字段类型错误（含 `bool` 整数、非 `bytes` 的 `context`、非 `RegionProof`/`RangeProof`、非元组 `t`/`e`/`s`）、`leaf_count` 不是非 `bool` 整数、`proof`/`root` 类型错误、`randbelow` 不可调用——抛 `TypeError`；其余一切无效情形（空批、缺项、数量不符、索引缺口/重复/乱序、错误根、叶字节篡改、子证明或转录不符、非随机随机源导致的 `False` 等）均返回 `False`。入口不改写任何输入。与其它批量验证一样，这里的随机线性组合只供演示。

### 实例内防重放

`ReplayGuard` 在单个实例内为 :class:`MultiSchnorrEntry` 提供一次性的会话绑定。`ReplayBinding(session_id, digest, expires_at=None)` 是冻结的数据类：`session_id` 为非空 `bytes`，`digest` 为 `bytes` 摘要（不再限定长度；守卫登记的始终是 32 字节 SHA-256 摘要），`expires_at` 为 `None` 或非 `bool` 的 uint64 Unix 秒；三字段均可位置构造、按值相等、不可变。绑定摘要按

```
digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
```

计算，其中 `D = b"zr/r/v1"`，`F(x)` 是四字节无符号大端长度前缀加 `x`，`L(entry)` 是"Merkle 承诺的 Schnorr 完整批验"一节定义的 BoundSchnorr 叶原字节（**不**再套 `F`）；无期绑定 `E = b"\x00"`，有期绑定 `E = b"\x01" + uint64be(expires_at)`。

`bind_once(entry, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它：`session_id` 为空抛 `ValueError`，`expires_at` 越界（非 uint64）抛 `ValueError`，类型错误（含 `bool`、非 `bytes` 的 `session_id`、非 `MultiSchnorrEntry` 条目或其嵌套字段类型错误）抛 `TypeError`；`session_id` 已处于待用或已消费状态时重绑抛 `ValueError`。

`check(entry, binding, *, now=None) -> bool` 只接受本实例内仍待用且与登记值相等的绑定。校验次序为：在登记册中查到 `binding.session_id` 的待用绑定且与 `binding` 按值相等；重算摘要确认提交的 `entry` 就是绑定时的条目；有期绑定要求 `now < expires_at`（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`）；随后以条目的公钥与群参数构造 `SchnorrVerifier(public_key, prime=entry.prime, generator=entry.generator)`，再以 `entry.message`、`entry.proof`、`entry.context`（keyword `context=`）调用 `verify_proof`，旧接口的入参与行为完全不变——非法群参数或验签失败均返回 `False`。只有全部成功才把 `session_id` 从待用移入已消费；未登记（含已消费）的 id、不等值绑定、摘要不符、过期或验签失败一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。绑定状态不跨实例共享；`check` 的参数类型错误抛 `TypeError`。入口不改写任何输入。

### 区间证明的实例内一次性绑定

`RangeReplayGuard` 在单个实例内为 :class:`RangeBatchEntry` 提供与 `ReplayGuard` 同构的一次性会话绑定，复用同一个 `ReplayBinding` 类型。绑定摘要按同一公式

```
digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
```

计算，但域为 `D = b"zr/rr/v1"`，`L(entry)` 是"Merkle 承诺的区间证明完整批验"一节定义的 BoundRange 叶原字节（**不**再套 `F`），`E` 的过期编码与 `ReplayGuard` 逐字节相同。

`bind_once(entry, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它，参数边界与 `ReplayGuard` 一致：`entry` 须为 `RangeBatchEntry`（承诺、证明、`t`/`e`/`s` 元组与 `context` 的嵌套类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64 或 id 已待用/已消费均抛 `ValueError`。区间叶编码以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有额外的可编码性拒绝。

`check(entry, binding, *, now=None) -> bool` 的校验次序与 `ReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认条目一致，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），最后按字段顺序以 `entry.commitment`、`entry.proof`、`entry.context` 调用 `verify_range` 验区间证明。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、不等值绑定、摘要不符、过期或验证失败一律返回 `False` 且**不消费**。绑定状态不跨实例共享；类型错误抛 `TypeError`。入口不改写任何输入。

### 二维区域证明的实例内一次性绑定

`RegionReplayGuard` 在单个实例内为 :class:`RegionBatchEntry` 提供与 `RangeReplayGuard` 同构的一次性会话绑定，复用同一个 `ReplayBinding` 类型。绑定摘要按同一公式

```
digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
```

计算，但域为 `D = b"zr/rg/v1"`，`L(entry)` 是"Merkle 承诺的区域证明完整批验"一节定义的 BoundRegion 叶原字节（**不**再套 `F`），`E` 的过期编码与 `ReplayGuard` 逐字节相同。

`bind_once(entry, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它，参数边界与 `RangeReplayGuard` 一致：`entry` 须为 `RegionBatchEntry`（两个承诺、区域、`x_proof`/`y_proof` 及各自 `t`/`e`/`s` 元组与 `context` 的嵌套类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64 或 id 已待用/已消费均抛 `ValueError`。区域叶编码以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有额外的可编码性拒绝。

`check(entry, binding, *, now=None) -> bool` 的校验次序与 `RangeReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认条目一致，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），最后按字段顺序以 `entry.x_commitment`、`entry.y_commitment`、`entry.region`、`entry.proof`、`entry.context` 调用 `verify_region` 验二维区域证明（先 x 后 y 的字段顺序沿用旧接口，不被改写）。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、不等值绑定、摘要不符、条目任一字段被替换、过期或 `verify_region` 失败一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。绑定状态不跨实例共享；类型错误抛 `TypeError`。入口不改写任何输入。

### Merkle 承诺区域批的实例内一次性绑定

`BoundRegionReplayGuard` 在单个实例内为整批 :class:`BoundRegionBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型；`bind_once` 的入参为 `(batch, root, session_id, *, expires_at=None)`，旧接口（单条目的三个守卫）的入参与行为完全不变。绑定摘要为

```
digest = SHA-256(
    F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
    || Σ_i F(L(entry_i))
    || F(U(proof.leaf_count)) || S(proof.indices, U)
    || S(proof.siblings, λx.x) || F(E)
)
```

其中：

- 域 `D = b"zr/brg/v1"`；
- `F(x)` 是四字节无符号大端长度前缀加 `x`，`U(n)` 是八字节无符号大端整数编码；
- `L(entry_i)` 沿用"Merkle 承诺的区域证明完整批验"一节定义的 BoundRegion 叶原字节，按 `batch.entries` 的顺序逐个以 `F` 成帧；
- `S(a, f) = F(U(|a|)) || Σ F(f(a_i))`，即 `proof.indices` 逐项以 `U` 成帧、`proof.siblings` 逐项以恒等映射（原字节）成帧，两段都先写以 `U` 编码的元素数；
- `E` 的过期编码与 `ReplayGuard` 逐字节相同：无期 `E = b"\x00"`，有期 `E = b"\x01" + uint64be(expires_at)`。

`bind_once(batch, root, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它。类型边界与 `verify_region_bound` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、或 id 已待用/已消费均抛 `ValueError`。

`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序为：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后以**同一个 `randbelow`** 调用 `verify_region_bound(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与区域批验证明全部通过其随机源契约（每结构合法分支 `randbelow(prime - 1)` 一次，非整数返回 `TypeError`、越界返回 `ValueError`），不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、不等值绑定、摘要不符、过期、根或兄弟长度错误、错误根、任何结构/证明无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`。入口不改写任何输入。

### Merkle 承诺区间批的实例内一次性绑定

`BoundRangeReplayGuard` 在单个实例内为整批 :class:`BoundRangeBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型，入参与 `BoundRegionReplayGuard` 同形：`bind_once(batch, root, session_id, *, expires_at=None)`、`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow)`，状态同样不跨实例。绑定摘要逐项复用 `BoundRegionReplayGuard` 的公开公式与 `F`、`U`、`S`、`E` 编码、条目顺序不变，仅做两处替换：

- 域改为 `D = b"zr/brr/v1"`；
- 每个 `L(entry_i)` 改用"Merkle 承诺的区间证明完整批验"一节定义的 BoundRange 叶原字节（`_bound_range_leaf`），按 `batch.entries` 的顺序逐个以 `F` 成帧。

即

```
digest = SHA-256(
    F(D) || F(session_id) || F(root) || F(U(batch.leaf_count))
    || Σ_i F(L(entry_i))
    || F(U(proof.leaf_count)) || S(proof.indices, U)
    || S(proof.siblings, λx.x) || F(E)
)
```

`bind_once` 的类型边界与 `verify_range_bound` 一致（`batch` 及其嵌套 `RangeBatchEntry`、承诺、`RangeProof` 的 `t`/`e`/`s` 元组、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 须为非空 `bytes`，`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、或 id 已待用/已消费均抛 `ValueError`。

`check` 先核对本实例待用等值绑定、再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象、再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后把**同一个 `randbelow` 原样**传给 `verify_range_bound(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与区间批验证明全部通过其随机源契约，不做包装或改写。仅验证成功才消费 `session_id`；未登记（含已消费）的 id、替换对象（不等值绑定或摘要不符）、过期、`root` 或任一兄弟摘要非 32 字节、错误根、其他摘要/结构/证明无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，委托验证抛出的随机源异常（非整数 `TypeError`、越界 `ValueError`）原样传播。入口不改写任何输入。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。区域判定只是朴素的坐标比较，不检查坐标是否经过承诺绑定；批量验证所用的随机线性组合与默认群一样仅供演示。Pedersen 承诺默认的 `h = g**2 mod prime` 带有公开陷门、破坏绑定性；其上的 Schnorr OR 区间证明与二维区域成员证明同样是演示级构造——区间上限 256 个整数、挑战来自 SHA-256 Fiat-Shamir 转录、群参数与默认 `h` 均未做生产级安全分析，不能用于真实部署。

## 测试

```bash
python3 -m unittest discover -s tests
```
