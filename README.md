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

# 同一公钥 Schnorr 完整批验：整批 SchnorrBatchEntry 先提交到一棵 Merkle 树
from zkregion import SingleKeyBoundBatch

single = [
    SchnorrBatchEntry(b"alpha", prover.prove(b"alpha", context=b"s1"), context=b"s1"),
    SchnorrBatchEntry(b"beta", prover.prove(b"beta", context=b"s1"), context=b"s1"),
]

def single_leaf(entry):
    multi_entry = MultiSchnorrEntry(
        verifier.public_key, entry.message, entry.proof, entry.context
    )
    return bound_leaf(multi_entry)

single_leaves = [single_leaf(entry) for entry in single]
single_root = merkle_root(single_leaves)
single_proof = prove_multi_inclusion(single_leaves, tuple(range(len(single))))
single_bound = SingleKeyBoundBatch(tuple(single), len(single), single_proof)
assert verifier.verify_bound_batch(single_bound, single_root)

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

# Merkle 追加一致性证明（仅凭旧根、新根确认新树由旧叶序列追加所得）
from zkregion import prove_consistency, verify_consistency

old_root = merkle_root(leaves)
leaves = leaves + [b"delta", b"epsilon"]
consistency = prove_consistency(leaves, 3)
assert verify_consistency(old_root, merkle_root(leaves), consistency)

# 多检查点 Merkle 一致性链：一次确认递增检查点均由前树连续追加
from zkregion import prove_consistency_chain, verify_consistency_chain

chain = prove_consistency_chain(leaves, (1, 3, 5))
assert chain.roots == tuple(merkle_root(leaves[:n]) for n in (1, 3, 5))
assert verify_consistency_chain(chain)

# 独立 Merkle 一致性证明批验：一次检查多组互不相关的旧根、新根与证明
from zkregion import MerkleConsistencyBatchEntry, verify_consistency_batch

more_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta"]
batch = [
    MerkleConsistencyBatchEntry(
        merkle_root(more_leaves[:old_count]),
        merkle_root(more_leaves),
        prove_consistency(more_leaves, old_count),
    )
    for old_count in (1, 3, 5)
]
assert verify_consistency_batch(batch)
assert not verify_consistency_batch(())

# Merkle 承诺的一致性证明完整批验：整批一致性条目先提交到一棵 Merkle 树
from zkregion import BoundConsistencyBatch, verify_consistency_batch_bound

def bound_consistency_leaf(entry):
    proof = entry.proof
    items = [
        b"zkregion/consistency-bound/v1",
        entry.old_root,
        entry.new_root,
        str(proof.old_count).encode("ascii"),
        str(proof.new_count).encode("ascii"),
    ]
    items += list(proof.nodes)
    return b"".join(len(item).to_bytes(4, "big") + item for item in items)

bound_cb_leaves = [bound_consistency_leaf(entry) for entry in batch]
bound_cb_root = merkle_root(bound_cb_leaves)
bound_cb_proof = prove_multi_inclusion(
    bound_cb_leaves, tuple(range(len(bound_cb_leaves)))
)
bound_cb = BoundConsistencyBatch(
    tuple(batch), len(batch), bound_cb_proof
)
assert verify_consistency_batch_bound(bound_cb, bound_cb_root)

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
region_multi_proof = prove_multi_inclusion(region_leaves, tuple(range(len(region_leaves))))
bound_region = BoundRegionBatch(tuple(batch), len(batch), region_multi_proof)
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

# 可选 SQLite 后端：同文件同命名空间的独立实例（含重启后）共享状态
import tempfile
from zkregion import SQLiteReplayStore

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
shared_a = ReplayGuard(store=store)
binding = shared_a.bind_once(entry, b"session-2")         # 短事务写入待用
shared_b = ReplayGuard(store=store)                       # 另一个独立实例
assert shared_b.check(entry, binding)                     # 认领、验签并消费
assert not shared_a.check(entry, binding)                 # 已消费，二次提交被拒
try:
    shared_b.bind_once(entry, b"session-2")
except ValueError:
    pass
store.close()

# 多公钥 Schnorr 批次的一次性绑定：整批 MultiSchnorrEntry 绑定到一个 session id
from zkregion import SchnorrBatchReplayGuard

sbr_entries = [
    MultiSchnorrEntry(
        prover.public_key, b"alpha", prover.prove(b"alpha", context=b"s1"), context=b"s1"
    ),
    MultiSchnorrEntry(
        prover.public_key, b"beta", prover.prove(b"beta", context=b"s1"), context=b"s1"
    ),
]
sbr = SchnorrBatchReplayGuard()
sbr_binding = sbr.bind_once(sbr_entries, b"session-1")  # 非空批次，保序留重
assert sbr.check(sbr_entries, sbr_binding)               # 核摘要、期限并批验后消费
assert not sbr.check(sbr_entries, sbr_binding)           # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
sbr_a = SchnorrBatchReplayGuard(store=store)
sbr_binding = sbr_a.bind_once(sbr_entries, b"session-3")
sbr_b = SchnorrBatchReplayGuard(store=store)             # 另一个独立实例
assert sbr_b.check(sbr_entries, sbr_binding)             # 认领、批验并消费（行键域 b"zr/sbr/v1"）
assert not sbr_a.check(sbr_entries, sbr_binding)         # 已消费，二次提交被拒
store.close()

# 同一公钥 Schnorr 批次的一次性绑定：整批 SchnorrBatchEntry 绑定到一个 session id
from zkregion import SingleKeyBatchGuard

skbr_entries = [
    SchnorrBatchEntry(b"alpha", prover.prove(b"alpha", context=b"s1"), context=b"s1"),
    SchnorrBatchEntry(b"beta", prover.prove(b"beta", context=b"s1"), context=b"s1"),
]
skbr = SingleKeyBatchGuard(prover.public_key)            # 固定公钥与群参数
skbr_binding = skbr.bind_once(skbr_entries, b"session-1")  # 非空批次，保序留重
assert skbr.check(skbr_entries, skbr_binding)              # 核摘要、期限并批验后消费
assert not skbr.check(skbr_entries, skbr_binding)          # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
skbr_a = SingleKeyBatchGuard(prover.public_key, store=store)
skbr_binding = skbr_a.bind_once(skbr_entries, b"session-3")
skbr_b = SingleKeyBatchGuard(prover.public_key, store=store)  # 另一个独立实例
assert skbr_b.check(skbr_entries, skbr_binding)            # 认领、批验并消费（行键域 b"zr/skbr/v1"）
assert not skbr_a.check(skbr_entries, skbr_binding)        # 已消费，二次提交被拒
store.close()

# 区间证明批次的一次性绑定：整批 RangeBatchEntry 绑定到一个 session id
from zkregion import RangeBatchReplayGuard

rbr_entries = [
    RangeBatchEntry(commitment, proof, b"session-1"),
    RangeBatchEntry(commitment, proof, b"session-1"),
]
rbr = RangeBatchReplayGuard()
rbr_binding = rbr.bind_once(rbr_entries, b"session-1")  # 非空批次，保序留重
assert rbr.check(rbr_entries, rbr_binding)               # 核摘要、期限并批验后消费
assert not rbr.check(rbr_entries, rbr_binding)           # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
rbr_a = RangeBatchReplayGuard(store=store)
rbr_binding = rbr_a.bind_once(rbr_entries, b"session-3")
rbr_b = RangeBatchReplayGuard(store=store)              # 另一个独立实例
assert rbr_b.check(rbr_entries, rbr_binding)            # 认领、批验并消费（行键域 b"zr/rbr/v1"）
assert not rbr_a.check(rbr_entries, rbr_binding)        # 已消费，二次提交被拒
store.close()

# 区域证明批次的一次性绑定：整批 RegionBatchEntry 绑定到一个 session id
from zkregion import RegionBatchReplayGuard

rgbr_entries = [
    RegionBatchEntry(x_commitment, y_commitment, region, region_proof, b"session-1"),
    RegionBatchEntry(x_commitment, y_commitment, region, region_proof, b"session-1"),
]
rgbr = RegionBatchReplayGuard()
rgbr_binding = rgbr.bind_once(rgbr_entries, b"session-1")  # 非空批次，保序留重
assert rgbr.check(rgbr_entries, rgbr_binding)              # 核摘要、期限并批验后消费
assert not rgbr.check(rgbr_entries, rgbr_binding)          # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
rgbr_a = RegionBatchReplayGuard(store=store)
rgbr_binding = rgbr_a.bind_once(rgbr_entries, b"session-3")
rgbr_b = RegionBatchReplayGuard(store=store)             # 另一个独立实例
assert rgbr_b.check(rgbr_entries, rgbr_binding)          # 认领、批验并消费（行键域 b"zr/rgbr/v1"）
assert not rgbr_a.check(rgbr_entries, rgbr_binding)      # 已消费，二次提交被拒
store.close()

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

# 可选 SQLite 后端：整批区域绑定的待用/认领/已消费状态跨实例、进程及重启共享
store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
brg_a = BoundRegionReplayGuard(store=store)
brg_binding = brg_a.bind_once(bound_region, region_root, b"session-3")
brg_b = BoundRegionReplayGuard(store=store)                   # 另一个独立实例
assert brg_b.check(bound_region, region_root, brg_binding)    # 认领、验根与整批证明并消费
assert not brg_a.check(bound_region, region_root, brg_binding)  # 已消费，二次提交被拒
store.close()

# 整批 BoundRangeBatch 与 bytes 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import BoundRangeReplayGuard

brr = BoundRangeReplayGuard()
brr_binding = brr.bind_once(bound_range, range_root, b"session-1")
assert brr.check(bound_range, range_root, brr_binding)       # 先验根与整批证明再消费
assert not brr.check(bound_range, range_root, brr_binding)   # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
brr_a = BoundRangeReplayGuard(store=store)
brr_binding = brr_a.bind_once(bound_range, range_root, b"session-3")
brr_b = BoundRangeReplayGuard(store=store)                   # 另一个独立实例
assert brr_b.check(bound_range, range_root, brr_binding)     # 认领、验根与整批证明并消费
assert not brr_a.check(bound_range, range_root, brr_binding) # 已消费，二次提交被拒
store.close()

# 整批 BoundSchnorrBatch 与 bytes 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import BoundSchnorrReplayGuard

schnorr_entries = [
    MultiSchnorrEntry(prover.public_key, b"pay", prover.prove(b"pay"), b""),
]
schnorr_leaves = [bound_leaf(entry) for entry in schnorr_entries]
schnorr_root = merkle_root(schnorr_leaves)
schnorr_bound = BoundSchnorrBatch(
    tuple(schnorr_entries),
    len(schnorr_entries),
    prove_multi_inclusion(schnorr_leaves, tuple(range(len(schnorr_entries)))),
)
bsr = BoundSchnorrReplayGuard()
bsr_binding = bsr.bind_once(schnorr_bound, schnorr_root, b"session-1")
assert bsr.check(schnorr_bound, schnorr_root, bsr_binding)       # 先验根与整批验签再消费
assert not bsr.check(schnorr_bound, schnorr_root, bsr_binding)   # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
bsr_a = BoundSchnorrReplayGuard(store=store)
bsr_binding = bsr_a.bind_once(schnorr_bound, schnorr_root, b"session-3")
bsr_b = BoundSchnorrReplayGuard(store=store)                     # 另一个独立实例
assert bsr_b.check(schnorr_bound, schnorr_root, bsr_binding)     # 认领、验根与整批验签并消费
assert not bsr_a.check(schnorr_bound, schnorr_root, bsr_binding) # 已消费，二次提交被拒
store.close()

# 整批 BoundConsistencyBatch 与 bytes 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import BoundConsistencyReplayGuard

bcbr = BoundConsistencyReplayGuard()
bcbr_binding = bcbr.bind_once(bound_cb, bound_cb_root, b"session-1")
assert bcbr.check(bound_cb, bound_cb_root, bcbr_binding)       # 先验根与一致性批验再消费
assert not bcbr.check(bound_cb, bound_cb_root, bcbr_binding)   # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
bcbr_a = BoundConsistencyReplayGuard(store=store)
bcbr_binding = bcbr_a.bind_once(bound_cb, bound_cb_root, b"session-3")
bcbr_b = BoundConsistencyReplayGuard(store=store)                  # 另一个独立实例
assert bcbr_b.check(bound_cb, bound_cb_root, bcbr_binding)     # 认领、验根与一致性批验并消费
assert not bcbr_a.check(bound_cb, bound_cb_root, bcbr_binding) # 已消费，二次提交被拒
store.close()

# 同一公钥 SingleKeyBoundBatch 与 bytes 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import SingleKeyBoundReplayGuard

skbb_leaves = [single_leaf(entry) for entry in single]
skbb_root = merkle_root(skbb_leaves)
skbb_bound = SingleKeyBoundBatch(
    tuple(single),
    len(single),
    prove_multi_inclusion(skbb_leaves, tuple(range(len(single)))),
)
skbb = SingleKeyBoundReplayGuard(verifier.public_key)  # 固定公钥与群参数
skbb_binding = skbb.bind_once(skbb_bound, skbb_root, b"session-1")
assert skbb.check(skbb_bound, skbb_root, skbb_binding)       # 先验根与整批验签再消费
assert not skbb.check(skbb_bound, skbb_root, skbb_binding)   # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
skbb_a = SingleKeyBoundReplayGuard(verifier.public_key, store=store)
skbb_binding = skbb_a.bind_once(skbb_bound, skbb_root, b"session-3")
skbb_b = SingleKeyBoundReplayGuard(verifier.public_key, store=store)  # 另一个独立实例
assert skbb_b.check(skbb_bound, skbb_root, skbb_binding)     # 认领、验根与整批验签并消费
assert not skbb_a.check(skbb_bound, skbb_root, skbb_binding) # 已消费，二次提交被拒
store.close()

# 多检查点一致性链与 session id 的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import MerkleConsistencyChainReplayGuard

chain = prove_consistency_chain(leaves, (1, 3, 5))
mccr = MerkleConsistencyChainReplayGuard()
mccr_binding = mccr.bind_once(chain, b"session-1")
assert mccr.check(chain, mccr_binding)                          # 重算摘要、查期限并核链后消费
assert not mccr.check(chain, mccr_binding)                      # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
mccr_a = MerkleConsistencyChainReplayGuard(store=store)
mccr_binding = mccr_a.bind_once(chain, b"session-3")
mccr_b = MerkleConsistencyChainReplayGuard(store=store)         # 另一个独立实例
assert mccr_b.check(chain, mccr_binding)                        # 认领、核链并消费
assert not mccr_a.check(chain, mccr_binding)                    # 已消费，二次提交被拒
store.close()

# 单段一致性证明与两根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import MerkleConsistencyReplayGuard

old_root = merkle_root(leaves[:3])
new_root = merkle_root(leaves)
consistency = prove_consistency(leaves, 3)
mcr = MerkleConsistencyReplayGuard()
mcr_binding = mcr.bind_once(old_root, new_root, consistency, b"session-1")
assert mcr.check(old_root, new_root, consistency, mcr_binding)      # 核摘要、期限并验一致性后消费
assert not mcr.check(old_root, new_root, consistency, mcr_binding)  # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
mcr_a = MerkleConsistencyReplayGuard(store=store)
mcr_binding = mcr_a.bind_once(old_root, new_root, consistency, b"session-3")
mcr_b = MerkleConsistencyReplayGuard(store=store)                   # 另一个独立实例
assert mcr_b.check(old_root, new_root, consistency, mcr_binding)    # 认领、验一致性并消费
assert not mcr_a.check(old_root, new_root, consistency, mcr_binding)  # 已消费，二次提交被拒
store.close()

# 单叶包含证明与 Merkle 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import MerkleInclusionReplayGuard

mir_leaves = [b"alpha", b"beta", b"gamma"]
mir_root = merkle_root(mir_leaves)
inclusion = prove_inclusion(mir_leaves, 1)
mir = MerkleInclusionReplayGuard()
mir_binding = mir.bind_once(b"beta", mir_root, inclusion, b"session-1")
assert mir.check(b"beta", mir_root, inclusion, mir_binding)         # 核摘要、期限并验包含后消费
assert not mir.check(b"beta", mir_root, inclusion, mir_binding)     # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
mir_a = MerkleInclusionReplayGuard(store=store)
mir_binding = mir_a.bind_once(b"beta", mir_root, inclusion, b"session-3")
mir_b = MerkleInclusionReplayGuard(store=store)                     # 另一个独立实例
assert mir_b.check(b"beta", mir_root, inclusion, mir_binding)       # 认领、验包含并消费
assert not mir_a.check(b"beta", mir_root, inclusion, mir_binding)   # 已消费，二次提交被拒
store.close()

# 多叶紧凑包含证明（MerkleMultiProof）与 Merkle 根的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import MerkleMultiReplayGuard

mmr_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon"]
mmr_root = merkle_root(mmr_leaves)
mmr_indices = (0, 2, 4)
multi = prove_multi_inclusion(mmr_leaves, mmr_indices)
mmr_entries = [(i, mmr_leaves[i]) for i in mmr_indices]  # 与 proof.indices 同序的 (index, leaf)
mmr = MerkleMultiReplayGuard()
mmr_binding = mmr.bind_once(mmr_entries, mmr_root, multi, b"session-1")
assert mmr.check(mmr_entries, mmr_root, multi, mmr_binding)         # 核摘要、期限并验多包含后消费
assert not mmr.check(mmr_entries, mmr_root, multi, mmr_binding)     # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
mmr_a = MerkleMultiReplayGuard(store=store)
mmr_binding = mmr_a.bind_once(mmr_entries, mmr_root, multi, b"session-3")
mmr_b = MerkleMultiReplayGuard(store=store)                         # 另一个独立实例
assert mmr_b.check(mmr_entries, mmr_root, multi, mmr_binding)       # 认领、验多包含并消费
assert not mmr_a.check(mmr_entries, mmr_root, multi, mmr_binding)   # 已消费，二次提交被拒
store.close()

# 独立一致性证明批次与 session id 的一次性绑定（可选 SQLite 后端跨实例共享）
from zkregion import MerkleConsistencyBatchReplayGuard

mcbr_leaves = [b"alpha", b"beta", b"gamma", b"delta", b"epsilon", b"zeta"]
mcbr_entries = [
    MerkleConsistencyBatchEntry(
        merkle_root(mcbr_leaves[:old_count]),
        merkle_root(mcbr_leaves),
        prove_consistency(mcbr_leaves, old_count),
    )
    for old_count in (1, 3, 5)
]
mcbr = MerkleConsistencyBatchReplayGuard()
mcbr_binding = mcbr.bind_once(mcbr_entries, b"session-1")
assert mcbr.check(mcbr_entries, mcbr_binding)                       # 核摘要、期限并批验后消费
assert not mcbr.check(mcbr_entries, mcbr_binding)                   # 二次提交被拒

store = SQLiteReplayStore(tempfile.mktemp(suffix=".db"))
mcbr_a = MerkleConsistencyBatchReplayGuard(store=store)
mcbr_binding = mcbr_a.bind_once(mcbr_entries, b"session-3")
mcbr_b = MerkleConsistencyBatchReplayGuard(store=store)             # 另一个独立实例
assert mcbr_b.check(mcbr_entries, mcbr_binding)                     # 认领、批验并消费
assert not mcbr_a.check(mcbr_entries, mcbr_binding)                 # 已消费，二次提交被拒
store.close()
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
  - `verify_bound_batch(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的同一公钥 Schnorr 完整批验：每项以本验证器固定公钥与群参数及条目的 `message`、`proof`、`context` 构造 `MultiSchnorrEntry`，叶字节逐字节复用既有 BoundSchnorr 编码；先 `verify_multi_inclusion` 验根（失败不取随机），根通过后才把 `randbelow` 透传给 `verify_batch`
- `SchnorrProof(commitment, response)` — 不可变证明对象（`t = g**k mod prime`，`s = k + c * secret`）
- `SchnorrBatchEntry(message, proof, context=b"")` — 不可变批量验证条目，字段类型依次为 `bytes`、`SchnorrProof`、`bytes`
- `verify_schnorr_batch(entries, *, randbelow=secrets.randbelow) -> bool` — 多公钥批量验证，按 `(prime, generator)` 分组做一次随机线性组合
- `MultiSchnorrEntry(public_key, message, proof, context=b"", prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR)` — 不可变多公钥批量验证条目；前三字段依次为 `int`、`bytes`、`SchnorrProof`，均为必填且可位置构造，值相等即相等
- `verify_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的 Schnorr 完整批验：先 `verify_multi_inclusion` 验根，再以同一 `randbelow` 调 `verify_schnorr_batch` 验签
- `BoundSchnorrBatch(entries, leaf_count, proof)` — 冻结的完整批对象；字段依次为 `tuple[MultiSchnorrEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变
- `SingleKeyBoundBatch(entries, leaf_count, proof)` — 冻结的同一公钥完整批对象；字段依次为 `tuple[SchnorrBatchEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变；公钥与群参数由验证它的 `SchnorrVerifier` 固定，`leaf_count` 须等于条目数及 `proof.leaf_count`，`proof.indices` 须为 `tuple(range(leaf_count))`，空批、缺项、乱序或索引缺口均返回 `False`
- `verify_region_bound(batch, root, *, randbelow=secrets.randbelow) -> bool` — Merkle 承诺的区域证明完整批验：先 `verify_multi_inclusion` 验根，再以同一 `randbelow` 调 `verify_region_batch` 验子证明
- `BoundRegionBatch(entries, leaf_count, proof)` — 冻结的完整批对象；字段依次为 `tuple[RegionBatchEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变
- `ReplayBinding(session_id, digest, expires_at=None)` — 冻结的一次性防重放绑定；字段依次为非空 `bytes`、`bytes` 摘要（不限定长度；各守卫登记的均为 32 字节 SHA-256 摘要）、`None` 或非 `bool` 的 uint64 Unix 秒过期时间；可位置构造、按值相等且不可变
- `ReplayGuard(*, store=None)` — 防重放登记册（线程安全）；无参时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中
  - `bind_once(entry: MultiSchnorrEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记待用绑定；待用、正在校验（认领未过期）或已消费的 `session_id` 重绑抛 `ValueError`；存储后端下连过期认领的 id 也不能重绑（只有 `check` 能接管过期认领）
  - `check(entry, binding, *, now=None) -> bool` — 原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再以条目的公钥与群参数构造 `SchnorrVerifier` 并以 `message`、`proof`、`context` 调 `verify_proof`；成功才消费 `session_id`，任何拒绝（含竞争失败）都返回 `False` 且不消费；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用
- `SchnorrBatchReplayGuard(*, store=None)` — 多公钥 `MultiSchnorrEntry` 批次的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/sbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(entries: Sequence[MultiSchnorrEntry], session_id, *, expires_at=None) -> ReplayBinding` — 把非空批次（沿用 `verify_schnorr_batch` 的序列与嵌套类型规则，保序、留重）一次性绑定到 `session_id`；空批、空 id、uint64 越界（期限或批次长度）、叶内负整数或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，错型（含 `bool` 整数）抛 `TypeError`
  - `check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 先原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再重算摘要、检查期限，随后把 `randbelow` 原样透传给 `verify_schnorr_batch`；成功才消费 `session_id`，任何拒绝（含竞争失败、空批、叶内负整数、批验返回 `False`）都返回 `False` 且复原待用；委托验证抛出的异常（含随机源错型 `TypeError`、越界 `ValueError`）先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费
- `SingleKeyBatchGuard(public_key, *, prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR, store=None)` — 同一公钥 `SchnorrBatchEntry` 批次的防重放登记册（线程安全）；公钥与群参数在构造时固定并据以构造一个固定的 `SchnorrVerifier`，错型（含 `bool` 整数）抛 `TypeError`，非法群值（`0 < public_key < prime`、`1 < generator < prime` 之外）抛 `ValueError`；无 `store` 时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/skbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态；摘要为 `SHA-256(F(D) || F(session_id) || S(entries,L) || F(E))`，其中 `D = b"zr/skbr/v1"`、`L(entry)` 逐字节复用以本守卫公钥和群参数构造的 BoundSchnorr 叶原字节（`_bound_schnorr_leaf`），F/U/S/E 逐字节沿用各批守卫
  - `bind_once(entries: Sequence[SchnorrBatchEntry], session_id, *, expires_at=None) -> ReplayBinding` — 把非空批次（沿用 `SchnorrVerifier.verify_batch` 的序列与嵌套类型规则，保序、留重）一次性绑定到 `session_id`；空批、空 id、uint64 越界（期限或批次长度）、叶内负整数或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，错型（含 `bool` 整数）抛 `TypeError`
  - `check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 先原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再重算摘要、检查期限，随后把 `randbelow` 原样透传给固定验证器的 `verify_batch`；成功才消费 `session_id`，任何拒绝（含竞争失败、空批、叶内负整数、批验返回 `False`）都返回 `False` 且复原待用；委托验证抛出的异常（含随机源错型 `TypeError`、越界 `ValueError`）先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费
- `RangeBatchReplayGuard(*, store=None)` — 区间证明 `RangeBatchEntry` 批次的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态；摘要为 `SHA-256(F(D) || F(session_id) || S(entries,L) || F(E))`，其中 `D = b"zr/rbr/v1"`、`L` 复用既有 BoundRange 叶原字节（`_bound_range_leaf`），F/U/S/E 逐字节沿用各批守卫
  - `bind_once(entries: Sequence[RangeBatchEntry], session_id, *, expires_at=None) -> ReplayBinding` — 把非空批次（沿用 `verify_range_batch` 的序列与嵌套类型规则，保序、留重）一次性绑定到 `session_id`；登记空批、空 id、uint64 越界（期限或批次长度）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，错型（含 `bool` 整数）抛 `TypeError`
  - `check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 先原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再重算摘要、检查期限，随后把 `randbelow` 原样透传给 `verify_range_batch`；成功才消费 `session_id`，任何拒绝（含竞争失败、空批、批验返回 `False`）都返回 `False` 且复原待用；委托验证抛出的异常（含随机源返回非整数的 `TypeError`、越界 `ValueError`）先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费
- `RegionBatchReplayGuard(*, store=None)` — 区域证明 `RegionBatchEntry` 批次的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rgbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态；摘要为 `SHA-256(F(D) || F(session_id) || S(entries,L) || F(E))`，其中 `D = b"zr/rgbr/v1"`、`L` 复用既有 BoundRegion 叶原字节（`_bound_region_leaf`），F/U/S/E 逐字节沿用各批守卫
  - `bind_once(entries: Sequence[RegionBatchEntry], session_id, *, expires_at=None) -> ReplayBinding` — 把非空批次（沿用 `verify_region_batch` 的序列与嵌套类型规则，保序、留重）一次性绑定到 `session_id`；登记空批、空 id、uint64 越界（期限或批次长度）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，错型（含 `bool` 整数）抛 `TypeError`
  - `check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 先原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再重算摘要、检查期限，随后把 `randbelow` 原样透传给 `verify_region_batch`；成功才消费 `session_id`，任何拒绝（含竞争失败、空批、批验返回 `False`）都返回 `False` 且复原待用；委托验证抛出的异常（含随机源不可调用或返回非整数的 `TypeError`、越界 `ValueError`）先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费
- `SQLiteReplayStore(path: str, namespace: bytes = b"default", *, lease_seconds: int = 30, clock=None)` — `ReplayGuard`、`SchnorrBatchReplayGuard`、`SingleKeyBatchGuard`、`RangeBatchReplayGuard`、`RegionBatchReplayGuard`、`RangeReplayGuard`、`RegionReplayGuard`、`BoundRegionReplayGuard`、`BoundRangeReplayGuard`、`BoundSchnorrReplayGuard`、`SingleKeyBoundReplayGuard`、`MerkleConsistencyChainReplayGuard` 与 `MerkleConsistencyReplayGuard`、`MerkleInclusionReplayGuard`、`MerkleMultiReplayGuard`、`MerkleConsistencyBatchReplayGuard`、`BoundConsistencyReplayGuard` 的可选 SQLite 后端：同一文件同一命名空间的独立实例（含重启后、跨进程）共享待用、认领与已消费状态；行键为 `namespace`、守卫域（`ReplayGuard` 为 `b"zr/r/v1"`、`SchnorrBatchReplayGuard` 为 `b"zr/sbr/v1"`、`SingleKeyBatchGuard` 为 `b"zr/skbr/v1"`、`RangeBatchReplayGuard` 为 `b"zr/rbr/v1"`、`RegionBatchReplayGuard` 为 `b"zr/rgbr/v1"`、`RangeReplayGuard` 为 `b"zr/rr/v1"`、`RegionReplayGuard` 为 `b"zr/rg/v1"`、`BoundRegionReplayGuard` 为 `b"zr/brg/v1"`、`BoundRangeReplayGuard` 为 `b"zr/brr/v1"`、`BoundSchnorrReplayGuard` 为 `b"zr/bsr/v1"`、`SingleKeyBoundReplayGuard` 为 `b"zr/skbbr/v1"`、`MerkleConsistencyChainReplayGuard` 为 `b"zr/mccr/v1"`、`MerkleConsistencyReplayGuard` 为 `b"zr/mcr/v1"`、`MerkleInclusionReplayGuard` 为 `b"zr/mir/v1"`、`MerkleMultiReplayGuard` 为 `b"zr/mmr/v1"`、`MerkleConsistencyBatchReplayGuard` 为 `b"zr/mcbr/v1"`、`BoundConsistencyReplayGuard` 为 `b"zr/bcbr/v1"`）、`session_id` 三段 `bytes`，值保存等值 `ReplayBinding`（摘要与 `E` 期限编码逐字节沿用绑定摘要的编码）及状态、认领 token 与租约截止；`clock` 缺省取整数 Unix 秒，返回值须为非 `bool` uint64，否则 `ValueError`/`TypeError`；`lease_seconds` 须为正的非 `bool` 整数否则 `ValueError`；`store` 参数类型错误抛 `TypeError`；数据库错误原样透传 `sqlite3.Error`
- `RangeReplayGuard(*, store=None)` — 区间证明的防重放登记册（线程安全）；无参时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rr/v1"`）
  - `bind_once(entry: RangeBatchEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记待用绑定；待用、正在校验（认领未过期）或已消费的 `session_id` 重绑抛 `ValueError`；存储键已存在即抛 `ValueError`，存储后端下连过期认领的 id 也不能重绑（只有 `check` 能接管过期认领）
  - `check(entry, binding, *, now=None) -> bool` — 原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再按字段顺序以 `commitment`、`proof`、`context` 调 `verify_range`；成功才消费 `session_id`，任何拒绝（含竞争失败）都返回 `False` 且不消费；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用
- `RegionReplayGuard(*, store=None)` — 二维区域证明的防重放登记册（线程安全）；无参时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rg/v1"`）
  - `bind_once(entry: RegionBatchEntry, session_id, *, expires_at=None) -> ReplayBinding` — 登记待用绑定；待用、正在校验（认领未过期）或已消费的 `session_id` 重绑抛 `ValueError`；存储键已存在即抛 `ValueError`，存储后端下连过期认领的 id 也不能重绑（只有 `check` 能接管过期认领）
  - `check(entry, binding, *, now=None) -> bool` — 原子认领等值待用绑定（存储后端可在认领租约过期后接管旧认领），再按字段顺序以 `x_commitment`、`y_commitment`、`region`、`proof`、`context` 调 `verify_region`；成功才消费 `session_id`，任何拒绝（含竞争失败）都返回 `False` 且不消费；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用
- `BoundRegionReplayGuard(*, store=None)` — Merkle 承诺区域批与 Merkle 根的防重放登记册（线程安全）；无参时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/brg/v1"`）
  - `bind_once(batch: BoundRegionBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundRegionBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空值、uint64 越界或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，类型错误抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 原子认领、重算绑定摘要、检查期限后委托 `verify_region_bound` 并透传同一随机源；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，`randbelow` 抛错时同样撤销认领并原样抛出；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `BoundRangeReplayGuard(*, store=None)` — Merkle 承诺区间批与 bytes 根的防重放登记册（线程安全）；无参时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/brr/v1"`）
  - `bind_once(batch: BoundRangeBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundRangeBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空值、uint64 越界或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，类型错误抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 原子认领、重算绑定摘要、检查期限后委托 `verify_range_bound` 并透传同一随机源；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，`randbelow` 抛错时同样撤销认领并原样抛出；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `BoundSchnorrReplayGuard(*, store=None)` — Merkle 承诺 Schnorr 批与 bytes 根的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/bsr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(batch: BoundSchnorrBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundSchnorrBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空值、uint64 越界、叶内负整数或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，类型错误抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 原子认领、重算绑定摘要、检查期限后原样委托 `verify_bound` 并透传同一随机源；成功才消费 `session_id`，其余无效（含叶内负整数）一律返回 `False` 且撤销认领、保持待用，`randbelow` 抛错时同样撤销认领并原样抛出；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `BoundConsistencyReplayGuard(*, store=None)` — Merkle 承诺一致性批（`BoundConsistencyBatch`）与 bytes 根的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/bcbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态；摘要逐字节复用 `BoundRegionReplayGuard` 的公开公式与 F/U/S/E 成帧，仅域改为 `b"zr/bcbr/v1"`、逐项 `L(entry)` 改为既有一致性 Bound 叶原字节（`_bound_consistency_leaf`）
  - `bind_once(batch: BoundConsistencyBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `BoundConsistencyBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空 id、uint64 越界的期限或 U 成帧整数（`leaf_count`、`proof.leaf_count`、各索引）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，错型（含 `bool` 整数）抛 `TypeError`
  - `check(batch, root, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后原样委托 `verify_consistency_batch_bound`；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，委托验证抛出的异常先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `SingleKeyBoundReplayGuard(public_key, *, prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR, store=None)` — Merkle 承诺同一公钥 Schnorr 批（`SingleKeyBoundBatch`）与 bytes 根的防重放登记册（线程安全）；公钥与群参数在构造时固定并据以构造一个固定的 `SchnorrVerifier`，错型（含 `bool` 整数）抛 `TypeError`，非法群值（`0 < public_key < prime`、`1 < generator < prime` 之外）抛 `ValueError`；无 `store` 时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/skbbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态；摘要逐字节复用 `BoundSchnorrReplayGuard` 的公开公式与 F/U/S/E 成帧，仅域改为 `b"zr/skbbr/v1"`、逐项 `L(entry)` 改为以本守卫固定公钥与群参数构造的 BoundSchnorr 叶原字节（`_bound_schnorr_leaf`）
  - `bind_once(batch: SingleKeyBoundBatch, root: bytes, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整批 `SingleKeyBoundBatch` 连同其 Merkle `root` 一次性绑定到 `session_id`；空 id、uint64 越界的期限或 U 成帧整数（`leaf_count`、`proof.leaf_count`、各索引）、叶内负整数（证明 commitment/response）或任意状态（待用/校验中（存储后端下含过期认领）/已消费）重绑均抛 `ValueError`；`batch`、`root`、证明或嵌套字段错型（含 `bool` 整数）抛 `TypeError`
  - `check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` — 原子认领、重算绑定摘要、检查期限后原样委托固定验证器的 `verify_bound_batch` 并透传同一随机源；成功才消费 `session_id`，其余无效（竞争失败、摘要不符、过期、叶内负整数、根/兄弟长度错误、错误根、结构/证明无效或委托返回 `False`）一律返回 `False` 且撤销认领、保持待用，委托验证抛出的异常（含随机源错型 `TypeError`、越界 `ValueError`）先复原再原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `MerkleConsistencyChainReplayGuard(*, store=None)` — 多检查点 Merkle 一致性链的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/mccr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(chain: MerkleConsistencyChain, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把整条一致性链（按原顺序的 `roots` 与 `proofs`，各证明的 `nodes` 亦保持原顺序）一次性绑定到 `session_id`；摘要为 `SHA-256(F(D) || F(session_id) || S(roots, id) || S(proofs, P) || F(E))`，其中 `D = b"zr/mccr/v1"`、`P(p) = F(U(p.old_count)) || F(U(p.new_count)) || S(p.nodes, id)`，F/U/S/E 逐字节沿用各 Bound 守卫；空 id、uint64 越界的期限或 U 值或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，链、根、证明或嵌套字段错型（含 `bool` 计数）抛 `TypeError`
  - `check(chain, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后委托 `verify_consistency_chain` 核链；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，核链抛异常时同样撤销认领并原样抛出；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `MerkleConsistencyReplayGuard(*, store=None)` — 单段 Merkle 一致性证明的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/mcr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(old_root, new_root, proof, session_id, *, expires_at=None) -> ReplayBinding` — 把单段 `MerkleConsistencyProof` 连同其 `old_root`、`new_root` 一次性绑定到 `session_id`；摘要为 `SHA-256(F(D) || F(session_id) || F(old_root) || F(new_root) || F(U(proof.old_count)) || F(U(proof.new_count)) || S(proof.nodes, id) || F(E))`，其中 `D = b"zr/mcr/v1"`，F/U/S/E 逐字节沿用各 Bound 守卫，`S` 对 `nodes` 取恒等映射并保持原序；空 id、uint64 越界的期限或 U 值或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，根、证明或嵌套字段错型（含 `bool` 计数）抛 `TypeError`
  - `check(old_root, new_root, proof, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后委托 `verify_consistency` 核单段一致性；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，验证抛异常时同样撤销认领并原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `MerkleInclusionReplayGuard(*, store=None)` — 单叶 Merkle 包含证明的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/mir/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(leaf, root, proof: MerkleProof, session_id, *, expires_at=None) -> ReplayBinding` — 把单段 `MerkleProof` 连同其 `leaf` 与 Merkle `root` 一次性绑定到 `session_id`；摘要为 `SHA-256(F(D) || F(session_id) || F(leaf) || F(root) || F(U(proof.index)) || S(proof.siblings, id) || F(E))`，其中 `D = b"zr/mir/v1"`，F/U/S/E 逐字节沿用各 Bound 守卫与一致性守卫，`S` 对 `siblings` 取恒等映射并保持叶到根的原序；空 id、uint64 越界的期限或 U 值（`proof.index`）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，leaf、root、证明或嵌套字段错型（含 `bool` 索引）抛 `TypeError`
  - `check(leaf, root, proof, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后以 `verify_inclusion(leaf, proof, root)` 核单叶包含；成功才消费 `session_id`，其余无效一律返回 `False` 且撤销认领、保持待用，验证抛异常时同样撤销认领并原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `MerkleMultiReplayGuard(*, store=None)` — 多叶紧凑 Merkle 包含证明（`MerkleMultiProof`）的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/mmr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(entries, root: bytes, proof: MerkleMultiProof, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把 `MerkleMultiProof` 连同其 `entries`（与 `proof.indices` 同序的 `(index, leaf)` 对）与 Merkle `root` 一次性绑定到 `session_id`；摘要为 `SHA-256(F(D) || F(session_id) || F(root) || F(U(proof.leaf_count)) || S(proof.indices,U) || S(entries,Q) || S(proof.siblings,id) || F(E))`，其中 `D = b"zr/mmr/v1"`、`Q((index,leaf)) = F(U(index)) || F(leaf)`，F/U/S/E 逐字节沿用各 Bound、一致性与单叶包含守卫，`S` 对 `siblings` 取恒等映射并保持逐层、从左到右的原序；空 id、uint64 越界的期限或 U 值（`proof.leaf_count`、各 index、序列长度）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，entries、root、证明或嵌套字段错型（含 `bool` 计数/索引）抛 `TypeError`
  - `check(entries, root, proof, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后以 `verify_multi_inclusion(entries, proof, root)` 核多叶包含；成功才消费 `session_id`，其余无效（含 entries 与 indices 不同序、计数不符、错序或篡改）一律返回 `False` 且撤销认领、保持待用、不改写输入，验证抛异常时同样撤销认领并原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `MerkleConsistencyBatchReplayGuard(*, store=None)` — 独立一致性证明批次的防重放登记册（线程安全）；无参时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/mcbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态
  - `bind_once(entries, session_id: bytes, *, expires_at=None) -> ReplayBinding` — 把一**非空**批 `MerkleConsistencyBatchEntry`（`entries` 的序列形状与类型规则沿用 `verify_consistency_batch`，批次与各 proof 的 `nodes` 均保序、留重、不删项）一次性绑定到 `session_id`；摘要为 `SHA-256(F(D) || F(session_id) || S(entries,Q) || F(E))`，每项 `Q = F(old_root) || F(new_root) || F(U(old_count)) || F(U(new_count)) || S(nodes,id)`，其中 `D = b"zr/mcbr/v1"`，F/U/S/E 逐字节沿用各 Bound 守卫；空批、空 id、uint64 越界的期限或 U 值（各计数、批次与 nodes 序列长度）或待用/校验中（存储后端下含过期认领）/已消费 id 重绑抛 `ValueError`，entries、证明或嵌套字段错型（含 `bool` 计数）抛 `TypeError`
  - `check(entries, binding, *, now=None) -> bool` — 原子认领、重算绑定摘要、检查期限后以 `verify_consistency_batch(entries)` 核整批；成功才消费 `session_id`，无效、过期或竞争失败一律返回 `False` 且不消费、撤销认领、保持待用、不改写输入，验证抛异常时同样撤销认领并原样透传；存储后端下只有持有当前认领 token 的一方能消费，拒绝或异常时以该 token 把 id 复原为待用（token 已失效则为无操作）
- `merkle_root(leaves) -> bytes` — 非空 `bytes` 序列的 Merkle 根
- `prove_inclusion(leaves, index) -> MerkleProof` — 按零基索引生成包含证明
- `verify_inclusion(leaf, proof, root) -> bool` — 验证包含证明
- `MerkleProof(index, siblings)` — 不可变证明对象，`siblings` 为按叶到根排列的 `tuple[bytes, ...]`
- `prove_multi_inclusion(leaves, indices) -> MerkleMultiProof` — 为多片叶子生成紧凑的合并包含证明
- `verify_multi_inclusion(entries, proof, root) -> bool` — 无需完整叶集验证多包含证明；`entries` 按 `proof.indices` 顺序给出 `(index, leaf)`
- `MerkleMultiProof(leaf_count, indices, siblings)` — 不可变多包含证明对象，`indices` 为 `tuple[int, ...]`，`siblings` 为 `tuple[bytes, ...]`
- `prove_consistency(leaves, old_count) -> MerkleConsistencyProof` — 生成追加一致性证明，证明新树由前 `old_count` 片旧叶追加所得
- `verify_consistency(old_root, new_root, proof) -> bool` — 仅凭旧根、新根与证明验证追加一致性
- `MerkleConsistencyProof(old_count, new_count, nodes)` — 不可变一致性证明对象，`nodes` 为 `tuple[bytes, ...]`
- `MerkleConsistencyBatchEntry(old_root, new_root, proof)` — 不可变一致性批验条目，字段依次为 `bytes`、`bytes`、`MerkleConsistencyProof`，次序与 `verify_consistency` 入参一致；三字段均可位置构造、按值相等且不可变
- `verify_consistency_batch(entries) -> bool` — 独立一致性证明的批量验证：逐项以 `old_root`、`new_root`、`proof` 调 `verify_consistency`，各条目计数互不要求衔接，不做密码学聚合
- `BoundConsistencyBatch(entries, leaf_count, proof)` — 冻结的一致性证明完整批对象；字段依次为非空 `tuple[MerkleConsistencyBatchEntry, ...]`、正的非 `bool` `int`、`MerkleMultiProof`，均可位置构造、按值相等且不可变；`leaf_count` 须等于条目数及 `proof.leaf_count`，`proof.indices` 须为 `tuple(range(leaf_count))`，空批、缺项、计数不符或索引不完整均返回 `False`
- `verify_consistency_batch_bound(batch, root) -> bool` — Merkle 承诺的一致性证明完整批验：先以域 `b"zkregion/consistency-bound/v1"` 的叶编码与 `verify_multi_inclusion` 验根（结构/根失败即返回，不委托批验），根通过后原样委托 `verify_consistency_batch(batch.entries)`；错型抛 `TypeError`，其余无效返回 `False`，输入不变
- `prove_consistency_chain(leaves, counts) -> MerkleConsistencyChain` — 生成多检查点一致性链，`roots` 按 `counts` 取前缀根，`proofs` 为相邻段的一致性证明
- `verify_consistency_chain(chain) -> bool` — 一次确认链上每个检查点均由前一棵树连续追加所得
- `MerkleConsistencyChain(roots, proofs)` — 冻结的一致性链对象，`roots` 为 `tuple[bytes, ...]`，`proofs` 为 `tuple[MerkleConsistencyProof, ...]`，可位置构造、按值相等且不可变
- `Region(min_x, max_x, min_y, max_y)` — 闭区间矩形；`contains(x, y)`

### Merkle 树构造

叶摘要为 `SHA-256(b"\x00" + len4 + leaf)`，其中 `len4` 是叶长的四字节无符号大端编码；内部节点摘要为 `SHA-256(b"\x01" + left + right)`。每层按输入顺序两两合并，奇数节点复制末项后再合并；单叶树的根就是叶摘要，证明路径为空。重复叶按调用方给出的零基索引定位，不按内容搜索。`leaves` 为空抛 `ValueError`，叶或索引类型错误抛 `TypeError`，索引越界抛 `IndexError`。验证时 `leaf`、`root` 与各兄弟摘要须为 `bytes`（后两者恰 32 字节），`proof` 须为 `MerkleProof` 且 `index` 为非负整数；类型错误抛 `TypeError`，摘要长度或索引结构非法返回 `False`。验证按 `index` 奇偶决定左右顺序并逐层整除二；叶、索引、路径或根被篡改均返回 `False`，所有入口均不改写输入。

### Merkle 多包含证明

多包含证明复用同一套哈希与奇数末项复制规则，把多片叶子的路径合并为一个证明。`indices` 须非空、严格递增且无重复；生成时逐层从左到右处理：兄弟节点本身也在被证明之列则直接合并、无需收集，奇数层末项无兄弟则自复制，其余情况才收集兄弟摘要；父层位置按 `position // 2` 去重。证明确定且最小——证明全部叶子时 `siblings` 为空。验证方只需 `entries`（按 `proof.indices` 顺序给出的 `(index, leaf)`）、证明与根，无需完整叶集；按同一规则逐层恢复根，且必须恰好耗尽全部 `siblings`，否则返回 `False`。

生成时 `leaves` 须为非空 `bytes` 序列；`leaf_count` 须为正的非 bool 整数，索引须为范围内的非 bool 整数。类型错误抛 `TypeError`，`indices` 为空、重复或乱序抛 `ValueError`，越界抛 `IndexError`。验证时 `entries` 的索引序列须与 `proof.indices` 完全一致；`entries`、`proof`、`root` 或摘要的类型错误抛 `TypeError`；空项、乱序、越界、数量不符、摘要长度错误及任何篡改均返回 `False`。

### Merkle 追加一致性证明

一致性证明让验证方**仅凭旧根、新根与证明**（无需任何叶子）确认：新树恰好由旧叶序列追加若干新叶所得。`prove_consistency(leaves, old_count)` 对前 `old_count` 片叶子生成证明，`new_count = len(leaves)`；`verify_consistency(old_root, new_root, proof)` 验证。证明为冻结的 `MerkleConsistencyProof(old_count, new_count, nodes)`，三字段均可位置构造、按值相等且不可变。

`n` 片叶子的树可分解为 `n` 的二进制展开对应的若干完整子树（高度严格递减），称为峰；`nodes` 先列旧前缀的各峰根（树高递减），再按顺序列新增叶的摘要，摘要逐字节复用同一套 Merkle 协议（`SHA-256(b"\x00" + len4 + leaf)` / `SHA-256(b"\x01" + left + right)`，奇数末项自复制）。验证时先按二进制进位把同高峰合并、再从最右峰起自哈希提升至左邻高度后按 left、right 合并求根：先核对 `old_root`，再把新增叶摘要逐个按进位规则折入峰表并核对 `new_root`。

生成时 `leaves` 须为非空 `bytes` 序列且 `1 <= old_count <= len(leaves)`；叶或计数错型（含 `bool`）抛 `TypeError`，空树或计数越界抛 `ValueError`。验证时根、证明或 `nodes` 的类型错误（含 `bool` 计数）抛 `TypeError`；计数非法（`old_count < 1` 或 `new_count < old_count`）、节点数不符、摘要长度非 32 字节、缺余项或任一根不符均返回 `False`。所有入口均不改写输入。

### 多检查点 Merkle 一致性链

一致性链把单段一致性证明扩展成一串递增检查点：`prove_consistency_chain(leaves, counts)` 对 `counts` 给出的每个检查点取前缀根（`merkle_root(leaves[:count])`）组成 `roots`，并对每对相邻检查点复用 `prove_consistency` 生成段证明组成 `proofs`，一次确认每个检查点都由前一棵树连续追加所得。链为冻结的 `MerkleConsistencyChain(roots, proofs)`，`roots` 为 `tuple[bytes, ...]`、`proofs` 为 `tuple[MerkleConsistencyProof, ...]`，两字段均可位置构造、按值相等且不可变；根与证明节点逐字节沿用既有 Merkle 协议，不新增任何编码。

生成时 `leaves` 须为非空 `bytes` 序列；`counts` 须为至少两项、严格递增且无重复的非 `bool` 整数 `tuple`，每项满足 `1 <= count <= len(leaves)`。叶、`counts` 或计数项错型（含 `bool`）抛 `TypeError`；空树、项数不足、重复、乱序或计数越界抛 `ValueError`。

`verify_consistency_chain(chain)` 要求根数等于证明数加一且至少两个根；每段证明的 `old_count`/`new_count` 须严格递增并与相邻段首尾相接（`proofs[i].new_count == proofs[i+1].old_count`），随后逐段复用 `verify_consistency` 核对相邻两个根。链、根、证明或嵌套字段（计数、`nodes`）错型（含 `bool` 计数）抛 `TypeError`；空链、根或证明数量不符、段间计数断裂或乱序、根非 32 字节、节点摘要长度错误或任一根/节点不符均返回 `False`。入口不改写任何输入。

### 独立 Merkle 一致性证明批验

`verify_consistency_batch(entries)` 一次检查多组彼此独立的旧根、新根与一致性证明。每个条目是把 `verify_consistency` 的三个入参（`old_root`、`new_root`、`proof`）按原顺序冻结成的不可变数据类 `MerkleConsistencyBatchEntry(old_root, new_root, proof)`，字段类型依次为 `bytes`、`bytes`、`MerkleConsistencyProof`；三字段均可位置构造，对象按值相等且不可变。

`entries` 须为非 `bytes`/`bytearray`/`str` 的序列：空批返回 `False`，列表、元组以及重复条目均合法。验证逐项按 `old_root`、`new_root`、`proof` 顺序委托既有 `verify_consistency`，完全沿用其根长度、计数、节点数量与长度、缺余节点及追加关系规则；任一条目无效即返回 `False`，允许短路。各条目彼此独立：不要求相邻计数衔接（与一致性链不同），可以乱序、可以重复；批验不新增任何哈希编码，也不做密码学聚合。

`entries` 本身不是序列或是 `bytes`/`bytearray`/`str`、条目不是 `MerkleConsistencyBatchEntry`、任一字段错型——含嵌套证明的 `bool` 计数、`nodes` 非元组或节点非 `bytes`——均抛 `TypeError`，即类型错误不会被转换为批量拒绝（返回 `False`）。除空批外，根非 32 字节、计数非法（`old_count < 1` 或 `new_count < old_count`）、节点数量或长度不符、缺余节点、任一根或追加关系不符均返回 `False`。入口不改写任何输入。

### Merkle 承诺的一致性证明完整批验

`BoundConsistencyBatch(entries, leaf_count, proof)` 把一批**完整**的一致性证明条目与一棵 Merkle 树的多包含证明冻结在一起，三个字段依次为：

1. `entries: tuple[MerkleConsistencyBatchEntry, ...]` —— 必须是非空元组（不是列表），每项是 `MerkleConsistencyBatchEntry`；
2. `leaf_count: int` —— 正的非 `bool` 整数，且必须同时等于 `len(entries)` 与 `proof.leaf_count`；
3. `proof: MerkleMultiProof` —— 其 `indices` 必须无缺口、无重复、无乱序地恰好覆盖 `0 .. leaf_count - 1`（即等于 `tuple(range(leaf_count))`）。

三字段均可位置构造，对象按值相等且不可变（冻结 dataclass）。空批（`leaf_count < 1` 或 `entries` 为空）、缺项（数量不符）、`leaf_count` 与条目数或 `proof.leaf_count` 不一致、`proof.indices` 不等于 `tuple(range(leaf_count))`（含索引缺口、重复、乱序）均返回 `False`。

每个条目的 Merkle 叶字节以域 `b"zkregion/consistency-bound/v1"` 开始，随后按 `old_root,new_root,old_count,new_count,nodes` 的顺序写入对应字段：先 `old_root`、`new_root` 两个根的原始 `bytes`，再写 `old_count`、`new_count` 的十进制 ASCII，最后按原序写入该证明 `nodes` 的每片原始 `bytes`。每个原子项前置四字节无符号大端长度；根与 nodes 不经任何编码、原样成帧并保持原序（含重复）。叶摘要仍按 Merkle 树构造一节的 `SHA-256(b"\x00" + len4 + leaf)` 计算。

`verify_consistency_batch_bound(batch, root) -> bool` 的验证分两步、次序固定：

1. 先校验批结构（`entries` 非空元组、`leaf_count` 正数且与条目数及 `proof.leaf_count` 相等、`proof.indices == tuple(range(leaf_count))`），再以全部 `(index, leaf)`（`index` 即 0 起的条目位置）调用 `verify_multi_inclusion` 校验 Merkle 根；任一叶字节、proof 或根不符即返回 `False`，且根校验通过前不进行任何批验；
2. 根通过后，**原样委托** `verify_consistency_batch(batch.entries)`，逐项沿用其根长度、计数、节点数量与长度、缺余节点及追加关系规则，不做包装或改动。

类型错误——`batch` 不是 `BoundConsistencyBatch`、`entries` 不是元组或含非 `MerkleConsistencyBatchEntry`、条目嵌套字段类型错误（根非 `bytes`、`proof` 非 `MerkleConsistencyProof`、`bool` 计数、`nodes` 非元组或节点非 `bytes`）、`leaf_count` 不是非 `bool` 整数、外层 `proof`/`root` 类型错误——抛 `TypeError`；其余一切无效情形（空批、缺项、计数不符、索引不完整、错误根、叶字节篡改、根非 32 字节，以及委托 `verify_consistency_batch` 返回的任何 `False`）均返回 `False`。入口不改写任何输入。

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

`check(entry, binding, *, now=None) -> bool` 只接受仍待用且与登记值相等的绑定。校验次序为：在登记册中查到 `binding.session_id` 的待用绑定且与 `binding` 按值相等；重算摘要确认提交的 `entry` 就是绑定时的条目；有期绑定要求 `now < expires_at`（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`）；随后以条目的公钥与群参数构造 `SchnorrVerifier(public_key, prime=entry.prime, generator=entry.generator)`，再以 `entry.message`、`entry.proof`、`entry.context`（keyword `context=`）调用 `verify_proof`，旧接口的入参与行为完全不变——非法群参数或验签失败均返回 `False`。只有全部成功才把 `session_id` 从待用移入已消费；未登记（含已消费）的 id、不等值绑定、摘要不符、过期或验签失败一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。无参构造时绑定状态不跨实例共享；`check` 的参数类型错误抛 `TypeError`。入口不改写任何输入。

#### 可选 SQLite 后端

`ReplayGuard(*, store=None)` 在传入 `SQLiteReplayStore` 时，待用、认领与已消费三种状态改由该存储保存，守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界逐字节、逐类型保持不变。

`SQLiteReplayStore(path: str, namespace: bytes = b"default", *, lease_seconds: int = 30, clock=None)` 打开（必要时创建）`path` 处的 SQLite 数据库：`path` 须为 `str`、`namespace` 须为 `bytes`，否则 `TypeError`；`lease_seconds` 须为正的非 `bool` 整数，类型错抛 `TypeError`、非正抛 `ValueError`；`clock` 缺省为返回整数 Unix 秒的可调用对象，显式给出时必须可调用（否则 `TypeError`），其返回值须为非 `bool` 整数且落在 uint64 范围内——`bool`/非整数抛 `TypeError`，越界抛 `ValueError`；`clock() + lease_seconds` 越出 uint64 同样抛 `ValueError`。每个状态行的键为 `namespace`、`b"zr/r/v1"`、`session_id` 三段 `bytes`，值保存与 `ReplayBinding` 等值的摘要与期限（无期 `b"\x00"`、有期 `b"\x01" + uint64be(expires_at)`，与摘要中的 `E` 编码一致；租约截止时间因 SQLite 整数为有符号 64 位而以 8 字节大端 `BLOB` 保存）以及状态与认领 token。同一文件同一命名空间的多个独立 `SQLiteReplayStore`（包括重启后与其它进程中的实例）共享全部状态，不同命名空间互不影响；数据库错误原样透传 `sqlite3.Error`。

`bind_once` 在一个短事务中插入待用行；键已存在即抛 `ValueError`——待用、被认领（**即使认领租约已过期**；过期认领只能由 `check` 接管）或已消费的 id 都不能重绑。

`check` 在一个短事务内写入随机认领 token 与 `clock() + lease_seconds` 截止时间后完成认领（待用时要求存储的绑定与提交的 `binding` 按值相等；行不存在、已消费或认领仍有效时认领失败返回 `False`），随后在**不持任何事务**的情况下重算摘要、检查期限并验签。认领截止时间已过的旧认领可被等值 `binding` 的 `check` 接管并换发新 token；只有持有当前 token 的一方能把 id 置为已消费，旧 token 在被接管后既不能消费也不能复原。验签失败、摘要不符、过期等一切拒绝以及验证期间逃出的异常，都以当前 token 在短事务中把 id 复原为待用（token 已失效则为无操作，保持已消费或新认领方的状态不变）；旧认领方因此不可能在被接管后消费成功。

### 多公钥 Schnorr 批次的一次性绑定

`SchnorrBatchReplayGuard(*, store=None)` 为整批 :class:`MultiSchnorrEntry` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型；`bind_once` 的入参为 `(entries, session_id, *, expires_at=None)`，`entries` 沿用 :func:`verify_schnorr_batch` 的序列与嵌套类型规则（非 `bytes`/`bytearray`/`str` 的 `Sequence`，每项为六字段嵌套类型正确的 `MultiSchnorrEntry`），批次保序、留重、不丢项；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/sbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要为

```
digest = SHA-256(F(D) || F(session_id) || S(entries, Q) || F(E))
```

其中：

- 域 `D = b"zr/sbr/v1"`；
- `F(x)` 是四字节无符号大端长度前缀加 `x`，`U(n)` 是八字节无符号大端整数编码；
- `S(a, f) = F(U(|a|)) || Σ F(f(a_i))`，即先写以 `U` 编码的元素数，再逐项成帧；
- `Q(entry)` 取"Merkle 承诺的 Schnorr 完整批验"一节定义的既有 BoundSchnorr 叶**原字节**（`_bound_schnorr_leaf`：以最短无符号大端编码写 `prime`、`generator`、`public_key`、commitment、`context`、`message` 与 response、域为 `b"zkregion/schnorr-fs/v1"` 的叶原字节），再整体套一层 `F`；
- `E` 的过期编码与 `ReplayGuard` 逐字节相同：无期 `E = b"\x00"`，有期 `E = b"\x01" + uint64be(expires_at)`。

`bind_once` 只登记、不验签。类型错误（序列错型、非 `MultiSchnorrEntry` 项、嵌套字段错型，含 `bool` 整数）抛 `TypeError`；登记空批、`session_id` 为空、`expires_at` 越出 uint64、`U` 成帧的批次长度越界、任一叶内整数（`prime`、`generator`、`public_key`、commitment、response）为负，或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。

`check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序为：先原子认领登记册中的等值待用绑定（存储后端下认领租约过期后可被等值 `check` 接管并换发 token），再重算摘要确认提交的整批条目（含顺序与重复项）就是绑定时的批次，再检查期限（有期绑定要求 `now < expires_at`；`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，`bool`/非整数抛 `TypeError`、越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**透传给 `verify_schnorr_batch(entries, randbelow=randbelow)`——每个结构合法条目恰好抽取一次 `randbelow(prime - 1)` 随机系数，随机源不可调用或返回非整数（含 `bool`）抛 `TypeError`、返回值越界抛 `ValueError`，群参数/公钥/证明结构非法或批验失败返回 `False`，均不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、竞争失败、不等值绑定、摘要不符、空批、叶内负整数、过期或批验返回 `False` 一律返回 `False` 且撤销认领、把 id **复原为待用**；委托验证逃出的异常（含随机源的 `TypeError` / `ValueError`）同样先撤销认领再原样透传，id 之后仍可成功一次。存储后端下只有持有当前认领 token 的一方能消费，过期认领被接管后旧 token 既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。无参构造时绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，`store` 参数类型错误抛 `TypeError`。入口不改写任何输入。

### 区间证明批次的一次性绑定

`RangeBatchReplayGuard(*, store=None)` 为整批 :class:`RangeBatchEntry` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型；`bind_once` 的入参为 `(entries, session_id, *, expires_at=None)`，`entries` 沿用 :func:`verify_range_batch` 的序列与嵌套类型规则（非 `bytes`/`bytearray`/`str` 的 `Sequence`，每项为 :class:`PedersenCommitment` 六字段、:class:`RangeProof` 的 `t`/`e`/`s` 整数元组与 `context` 嵌套类型正确的 `RangeBatchEntry`），批次保序、留重、不丢项；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要为

```
digest = SHA-256(F(D) || F(session_id) || S(entries, L) || F(E))
```

其中：

- 域 `D = b"zr/rbr/v1"`；
- `F(x)` 是四字节无符号大端长度前缀加 `x`，`U(n)` 是八字节无符号大端整数编码；
- `S(a, f) = F(U(|a|)) || Σ F(f(a_i))`，即先写以 `U` 编码的元素数，再逐项成帧；
- `L(entry)` 取"Merkle 承诺的区间证明完整批验"一节定义的既有 BoundRange 叶**原字节**（`_bound_range_leaf`：以十进制 ASCII（负号保留）写六个承诺字段、`context` 与证明的 `t`/`e`/`s` 序列、域为 `b"zkregion/range-bound/v1"` 的叶原字节），再整体套一层 `F`；
- `E` 的过期编码与 `ReplayGuard` 逐字节相同：无期 `E = b"\x00"`，有期 `E = b"\x01" + uint64be(expires_at)`。

`bind_once` 只登记、不验证明。类型错误（序列错型、非 `RangeBatchEntry` 项、嵌套字段错型，含 `bool` 整数）抛 `TypeError`；登记空批、`session_id` 为空、`expires_at` 越出 uint64、`U` 成帧的批次长度越界，或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。BoundRange 叶以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有逐叶的可编码性拒绝。

`check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序为：先原子认领登记册中的等值待用绑定（存储后端下认领租约过期后可被等值 `check` 接管并换发 token），再重算摘要确认提交的整批条目（含顺序与重复项）就是绑定时的批次，再检查期限（有期绑定要求 `now < expires_at`；`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，`bool`/非整数抛 `TypeError`、越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**透传给 `verify_range_batch(entries, randbelow=randbelow)`——每个结构合法的区间证明分支恰好抽取一次 `randbelow(prime - 1)` 随机系数，随机源不可调用或返回非整数（含 `bool`）抛 `TypeError`、返回值越界抛 `ValueError`，结构非法或批验失败返回 `False`，均不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、竞争失败、不等值绑定、摘要不符、空批、过期或批验返回 `False` 一律返回 `False` 且撤销认领、把 id **复原为待用**；委托验证逃出的异常（含随机源的 `TypeError` / `ValueError`）同样先撤销认领再原样透传，id 之后仍可成功一次。存储后端下只有持有当前认领 token 的一方能消费，过期认领被接管后旧 token 既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。无参构造时绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，`store` 参数类型错误抛 `TypeError`。入口不改写任何输入。

### 区域证明批次的一次性绑定

`RegionBatchReplayGuard(*, store=None)` 为整批 :class:`RegionBatchEntry` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型；`bind_once` 的入参为 `(entries, session_id, *, expires_at=None)`，`entries` 沿用 :func:`verify_region_batch` 的序列与嵌套类型规则（非 `bytes`/`bytearray`/`str` 的 `Sequence`，每项为两个 :class:`PedersenCommitment` 六字段、:class:`Region` 四个边界、:class:`RegionProof` 的 `x_proof`/`y_proof` 各自 `t`/`e`/`s` 整数元组与 `context` 嵌套类型正确的 `RegionBatchEntry`），批次保序、留重、不丢项；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rgbr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要为

```
digest = SHA-256(F(D) || F(session_id) || S(entries, L) || F(E))
```

其中：

- 域 `D = b"zr/rgbr/v1"`；
- `F(x)` 是四字节无符号大端长度前缀加 `x`，`U(n)` 是八字节无符号大端整数编码；
- `S(a, f) = F(U(|a|)) || Σ F(f(a_i))`，即先写以 `U` 编码的元素数，再逐项成帧；
- `L(entry)` 取"Merkle 承诺的区域证明完整批验"一节定义的既有 BoundRegion 叶**原字节**（`_bound_region_leaf`：以十进制 ASCII（负号保留）写两个承诺各六个字段、四个区域边界、`context` 与 `x_proof`/`y_proof` 各自的 `t`/`e`/`s` 序列、域为 `b"zkregion/region-bound/v1"` 的叶原字节），再整体套一层 `F`；
- `E` 的过期编码与 `ReplayGuard` 逐字节相同：无期 `E = b"\x00"`，有期 `E = b"\x01" + uint64be(expires_at)`。

`bind_once` 只登记、不验证明。类型错误（序列错型、非 `RegionBatchEntry` 项、嵌套字段错型，含 `bool` 整数）抛 `TypeError`；登记空批、`session_id` 为空、`expires_at` 越出 uint64、`U` 成帧的批次长度越界，或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。BoundRegion 叶以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有逐叶的可编码性拒绝。

`check(entries, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序为：先原子认领登记册中的等值待用绑定（存储后端下认领租约过期后可被等值 `check` 接管并换发 token），再重算摘要确认提交的整批条目（含顺序与重复项）就是绑定时的批次，再检查期限（有期绑定要求 `now < expires_at`；`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，`bool`/非整数抛 `TypeError`、越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**透传给 `verify_region_batch(entries, randbelow=randbelow)`——每个结构合法的区间证明分支（x 轴与 y 轴）恰好抽取一次 `randbelow(prime - 1)` 随机系数，随机源不可调用或返回非整数（含 `bool`）抛 `TypeError`、返回值越界抛 `ValueError`，结构非法或批验失败返回 `False`，均不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、竞争失败、不等值绑定、摘要不符、空批、过期或批验返回 `False` 一律返回 `False` 且撤销认领、把 id **复原为待用**；委托验证逃出的异常（含随机源的 `TypeError` / `ValueError`）同样先撤销认领再原样透传，id 之后仍可成功一次。存储后端下只有持有当前认领 token 的一方能消费，过期认领被接管后旧 token 既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。无参构造时绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，`store` 参数类型错误抛 `TypeError`。入口不改写任何输入。

### 区间证明的一次性绑定

`RangeReplayGuard(*, store=None)` 为 :class:`RangeBatchEntry` 提供与 `ReplayGuard` 同构的一次性会话绑定，复用同一个 `ReplayBinding` 类型；无参构造时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rr/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要按同一公式

```
digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
```

计算，但域为 `D = b"zr/rr/v1"`，`L(entry)` 是"Merkle 承诺的区间证明完整批验"一节定义的 BoundRange 叶原字节（**不**再套 `F`），`E` 的过期编码与 `ReplayGuard` 逐字节相同。

`bind_once(entry, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它，参数边界与 `ReplayGuard` 一致：`entry` 须为 `RangeBatchEntry`（承诺、证明、`t`/`e`/`s` 元组与 `context` 的嵌套类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64 或 id 已待用/已消费均抛 `ValueError`。区间叶编码以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有额外的可编码性拒绝。

`check(entry, binding, *, now=None) -> bool` 的校验次序与 `ReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认条目一致，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），最后按字段顺序以 `entry.commitment`、`entry.proof`、`entry.context` 调用 `verify_range` 验区间证明。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、不等值绑定、摘要不符、过期或验证失败一律返回 `False` 且**不消费**。无参构造时绑定状态不跨实例共享；类型错误抛 `TypeError`。入口不改写任何输入。

存储后端下 `RangeReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段换为 `b"zr/rr/v1"`（与同一存储上 `ReplayGuard` 的 `b"zr/r/v1"` 行互不冲突）：`bind_once` 在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`；`check` 在一个短事务内写入随机认领 token 与 `clock() + lease_seconds` 截止时间完成认领（过期认领可被等值 `binding` 的 `check` 接管并换发新 token），随后在**不持任何事务**的情况下重算摘要、检查期限并调用 `verify_range`；只有持有当前 token 的一方能把 id 置为已消费，一切拒绝或验证期间逃出的异常都以当前 token 把 id 复原为待用（token 已失效则为无操作）；数据库错误原样透传 `sqlite3.Error`。守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界在两种模式下逐字节、逐类型保持一致。

### 二维区域证明的实例内一次性绑定

`RegionReplayGuard(*, store=None)` 在单个实例内为 :class:`RegionBatchEntry` 提供与 `RangeReplayGuard` 同构的一次性会话绑定，复用同一个 `ReplayBinding` 类型；无参构造时状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中（行键域为 `b"zr/rg/v1"`），同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要按同一公式

```
digest = SHA-256(F(D) || F(session_id) || L(entry) || F(E))
```

计算，但域为 `D = b"zr/rg/v1"`，`L(entry)` 是"Merkle 承诺的区域证明完整批验"一节定义的 BoundRegion 叶原字节（**不**再套 `F`），`E` 的过期编码与 `ReplayGuard` 逐字节相同。

`bind_once(entry, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它，参数边界与 `RangeReplayGuard` 一致：`entry` 须为 `RegionBatchEntry`（两个承诺、区域、`x_proof`/`y_proof` 及各自 `t`/`e`/`s` 元组与 `context` 的嵌套类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64 或 id 已待用/已消费均抛 `ValueError`。区域叶编码以十进制 ASCII 写整数（负号保留），任何整数字段都可成帧，因此没有额外的可编码性拒绝。

`check(entry, binding, *, now=None) -> bool` 的校验次序与 `RangeReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认条目一致，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），最后按字段顺序以 `entry.x_commitment`、`entry.y_commitment`、`entry.region`、`entry.proof`、`entry.context` 调用 `verify_region` 验二维区域证明（先 x 后 y 的字段顺序沿用旧接口，不被改写）。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、不等值绑定、摘要不符、条目任一字段被替换、过期或 `verify_region` 失败一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。无参构造时绑定状态不跨实例共享；类型错误抛 `TypeError`。入口不改写任何输入。

存储后端下 `RegionReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段不同。行键为 `namespace`、`b"zr/rg/v1"`、`session_id` 三段 `bytes`（与同一存储上 `ReplayGuard` 的 `b"zr/r/v1"`、`RangeReplayGuard` 的 `b"zr/rr/v1"` 行互不冲突）：`bind_once` 在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`；`check` 在一个短事务内写入随机认领 token 与 `clock() + lease_seconds` 截止时间完成认领（过期认领可被等值 `binding` 的 `check` 接管并换发新 token），随后在**不持任何事务**的情况下重算摘要、检查期限并调用 `verify_region`；只有持有当前 token 的一方能把 id 置为已消费，一切拒绝或验证期间逃出的异常都以当前 token 把 id 复原为待用（token 已失效则为无操作）；数据库错误原样透传 `sqlite3.Error`。守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界在两种模式下逐字节、逐类型保持一致。

### Merkle 承诺区域批的一次性绑定

`BoundRegionReplayGuard(*, store=None)` 为整批 :class:`BoundRegionBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型；`bind_once` 的入参为 `(batch, root, session_id, *, expires_at=None)`，旧接口（无参构造的三个单条目守卫与本守卫）的入参与行为完全不变。无参构造时待用/已消费状态隔离在本实例内存中；传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中，同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要为

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

`bind_once(batch, root, session_id, *, expires_at=None)` 登记待用绑定并返回它。类型边界与 `verify_region_bound` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、或 id 已待用/校验中/已消费均抛 `ValueError`。

`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序为：先原子认领登记册中的待用绑定（与提交绑定按值相等），再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后以**同一个 `randbelow`** 调用 `verify_region_bound(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与区域批验证明全部通过其随机源契约（每结构合法分支 `randbelow(prime - 1)` 一次，非整数返回 `TypeError`、越界返回 `ValueError`），不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、竞争失败、不等值绑定、摘要不符、过期、根或兄弟长度错误、错误根、任何结构/证明无效或委托验证返回 `False` 一律返回 `False` 且撤销认领、**不消费**，因此被拒的绑定稍后仍可成功一次；`randbelow` 等委托验证抛出的异常同样先撤销认领再原样透传。无参构造时绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，`store` 参数类型错误抛 `TypeError`。入口不改写任何输入。

存储后端下 `BoundRegionReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段不同。行键为 `namespace`、`b"zr/brg/v1"`、`session_id` 三段 `bytes`（与同一存储上 `ReplayGuard` 的 `b"zr/r/v1"`、`RangeReplayGuard` 的 `b"zr/rr/v1"`、`RegionReplayGuard` 的 `b"zr/rg/v1"` 行互不冲突），值保存等值 `ReplayBinding`（摘要与 `E` 期限编码逐字节沿用绑定摘要的编码）、状态、认领 token 与租约截止：`bind_once` 在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`；`check` 在一个短事务内写入随机认领 token 与八字节无符号大端的 `clock() + lease_seconds` 租约截止完成认领（行不存在、已消费、认领仍有效或存储绑定不等值时认领失败返回 `False`；过期认领可被等值 `binding` 的 `check` 接管并换发新 token），随后在**不持任何事务**的情况下重算摘要、检查期限并把 `randbelow` 原样传给 `verify_region_bound`；只有持有当前 token 的一方能把 id 置为已消费，一切拒绝（返回 `False`）或验证期间逃出的异常都以当前 token 把 id 复原为待用（token 已失效则为无操作，保持已消费或新认领方的状态不变），旧认领方在被接管后既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界在内存与 SQLite 两种模式下逐字节、逐类型保持一致，旧绑定在两种后端下均兼容。

### Merkle 承诺区间批的一次性绑定

`BoundRangeReplayGuard(*, store=None)` 为整批 :class:`BoundRangeBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型，`bind_once` 的入参同为 `(batch, root, session_id, *, expires_at=None)`；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中，同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要逐字节复用 `BoundRegionReplayGuard` 的公开公式与 `F`、`U`、`S`、`E` 编码，条目顺序不变，仅两处不同：

- 域改为 `D = b"zr/brr/v1"`；
- 逐项成帧的 `L(entry_i)` 改为"Merkle 承诺的区间证明完整批验"一节定义的 BoundRange 叶原字节（`_bound_range_leaf`），即以十进制 ASCII 写六个承诺字段、`context` 与证明的 `t`/`e`/`s` 序列、域为 `b"zkregion/range-bound/v1"` 的叶原字节。

`bind_once(batch, root, session_id, *, expires_at=None)` 登记待用绑定并返回它。类型边界与 `verify_range_bound` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、或 id 已待用/校验中/已消费均抛 `ValueError`。内存模式下待用与已消费状态只存在于本实例、不跨实例共享；存储模式下在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`。

`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序与 `BoundRegionReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**传给 `verify_range_bound(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与区间批验证明全部通过其随机源契约（每结构合法分支 `randbelow(prime - 1)` 一次，非整数返回 `TypeError`、越界返回 `ValueError`），不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、被替换的绑定、摘要不符、过期、根或兄弟长度错误、错误根、其他摘要/结构/证明无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。内存模式下绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`。入口不改写任何输入。

存储后端下 `BoundRangeReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段不同。行键为 `namespace`、`b"zr/brr/v1"`、`session_id` 三段 `bytes`（与同一存储上 `ReplayGuard` 的 `b"zr/r/v1"`、`RangeReplayGuard` 的 `b"zr/rr/v1"`、`RegionReplayGuard` 的 `b"zr/rg/v1"`、`BoundRegionReplayGuard` 的 `b"zr/brg/v1"` 行互不冲突），值保存等值 `ReplayBinding`（摘要与 `E` 期限编码逐字节沿用绑定摘要的编码）、状态、认领 token 与租约截止：`check` 在一个短事务内写入随机认领 token 与八字节无符号大端的 `clock() + lease_seconds` 租约截止完成认领（行不存在、已消费、认领仍有效或存储绑定不等值时认领失败返回 `False`；过期认领可被等值 `binding` 的 `check` 接管并换发新 token），随后在**不持任何事务**的情况下重算摘要、检查期限并把 `randbelow` 原样传给 `verify_range_bound`；只有持有当前 token 的一方能把 id 置为已消费，一切拒绝（返回 `False`）或验证期间逃出的异常都以当前 token 把 id 复原为待用（token 已失效则为无操作，保持已消费或新认领方的状态不变），旧认领方在被接管后既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界在内存与 SQLite 两种模式下逐字节、逐类型保持一致，旧绑定在两种后端下均兼容。

### Merkle 承诺 Schnorr 批的一次性绑定

`BoundSchnorrReplayGuard(*, store=None)` 为整批 :class:`BoundSchnorrBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型，`bind_once` 的入参同为 `(batch, root, session_id, *, expires_at=None)`；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中，同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要逐字节复用 `BoundRegionReplayGuard` 的公开公式与 `F`、`U`、`S`、`E` 编码，字段次序与条目顺序不变，仅两处不同：

- 域改为 `D = b"zr/bsr/v1"`；
- 逐项成帧的 `L(entry_i)` 改为"Merkle 承诺的 Schnorr 完整批验"一节定义的 BoundSchnorr 叶原字节（`_bound_schnorr_leaf`），即以最短无符号大端编码写 `prime`、`generator`、`public_key`、commitment、`context`、`message` 与 response、域为 `b"zkregion/schnorr-fs/v1"` 的叶原字节。

字段依次为 `D`、`session_id`、`root`、`batch.leaf_count`、`entries` 顺序的各 `L`，再写 `proof.leaf_count`、`indices`、`siblings`、`E`；其中 `U` 成帧的整数（`batch.leaf_count`、`proof.leaf_count`、各索引）须落在 uint64 内，而叶原字节 `L` 内的五个整数（`prime`、`generator`、`public_key`、commitment、response）使用无符号大端编码，**须非负**。

`bind_once(batch, root, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它。类型边界与 `verify_bound` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、任一叶内整数为负、或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。内存模式下待用与已消费状态只存在于本实例、不跨实例共享；存储模式下在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`。

`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序与 `BoundRegionReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**传给 `verify_bound(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与多公钥批验签全部通过其随机源契约（每结构合法条目 `randbelow(prime - 1)` 一次，非整数返回 `TypeError`、越界返回 `ValueError`），不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、被替换的绑定、摘要不符、过期、叶内负整数、根或兄弟长度错误、错误根、其他摘要/结构/签名无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。内存模式下绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`。入口不改写任何输入。

存储后端下 `BoundSchnorrReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段不同。行键为 `namespace`、`b"zr/bsr/v1"`、`session_id` 三段 `bytes`（与同一存储上 `ReplayGuard` 的 `b"zr/r/v1"`、`RangeReplayGuard` 的 `b"zr/rr/v1"`、`RegionReplayGuard` 的 `b"zr/rg/v1"`、`BoundRegionReplayGuard` 的 `b"zr/brg/v1"`、`BoundRangeReplayGuard` 的 `b"zr/brr/v1"` 行互不冲突），值保存等值 `ReplayBinding`（摘要与 `E` 期限编码逐字节沿用绑定摘要的编码）、状态、认领 token 与租约截止：`check` 在一个短事务内写入随机认领 token 与八字节无符号大端的 `clock() + lease_seconds` 租约截止完成认领（行不存在、已消费、认领仍有效或存储绑定不等值时认领失败返回 `False`；过期认领可被等值 `binding` 的 `check` 接管并换发新 token），随后在**不持任何事务**的情况下重算摘要、检查期限并把 `randbelow` 原样传给 `verify_bound`；只有持有当前 token 的一方能把 id 置为已消费，一切拒绝（返回 `False`）或验证期间逃出的异常都以当前 token 把 id 复原为待用（token 已失效则为无操作，保持已消费或新认领方的状态不变），旧认领方在被接管后既不能消费也不能复原；数据库错误原样透传 `sqlite3.Error`。守卫的摘要公式、`ReplayBinding` 类型与 `bind_once`/`check` 的参数边界在内存与 SQLite 两种模式下逐字节、逐类型保持一致，旧绑定在两种后端下均兼容。

### Merkle 承诺一致性批的一次性绑定

`BoundConsistencyReplayGuard(*, store=None)` 为整批 :class:`BoundConsistencyBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型，`bind_once` 的入参同为 `(batch, root, session_id, *, expires_at=None)`；无参构造时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中，同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要逐字节复用 `BoundRegionReplayGuard` 的公开公式与 `F`、`U`、`S`、`E` 编码，字段次序与条目顺序不变（保序留重），仅两处不同：

- 域改为 `D = b"zr/bcbr/v1"`；
- 逐项成帧的 `L(entry_i)` 是既有一致性 Bound 叶原字节（`_bound_consistency_leaf`），即 `verify_consistency_batch_bound` 验根时重算的叶字节。

`bind_once(batch, root, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它。类型边界与 `verify_consistency_batch_bound` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。内存模式下待用与已消费状态只存在于本实例、不跨实例共享；存储模式下在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`。

`check(batch, root, binding, *, now=None) -> bool` 的校验次序与 `BoundRegionReplayGuard` 相同：先原子认领登记册中与提交绑定按值相等的待用绑定，再重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后原样委托 `verify_consistency_batch_bound(batch, root)`。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、竞争失败、被替换的绑定、摘要不符、过期、根或兄弟长度错误、错误根、其他摘要/结构/证明无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。委托验证逃出的异常先撤销认领再原样透传。内存模式下绑定状态不跨实例共享；`check` 的参数类型错误抛 `TypeError`。入口不改写任何输入。

存储后端下 `BoundConsistencyReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段为 `b"zr/bcbr/v1"`（与同一存储上 `MerkleConsistencyBatchReplayGuard` 的 `b"zr/mcbr/v1"`、`BoundRegionReplayGuard` 的 `b"zr/brg/v1"` 等行互不冲突）：认领、换发 token、消费与异常复原语义与 `BoundRegionReplayGuard` 逐字节一致，数据库错误原样透传 `sqlite3.Error`。

### Merkle 承诺同一公钥 Schnorr 批的一次性绑定

`SingleKeyBoundReplayGuard(public_key, *, prime=DEFAULT_PRIME, generator=DEFAULT_GENERATOR, store=None)` 为整批 :class:`SingleKeyBoundBatch` 连同其 Merkle `root` 提供一次性会话绑定，复用同一个 `ReplayBinding` 类型，`bind_once` 的入参同为 `(batch, root, session_id, *, expires_at=None)`。与 `SingleKeyBatchGuard` 一样，公钥与群参数在构造时固定，并据以构造一个固定的 `SchnorrVerifier`：`public_key`、`prime`、`generator` 错型（含 `bool`）抛 `TypeError`，`0 < public_key < prime`、`1 < generator < prime` 之外的非法群值抛 `ValueError`。无参 `store` 时待用/已消费状态隔离在本实例内存中，传入 `SQLiteReplayStore` 时待用/认领/已消费状态落在该存储中，同文件同命名空间的独立实例（含重启后、跨进程）共享状态。绑定摘要逐字节复用 `BoundSchnorrReplayGuard` 的公开公式与 `F`、`U`、`S`、`E` 编码，字段次序与条目顺序不变，仅两处不同：

- 域改为 `D = b"zr/skbbr/v1"`；
- 逐项成帧的 `L(entry_i)` 是以本守卫固定公钥与群参数构造的 BoundSchnorr 叶原字节（`_bound_schnorr_leaf`），即把每条 `SchnorrBatchEntry` 的 `message`、`proof`、`context` 连同守卫的 `public_key`、`prime`、`generator` 提升为 `MultiSchnorrEntry` 后得到的叶字节——与 `SchnorrVerifier.verify_bound_batch` 验根时重算的叶逐字节一致。

`bind_once(batch, root, session_id, *, expires_at=None)` 登记本实例的待用绑定并返回它。类型边界与 `verify_bound_batch` 一致（`batch` 及其嵌套条目、`proof` 的字段类型同样校验），类型错误抛 `TypeError`；`session_id` 为空、`expires_at` 非 uint64、任一 `U` 成帧整数（`leaf_count`、`proof.leaf_count` 或索引）为负或超出 uint64、任一叶内整数（证明 commitment/response）为负、或 id 已待用/校验中（存储后端下含过期认领）/已消费均抛 `ValueError`。内存模式下待用与已消费状态只存在于本实例、不跨实例共享；存储模式下在一个短事务中插入待用行，键已存在（待用、被认领——**即使租约已过期**——或已消费）即抛 `ValueError`。

`check(batch, root, binding, *, now=None, randbelow=secrets.randbelow) -> bool` 的校验次序与 `BoundSchnorrReplayGuard` 相同：先核对登记册中的待用绑定与提交绑定按值相等，再以本守卫固定公钥与群参数重算摘要确认提交的 `batch`/`root` 就是绑定时的对象，再检查期限（`now` 缺省取当前 Unix 秒，显式给出时须为非 `bool` uint64，越界抛 `ValueError`），随后将**同一个 `randbelow` 原样**传给固定验证器的 `verify_bound_batch(batch, root, randbelow=randbelow)`——根与兄弟摘要须恰 32 字节、Merkle 根校验与同一公钥批验签全部通过其随机源契约（每结构合法条目 `randbelow(prime - 1)` 一次，非整数返回 `TypeError`、越界返回 `ValueError`），不做包装或改写。只有全部成功才消费 `session_id`；未登记（含已消费）的 id、被替换的绑定、摘要不符、过期、叶内负整数、根或兄弟长度错误、错误根、其他摘要/结构/签名无效或委托验证返回 `False` 一律返回 `False` 且**不消费**，因此被拒的绑定稍后仍可成功一次。委托验证逃出的异常（含随机源的 `TypeError` / `ValueError`）先撤销认领再原样透传。内存模式下绑定状态不跨实例共享；`check` 的参数类型错误（含不可调用的 `randbelow`）抛 `TypeError`，`store` 参数类型错误抛 `TypeError`。入口不改写任何输入。

存储后端下 `SingleKeyBoundReplayGuard` 复用 `SQLiteReplayStore` 的全部机制，仅行键的域段为 `b"zr/skbbr/v1"`（与同一存储上 `BoundSchnorrReplayGuard` 的 `b"zr/bsr/v1"`、`SingleKeyBatchGuard` 的 `b"zr/skbr/v1"` 等行互不冲突）：认领、换发 token、消费与异常复原语义与 `BoundSchnorrReplayGuard` 逐字节一致，数据库错误原样透传 `sqlite3.Error`。

### 并发认领与实例内原子消费

`ReplayGuard`、`RangeReplayGuard`、`RegionReplayGuard` 三个单条守卫、`SchnorrBatchReplayGuard`、`RangeBatchReplayGuard`、`RegionBatchReplayGuard` 三个批守卫，与 `BoundRegionReplayGuard`、`BoundRangeReplayGuard`、`BoundSchnorrReplayGuard`、`SingleKeyBoundReplayGuard`、`BoundConsistencyReplayGuard` 五个 Bound 批守卫以及 `MerkleConsistencyChainReplayGuard`、`MerkleConsistencyReplayGuard`、`MerkleInclusionReplayGuard`、`MerkleMultiReplayGuard`、`MerkleConsistencyBatchReplayGuard` 五个 Merkle 守卫的登记册都是线程安全的，且并发语义一致。每个 `session_id` 在一个实例内依次经历三种状态：**待用**（`bind_once` 登记后尚无校验在进行）、**校验中**（某个 `check` 已原子认领，正在执行可能耗时的证明/批验）、**已消费**（校验成功）。

- **实例内原子消费**：对同一待用 `session_id` 的并发 `check`，至多一个能原子认领成功并可能返回 `True`；其余调用看到该 id 已在校验中或已消费，一律返回 `False`。认领在任何证明验证（Schnorr 验签、区间/区域证明、Merkle 根与整批验证）之前完成，因此验证完成前不会消费 id。
- **短暂认领、无全局锁**：认领只是按 id 记录的登记册状态（每次只在极短临界区内用一个 `threading.Lock` 改写字典），锁在委托验证之前就已释放。一个标识的耗时验证**不会**持有阻塞其他标识的全局锁——不同 `session_id` 的 `check` 与 `bind_once` 可以全程并发，互不串行。
- **已消费或校验中均不可重绑**：`bind_once` 对待用、校验中、已消费三种状态的 id 都抛 `ValueError`。
- **成功后原子消费；失败即撤销**：只有全部校验通过才把 id 原子移入已消费。返回 `False`（竞争失败、摘要不符、过期、委托验证返回 `False` 等）、过期，或委托验证/`randbelow` 抛出异常（Bound 守卫透传其 `TypeError` / `ValueError` 等）时，认领都被撤销，id 恢复为待用并保留原绑定，因此稍后仍可成功一次；整个过程不产生 `KeyError`，也不改写任何输入。
- **实例隔离或共享存储**：无参构造时，待用/校验中/已消费状态只存在于单个守卫实例内，不同实例（即便同 id）完全独立、互不阻塞；传入同一 `SQLiteReplayStore`（同文件、同命名空间）的守卫实例则经由短事务与唯一认领 token 共享三种状态，跨实例、跨进程并在重启后保持一致，认领租约过期后只能由等值 `binding` 的 `check` 接管，不同守卫域（`zr/r/v1`、`zr/sbr/v1`、`zr/skbr/v1`、`zr/rbr/v1`、`zr/rgbr/v1`、`zr/rr/v1`、`zr/rg/v1`、`zr/brg/v1`、`zr/brr/v1`、`zr/bsr/v1`、`zr/skbbr/v1`、`zr/mccr/v1`、`zr/mcr/v1`、`zr/mir/v1`、`zr/mmr/v1`、`zr/mcbr/v1`）的行互不冲突。
- **字节级兼容**：并发改造不改变 `ReplayBinding` 的任何字节——各守卫既有域标签、`F`/`U`/`S`/`E` 成帧、叶字段与整数顺序、Merkle 根与期限编码逐字节不变，方法签名（单条 `bind_once(entry, session_id, *, expires_at=None)` / `check(entry, binding, *, now=None)`；批 `bind_once(entries, session_id, *, expires_at=None)` / `check(entries, binding, *, now=None, randbelow=...)`；Bound 批 `bind_once(batch, root, session_id, *, expires_at=None)` / `check(batch, root, binding, *, now=None, randbelow=...)`）与既有 `TypeError`/`ValueError` 边界保持不变，旧绑定与单线程行为完全兼容。

## 限制

`DEFAULT_PRIME` 是梅森素数而非安全素数，`2**127 - 2` 的因子分解不干净，因此这里没有可用的素数阶子群，应答按普通整数计算、不针对群阶取模；安全性只够做协议演示，不足以用于真实部署。区域判定只是朴素的坐标比较，不检查坐标是否经过承诺绑定；批量验证所用的随机线性组合与默认群一样仅供演示。Pedersen 承诺默认的 `h = g**2 mod prime` 带有公开陷门、破坏绑定性；其上的 Schnorr OR 区间证明与二维区域成员证明同样是演示级构造——区间上限 256 个整数、挑战来自 SHA-256 Fiat-Shamir 转录、群参数与默认 `h` 均未做生产级安全分析，不能用于真实部署。

## 测试

```bash
python3 -m unittest discover -s tests
```
