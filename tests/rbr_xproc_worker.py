"""Cross-process worker for the RangeBatchReplayGuard SQLite lease tests.

The parent test drives the worker through a JSON specification file; the
worker deterministically regenerates the exact same real
:class:`zkregion.RangeBatchEntry` batch from public entry points
(:func:`zkregion.pedersen_commit` and :func:`zkregion.prove_range`) so the
scenario never depends on private store fields. Outcomes (``true`` /
``false`` / ``ValueError`` / ``RuntimeError`` / ``other``) are reported
through a JSON result file, and the parent additionally observes state
only through its own public ``bind_once`` / ``check`` calls.

Modes:

* ``bind``    — open the store and ``bind_once`` the batch to a session id;
* ``check``   — one normal ``check`` with an explicit ``now`` and a fixed
                lease-clock value;
* ``blocked`` — a check whose first ``randbelow`` call writes a gate file,
                blocks on a release file, then finishes verification while
                holding the claim (used to resume a stale lease owner);
* ``crash``   — a check that exits hard (``os._exit``) with no cleanup once
                it has claimed the id and entered verification;
* ``error``   — a check whose ``randbelow`` always raises ``RuntimeError``.
"""

import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zkregion import (  # noqa: E402
    RangeBatchEntry,
    RangeBatchReplayGuard,
    ReplayBinding,
    SQLiteReplayStore,
    pedersen_commit,
    prove_range,
)

PRIME_A = 104729
PRIME_B = 104723


def counter_randbelow(start=1):
    """The same deterministic LCG the test suite uses for honest proofs."""
    state = {"value": start}

    def randbelow(upper):
        state["value"] = (state["value"] * 1103515245 + 12345) % upper
        return state["value"]

    return randbelow


def make_entries():
    """Rebuild the shared three-entry batch deterministically and honestly."""
    specs = [
        (4, PRIME_A, 1001),
        (7, PRIME_A, 1002),
        (3, PRIME_B, 2001),
    ]
    entries = []
    for value, prime, blinding in specs:
        commitment, nonce = pedersen_commit(
            value, 0, 10, prime=prime, generator=3, blinding=blinding
        )
        proof = prove_range(
            commitment, value, nonce, context=b"batch",
            randbelow=counter_randbelow(),
        )
        entries.append(RangeBatchEntry(commitment, proof, b"batch"))
    return entries


def wait_for(path, timeout=30.0):
    """Block until ``path`` appears, keeping timing deterministic."""
    deadline = time.monotonic() + timeout
    while not os.path.exists(path):
        if time.monotonic() > deadline:
            raise RuntimeError("timed out waiting for release file")
        time.sleep(0.01)


def write_result(path, payload):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)


def open_store(spec):
    """Open the shared file with a fixed lease clock distinct per scenario."""
    clock_value = spec.get("clock_start")
    if clock_value is None:
        return SQLiteReplayStore(
            spec["db_path"], b"xproc",
            lease_seconds=int(spec.get("lease_seconds", 30)),
        )
    state = {"t": int(clock_value)}
    return SQLiteReplayStore(
        spec["db_path"], b"xproc",
        lease_seconds=int(spec.get("lease_seconds", 30)),
        clock=lambda: state["t"],
    )


def run_bind(spec):
    store = open_store(spec)
    try:
        RangeBatchReplayGuard(store=store).bind_once(
            make_entries(),
            spec["session_id"].encode(),
            expires_at=spec.get("expires_at"),
        )
        write_result(spec["result_file"], {"outcome": "ok"})
    except ValueError:
        write_result(spec["result_file"], {"outcome": "ValueError"})
    finally:
        store.close()


def run_check(spec):
    store = open_store(spec)
    mode = spec["mode"]
    entries = make_entries()
    binding = ReplayBinding(
        spec["session_id"].encode(),
        bytes.fromhex(spec["digest"]),
        spec.get("expires_at"),
    )
    gate_file = spec.get("gate_file")
    release_file = spec.get("release_file")
    randbelow = counter_randbelow()

    if mode in ("blocked", "crash"):
        # The gate file appears on the first randbelow call, i.e. after the
        # claim is taken and while verification is suspended; a crash worker
        # exits hard there without releasing anything, a blocked worker waits
        # for the release file and then continues the same LCG sequence.
        sequence = counter_randbelow()
        state = {"released": False}

        def gated_randbelow(upper):
            if not state["released"]:
                if gate_file is not None and not os.path.exists(gate_file):
                    with open(gate_file, "w", encoding="utf-8"):
                        pass
                if mode == "crash":
                    os._exit(7)
                wait_for(release_file)
                state["released"] = True
            return sequence(upper)

        randbelow = gated_randbelow
    elif mode == "error":
        def failing_randbelow(_upper):
            raise RuntimeError("randbelow failure")

        randbelow = failing_randbelow

    try:
        accepted = RangeBatchReplayGuard(store=store).check(
            entries, binding,
            now=spec.get("now"), randbelow=randbelow,
        )
        write_result(spec["result_file"], {"outcome": "true" if accepted else "false"})
    except RuntimeError:
        write_result(spec["result_file"], {"outcome": "RuntimeError"})
    except ValueError:
        write_result(spec["result_file"], {"outcome": "ValueError"})
    except BaseException as exc:  # diagnostic only; the test fails on it
        write_result(
            spec["result_file"], {"outcome": "other", "error": type(exc).__name__}
        )
    finally:
        store.close()


def main():
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        spec = json.load(handle)
    if spec["mode"] == "bind":
        run_bind(spec)
    else:
        run_check(spec)


if __name__ == "__main__":
    main()
