# MAX_MONEY at 20B: why, and how it compares

> Companion to the reasoning block in `src/amount.h`. Kept OUT of `doc/design/` on
> purpose: `**/DL-*` is gitignored in this public repo because those documents carry
> fleet topology and infrastructure detail. This one carries neither, and it is useful
> to a reviewer reading `amount.h`, so it lives here instead.

**Question asked (Casey, 2026-08-27):** is 20B truly the best number for Soqucoin, would
comparable top-10 chains do the same given similar emissions tokenomics, why do we have
MAX_MONEY at all, and is it related to the new emission schedule?

**Short answer:** the question contains a premise worth correcting before the comparison
means anything. **On Soqucoin, MAX_MONEY is not a supply cap and structurally cannot be
one.** It is a per-transaction ceiling. Soqucoin has **no supply cap at all** — that is a
deliberate, already-ratified property of the emission schedule, and it is a separate
decision from this constant.

Once that is straight, 20B is not really a choice. It is the largest round number under a
hard structural bound, and the only way past it is replacing the chainstate amount codec.

---

## 1. Why the constant exists at all

It is an artifact of **amount representation**, not of tokenomics.

Bitcoin-derived chains store amounts as `int64` satoshis (`typedef int64_t CAmount`).
Validation accumulators **add before they range-check** — `validation.cpp:1947` does
`nValueIn += ...` and only then calls `MoneyRange`. So a sum of two in-range values must not
overflow, or the check downstream is reading an already-wrapped number. `MAX_MONEY` is the
bound that makes that safe.

Chains that use big integers have no equivalent constant and no equivalent problem:

| Chain | Amount type | Has a MAX_MONEY-style constant? |
|---|---|---|
| Bitcoin, Dogecoin, Litecoin, **Soqucoin** | `int64` | **Yes** — required by the representation |
| Ethereum | `uint256` | No |
| Polkadot | `u128` | No |

So "what would a top-10 chain do here" only has an answer for the `int64` family. For ETH
and Polkadot the question does not arise.

---

## 2. Why it cannot be our supply cap

Three independent reasons, all in `src/amount.h`:

1. **The supply is unbounded.** After four halvings the schedule enters a perpetual tail of
   2,500 SOQ per block, roughly 1.31B SOQ a year, forever. No constant bounds a supply that
   grows without limit.
2. **Even the head supply does not fit.** `2 * MAX_MONEY <= INT64_MAX` caps the constant at
   ~46.1B coins. Head supply is **46.875B** — already past that line. Setting MAX_MONEY "to
   cover the supply" would reintroduce the exact signed-overflow bug it exists to prevent.
3. **The chainstate codec binds tighter still.** `CompressAmount`/`DecompressAmount` computes
   roughly `9n + 81` in a `uint64`, so any amount above **~20.49B coins** with a non-round
   decimal tail fails to round-trip and **silently corrupts in the UTXO database**. This was
   found by test during FC4 when 40B was tried: `serialization_invariance_tests` caught
   `40B * COIN - 1` decompressing to garbage. Both bounds are now `static_assert`ed.

So the ceiling is **20.49B, hard**. 20B is the largest round number beneath it, with 2.4%
headroom.

---

## 3. Is it related to the emission schedule?

**Only as a consequence, not as a design input.** The emission schedule (locked 2026-06-28,
bead `c61`, `DL-EMISSION-47B-LOCK`) is:

- `nInitialSubsidy` 100,000 SOQ on mainnet, halved four times at `nSubsidyHalvingInterval`
- head supply ~46.875B = 25B + 12.5B + 6.25B + 3.125B
- then a **perpetual tail of 2,500 SOQ/block**, ~1.31B/yr, described in the code as keeping
  SOQ "a living currency, not hard-capped"

The emission is what makes MAX_MONEY *unable* to be a supply cap. It did not set its value —
the codec did.

---

## 4. The comparison

⚠️ Two different things are being compared, so the table separates them.

| Chain | Supply cap | Emission today | Per-tx `MAX_MONEY` | Constant vs supply |
|---|---|---|---|---|
| **Bitcoin** | 21M | halving, tail → 0 | 21M | **=100%** (they coincide) |
| **Dogecoin** | **None** | fixed +5B/yr (~3.4%) | **10B** | **~6.4%** of ~155.3B |
| **Kaspa** | ~28.7B (29B in code) | annual halving, ~95% mined, →0 late 2026 | n/a (not this codebase family) | — |
| **Polkadot** | **2.1B, adopted 2026-03-14** | cut 53.6% (120M → 56.88M DOT/yr), ~3.11% | none (`u128`) | — |
| **Ethereum** | None | issuance/burn net variable | none (`uint256`) | — |
| **Soqucoin** | **None** | 47B head + 2,500/block tail (~1.31B/yr) | **20B** | **~42.7%** of 46.875B |

### The precedent that actually governs

**Dogecoin is the direct one — Soqucoin is based on that codebase.** Dogecoin Core carries:

```c
static const CAmount MAX_MONEY = 10000000000 * COIN;
```

with the comment, verbatim: *"Note that this constant is **not** the total money supply …
but rather a sanity check."*

Dogecoin has run for a decade with a per-transaction ceiling of 10B against a circulating
supply now around **155.3B** — a ceiling at roughly **6.4%** of supply, on a top-10 chain, at
scale, without it being a problem.

Soqucoin's 20B against a 46.875B head supply is **~42.7%** of supply: proportionally about
**6.7× more generous** than the chain we inherited the mechanism from.

> Historical note: Soqucoin's old comment claimed "maximum of 100B coins". That was inherited
> from Dogecoin's own comment, which conflates two numbers — 100B was Dogecoin's *original*
> 2013 cap (removed in Feb 2014), and 10B is the *transaction* maximum. The value here was
> never 100B, and 100B coins in shors is 1e19, which does not fit in an `int64` at all.

---

## 5. So is 20B the best number?

**For what it actually is — a per-transaction ceiling — yes, and the choice is close to
forced.**

- Anything above **20.49B** silently corrupts the UTXO set. That is not a tuning knob.
- 20B is the largest round number under it, keeping 2.4% margin rather than sitting on the
  boundary.
- **4.5×** the largest consolidation ever observed on this chain (the 4.45B pool
  consolidation).
- **80%** of first-epoch emission (25B).
- **4.6×** under the `int64` additive ceiling.
- Proportionally far more generous than Dogecoin's decade-proven equivalent.

**The one real consequence, and it should be stated plainly in operator docs:** no single
transaction may move more than 20B SOQ on either side. A larger treasury move or exchange
consolidation must be split across transactions. Given the largest real consolidation to date
was 4.45B, that is a 4.5× margin — but it is a genuine operational constraint, not a
theoretical one.

**Going higher is not a constant bump.** It requires replacing the amount codec, which is
chainstate-format surgery. And there is no tokenomics reason to want to, because this
constant is not the supply cap.

---

## 6. ⚠️ The question underneath the question

Comparing against Bitcoin, Kaspa and Polkadot suggests what is really being asked is not
about `MAX_MONEY` but about **whether Soqucoin should have a supply cap at all.**

That is a separate decision, already ratified, and it is a **hard fork to change after
genesis**:

- Soqucoin is currently **uncapped** by design — perpetual 2,500 SOQ/block, "a living
  currency, not hard-capped". Same philosophy as Dogecoin and Ethereum.
- **Polkadot moved the other way on 2026-03-14**, adopting a 2.1B hard cap and cutting
  emissions 53.6%. That is a top-10 chain abandoning perpetual inflation *this year*, and it
  is the strongest contrary datapoint available.
- Kaspa and Bitcoin are capped. Dogecoin and Ethereum are not.

There is no consensus in the industry, and both models are defensible.

**⛔ CORRECTION, added after checking rather than assuming: that question is NOT open. It was
decided deliberately, and it was decided with this comparison already in hand.**

Bead `c61` weighed the 47B Moderate model against a Full 99B alternative, explicitly including
the tail rate as a parameter (the ratified outcome is `nInitialSubsidy` 100,000,
`nSubsidyHalvingInterval` 250,000, four halvings, **2,500 tail**). It was decided against
written peer-comparison analyses, with a named stakeholder group, and locked on
**2026-06-28** — three and a half months *after* Polkadot adopted its hard cap on
**2026-03-14**.

So the strongest apparently-contrary datapoint in the table above pre-dates the decision and
was available to it. Uncapped-with-a-tail is a chosen monetary policy here, not an oversight,
and changing it is a hard fork after genesis.

The narrow claim this document does make stands on its own: `MAX_MONEY` is the wrong variable
to move if anyone ever wants to revisit supply policy. It is a per-transaction ceiling forced
by the amount codec, and it has nothing to say about total supply.

---

## Sources

External figures retrieved 2026-08-27. In-repo figures measured from `src/amount.h`,
`src/soqucoin.cpp` and `src/chainparams.cpp` at commit `28bbcf8d0`.

- Dogecoin Core `src/amount.h` — https://raw.githubusercontent.com/dogecoin/dogecoin/master/src/amount.h
- Dogecoin supply — https://www.kucoin.com/blog/en-how-many-dogecoins-are-there-in-2026-a-deep-dive-into-doge-supply
- Dogecoin cap history — https://dogecoin.com/dogepedia/faq/putting-a-cap-on-dogecoin/
- Kaspa tokenomics — https://wiki.kaspa.org/en/tokenomics
- Polkadot hard cap — https://phemex.com/blogs/polkadot-halving-tokenomics-explained
- Polkadot 2.1B cap — https://www.nasdaq.com/articles/polkadots-21-billion-hard-cap-explained-put-away-your-calculators
