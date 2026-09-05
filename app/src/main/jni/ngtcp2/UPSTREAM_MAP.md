# ngtcp2 vendoring map & upgrade guide (Android)

A **vendored, flattened** copy of [ngtcp2](https://github.com/ngtcp2/ngtcp2),
plus an Android crypto backend and a "brutal" congestion-control add-on.

- **Current version:** `1.25.0` (see `ngtcp2/version.h`)
- Upstream's `lib/`, `crypto/` and `lib/includes/` are flattened into this one
  directory. The only header search path needed is this directory itself.

The rule that makes upgrades mechanical:

> **Stock files carry `/* Copyright (c) <year> ngtcp2 contributors */`.
> Ours carry a `Mythaia` header.**
>
> Stock files are pristine upstream and are replaced wholesale on an upgrade.
> Ours are hand-maintained and must be preserved.

---

## 1. File classification

### Ours — never overwrite from upstream

| File | Role | Upstream equivalent |
|------|------|---------------------|
| `config.h`                 | Hand-written bionic config | `cmakeconfig.h.in` / `configure` output |
| `ngtcp2/version.h`         | Hand-written; bump on upgrade | `lib/includes/ngtcp2/version.h.in` |
| `ngtcp2_crypto_android.c`  | **The TLS/crypto backend** | a backend such as `crypto/quictls/quictls.c` |

### Stock — replace wholesale

Everything else: 47 `.c` and 52 `.h` at the top level, plus `ngtcp2/ngtcp2.h`
and `ngtcp2/ngtcp2_crypto.h`.

| Vendored path              | Upstream source path                     |
|----------------------------|------------------------------------------|
| `ngtcp2_*.c`, `ngtcp2_*.h` | `lib/ngtcp2_*.c`, `lib/ngtcp2_*.h`       |
| `shared.c`, `shared.h`     | `crypto/shared.c`, `crypto/shared.h`     |
| `ngtcp2/ngtcp2.h`          | `lib/includes/ngtcp2/ngtcp2.h`           |
| `ngtcp2/ngtcp2_crypto.h`   | `crypto/includes/ngtcp2/ngtcp2_crypto.h` |

> Top-level `ngtcp2_crypto.{c,h}` are the *lib-internal* crypto files
> (`lib/ngtcp2_crypto.{c,h}`), **not** the crypto helper. The helper is
> `shared.{c,h}` + `ngtcp2/ngtcp2_crypto.h`. Don't confuse them.

---

## 2. Why there is no symbol clash

Upstream splits the `libngtcp2_crypto` helper in two:

- **Backend-agnostic** glue → `crypto/shared.c`, vendored as `shared.c` (stock).
- **Backend-specific** primitives → one file per TLS stack. Ours is
  `ngtcp2_crypto_android.c`.

The two define disjoint symbol sets, so both compile into one target. The
backend owes exactly these 25 symbols — the archive-wide undefined set, which
is how to re-derive the list after an upgrade:

```sh
A=$(find app -name libngtcp2_static.a | head -1)
NM=$(ls "$ANDROID_NDK"/toolchains/llvm/prebuilt/*/bin/llvm-nm* | head -1)
"$NM" --defined-only  "$A" | awk '{print $NF}' | grep ^ngtcp2 | sort -u > /tmp/def
"$NM" --undefined-only "$A" | awk '{print $NF}' | sort -u > /tmp/und
comm -23 /tmp/und /tmp/def | grep ^ngtcp2_crypto_
```

If a future upstream adds a backend primitive, every stock backend gains it and
ours will not — it shows up in that list as a new undefined symbol.

---

## 3. Build wiring

`app/src/main/jni/CMakeLists.txt` builds this directory as its own
`ngtcp2_static` target with `HAVE_CONFIG_H` and a **private** include path.

That separation is not cosmetic: libyaml also ships a `config.h` and reaches it
with a quoted `#include "config.h"` that falls through to the include path. In a
single target the two would share that path and whichever directory came first
would win for both.

## 4. Android-specific config notes

`config.h` differs from a glibc build in three places, each with a reason:

- `HAVE_ENDIAN_H` / `HAVE_DECL_BE64TOH` are **set** — bionic has both.
- `HAVE_MEMSET_S` is **unset** — bionic has no C11 Annex K.
- `HAVE_EXPLICIT_BZERO` is **unset even though bionic has it**, because bionic
  declares it in `<strings.h>` and `ngtcp2_str.c` includes only `<string.h>`.
  Upstream then falls back to a `memset` reached through a volatile function
  pointer, which the optimiser may not elide. Same guarantee, no patch to a
  stock file.

---

## 5. Upgrade procedure

Set `UP` to an unpacked upstream release, then from this directory:

```sh
UP=/path/to/ngtcp2-<NEW_VERSION>
OURS="config.h ngtcp2_crypto_android.c"

# 1. Detect files upstream added, or ones it removed/renamed.
for f in "$UP"/lib/*.c "$UP"/lib/*.h; do b=$(basename "$f"); [ -e "$b" ] || echo "ADDED: $b"; done
for f in *.c *.h; do case " $OURS " in *" $f "*) continue;; esac
  [ -e "$UP/lib/$f" ] || [ -e "$UP/crypto/$f" ] || echo "ORPHAN: $f"; done

# 2. Copy every stock file.
for f in *.c *.h; do
  case " $OURS " in *" $f "*) continue;; esac
  case "$f" in shared.c|shared.h) src="$UP/crypto/$f";; *) src="$UP/lib/$f";; esac
  [ -e "$src" ] && cp "$src" "$f"
done
cp "$UP/lib/includes/ngtcp2/ngtcp2.h"           ngtcp2/ngtcp2.h
cp "$UP/crypto/includes/ngtcp2/ngtcp2_crypto.h" ngtcp2/ngtcp2_crypto.h
```

3. Bump `ngtcp2/version.h`. `NGTCP2_VERSION_NUM` is `0xMMmmpp`, matching
   `AC_INIT` in `$UP/configure.ac` — e.g. `1.26.0` → `0x011a00`.
4. Re-check `config.h` against the macros the new sources reference:
   `grep -rhoE 'HAVE_[A-Z0-9_]+|WORDS_BIGENDIAN|DEBUGBUILD' . | sort -u`
5. Re-derive the backend symbol list with the command in §2 and implement
   anything new.
6. Build for every ABI and run the crypto known-answer tests.
