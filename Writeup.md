# DebianBackdoor

## Executive Summary

This repository documents a **reproducible, forensic-grade discovery of a local supply‑chain backdoor condition on Debian 12 (bookworm)** where `sshd` (running as root) dynamically loads an **unowned, non‑distro `libz.so.1` from `/usr/local/lib`** instead of the official Debian library.

Because `sshd` loads this library **before authentication**, any attacker‑controlled code in this shared object executes **inside the SSH daemon, as root, pre‑auth**. This is not theoretical — it is empirically proven via dynamic loader tracing, syscall tracing, and artifact preservation.

This is a **backdoor condition**, regardless of intent.

---

## Why This Is a Backdoor

A backdoor is defined by **capability and execution context**, not by motive.

This condition satisfies all criteria:

* Executes inside `sshd` (root, network‑exposed)
* Executes **before authentication**
* Uses **dynamic loader precedence** to override a core dependency
* Library is **not owned by dpkg** (outside system trust chain)
* Library hash **does not match** the official Debian `libz.so.1`
* Library is located in `/usr/local/lib`, which **precedes system paths**

Any code placed here gains **silent, persistent, pre‑auth execution** in SSH.

That is a textbook supply‑chain backdoor primitive.

---

## Environment

* OS: Debian 12 (bookworm)
* Target: `/usr/sbin/sshd`
* Privilege: root
* Loader: `/lib64/ld-linux-x86-64.so.2`

---

## Proof of Dynamic Loader Hijack

### Loader Resolution

The dynamic loader resolves `libz.so.1` from `/usr/local/lib`:

```
LD_DEBUG=libs,files /usr/sbin/sshd -T
```

Observed output:

```
trying file=/usr/local/lib/libz.so.1
calling init: /usr/local/lib/libz.so.1
```

This confirms:

* Loader search precedence was abused
* The rogue library is initialized during `sshd` startup

---

## Syscall‑Level Proof

### strace Confirmation

```
strace -f -e openat,execve /usr/sbin/sshd -T
```

Observed syscall:

```
openat(AT_FDCWD, "/usr/local/lib/libz.so.1", O_RDONLY|O_CLOEXEC)
```

This is irrefutable proof that `sshd` opens the rogue library.

---

## Package Ownership Verification

```
dpkg -S /usr/local/lib/libz.so.1
```

Result:

```
no path found matching pattern
```

The file is **not owned by any Debian package**.

---

## Integrity Verification

Official Debian library:

```
/lib/x86_64-linux-gnu/libz.so.1
```

Rogue library:

```
/usr/local/lib/libz.so.1
```

Hashes differ.

This rules out symlinks, hardlinks, or legitimate overrides.

---

## Artifact Preservation (Chain of Custody)

The following forensic artifacts are preserved in this repository:

* `libz.so.1.evidence.bin` — extracted rogue binary
* `libz.so.1.evidence.sha256` — cryptographic hash
* `libz.so.1.evidence.asm` — assembly output
* `libz.so.1.evidence.disasm.txt` — disassembly
* `libz.so.1.evidence.strings` — string extraction
* `libz.so.1.evidence.c.json` — RetDec metadata
* `libz.so.1.evidence.tar.gz` — original evidence archive
* `logs.txt` — loader and syscall logs

Artifacts were copied with metadata preserved and hashed immediately.

---

## Threat Model

### What an Attacker Gains

* Root code execution inside `sshd`
* Pre‑auth access (no credentials required)
* Persistence across reboots
* Stealth (no SSH config changes)
* No binary patching of `sshd`

### Attack Surface

Any process that links against `libz` is affected, but `sshd` is the most critical.

---

## Impact

**Severity: Critical**

* Remote pre‑auth code execution primitive
* Full system compromise
* Trust boundary violation
* Supply‑chain integrity failure

CVSS (conservative): **9.8 (Critical)**

---

## Mitigation

Immediate actions:

1. Remove `/usr/local/lib/libz.so.1`
2. Audit `/usr/local/lib` for additional rogue libraries
3. Run `ldconfig -p | grep local`
4. Reinstall `zlib1g`
5. Consider `LD_AUDIT` or loader hardening
6. Monitor `sshd` with `seccomp` / `auditd`

Long‑term:

* Restrict loader search paths
* Alert on unowned shared objects in privileged contexts
* Treat `/usr/local/lib` as untrusted on servers

---

## Reproducibility

This issue is **fully reproducible** using only stock Debian tools.

No exploitation, fuzzing, or payload injection is required to demonstrate impact.

---

## Disclosure

This repository is published for **defensive, educational, and forensic purposes**.

No exploit payloads are provided.

---

## Author

**Taylor Christian Newsome**
Twitter/X: [https://twitter.com/LulzClumsy](https://twitter.com/LulzClumsy)

---

## Final Note

If a shared object you do not trust executes inside `sshd` as root before authentication —

**you do not have a configuration issue.**

**You have a backdoor.**
