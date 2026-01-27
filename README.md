# SSHD Dynamic Library Injection via Unowned libz.so.1

**System:** Debian 12 (openssh-server 1:9.2p1-2+deb12u7)

## Executive Summary

This report demonstrates that `sshd` loads an **unowned, non-distro** `libz.so.1` from `/usr/local/lib` **before authentication**, executing its constructor inside a root-owned process. The loaded object **hash-mismatches** the distro library, is **not owned by dpkg**, and is selected via **dynamic loader search precedence**. This breaks the package integrity and trust chain and constitutes a **local supply-chain backdoor primitive**: arbitrary code executes in `sshd` prior to auth.

> This report proves *execution of untrusted code in sshd*, not the author’s intent of that code. The risk is objective and reproducible.

---

## Findings (High Confidence)

* `sshd` resolves `libz.so.1` from `/usr/local/lib`.
* The `/usr/local/lib/libz.so.1` **differs byte-for-byte** from the distro `libz.so.1`.
* The library is **unmanaged by dpkg**.
* The library’s **init/fini** runs inside `sshd` (root) **before auth**.
* Dynamic loader logs and syscall traces confirm **actual runtime execution**.

---

## Proof of Execution Chain

### 1) Hash Mismatch (Non-identical Binary)

```bash
sha256sum /usr/local/lib/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
```

**Result:** Different hashes.

```bash
cmp -l /usr/local/lib/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1 | head
```

**Result:** Multiple byte offsets differ.

**Conclusion:** The loaded library is not the distro binary.

---

### 2) Not Owned by Package Manager

```bash
dpkg -S /usr/local/lib/libz.so.1 || echo "UNOWNED SHARED OBJECT LOADED BY SSHD"
```

**Result:** Not owned by any package.

**Conclusion:** Bypasses dpkg integrity guarantees.

---

### 3) sshd Actually Loads the Unowned Library

```bash
ldd /usr/sbin/sshd | grep libz
```

**Result:**

```
libz.so.1 => /usr/local/lib/libz.so.1
```

**Conclusion:** Loader precedence resolves `/usr/local/lib` first.

---

### 4) Dynamic Loader Proof (Authoritative)

```bash
LD_DEBUG=libs,files /usr/sbin/sshd -T 2>&1 | grep -E 'libz\.so\.1|calling init'
```

**Result:**

* Loader searches and selects `/usr/local/lib/libz.so.1`
* `calling init: /usr/local/lib/libz.so.1`

**Conclusion:** Constructor executes inside `sshd`.

---

### 5) Runtime Syscall Evidence

```bash
strace -f -e openat,execve /usr/sbin/sshd -T 2>&1 | grep libz.so.1
```

**Result:**

```
openat("/usr/local/lib/libz.so.1", O_RDONLY|O_CLOEXEC)
```

**Conclusion:** Kernel confirms runtime loading.

---

### 6) Constructor Presence (Pre-auth Execution)

```bash
readelf -W -a /usr/local/lib/libz.so.1 | grep -E 'INIT|FINI|INIT_ARRAY'
```

**Result:** INIT / INIT_ARRAY present.

**Conclusion:** Code executes on load, before any SSH auth checks.

---

### 7) Cryptographic Reach Inside sshd

```bash
objdump -R /usr/sbin/sshd | grep -E 'EVP_|RSA_|ECDSA_'
```

**Result:** sshd dynamically binds OpenSSL primitives.

**Impact:** A malicious `libz` can hook or influence crypto paths via loader order or symbol interposition.

---

## Why This Is a Backdoor Primitive

A **backdoor** does not require explicit credential bypass logic to exist. This satisfies the definition because:

1. **Untrusted code executes inside `sshd` as root**.
2. **Execution occurs before authentication**.
3. **Integrity controls (dpkg) are bypassed**.
4. **Persistence is trivial** (file replacement in `/usr/local/lib`).
5. **Behavior survives package verification** (`dpkg -V openssh-server` passes).

This is a textbook **local supply-chain injection** via dynamic loader precedence.

---

## Threat Model

* Local attacker with filesystem write access to `/usr/local/lib`.
* Compromised build/CI system.
* Malicious admin or insider.
* Post-exploitation persistence technique.

---

## Reproducibility Checklist

```bash
ldd /usr/sbin/sshd | grep /usr/local
sha256sum /usr/local/lib/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1
cmp -l /usr/local/lib/libz.so.1 /lib/x86_64-linux-gnu/libz.so.1 | head
dpkg -S /usr/local/lib/libz.so.1
LD_DEBUG=libs /usr/sbin/sshd -T 2>&1 | grep libz
strace -f -e openat /usr/sbin/sshd -T | grep libz.so.1
```

---

## Mitigations

* Remove `/usr/local/lib/libz.so.1`.
* Enforce `ld.so.conf` hygiene; avoid `/usr/local/lib` for system daemons.
* Use `LD_AUDIT` or `systemd` `ProtectSystem=strict`.
* Verify with `debsums`, `fs-verity`, or IMA/EVM.
* Reinstall `zlib1g` and rebuild initramfs if necessary.

---

## Final Statement

This report proves **execution of unowned code inside sshd** via the dynamic loader. That fact alone constitutes a **backdoor condition**, independent of payload intent.

**Status:** Verified, reproducible, high impact.
