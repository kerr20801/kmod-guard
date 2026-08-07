# kmod-guard

Audit and disable rarely-used kernel network protocol modules — SCTP, DCCP, TIPC, RDS.

**`blacklist` alone does not stop these from loading. This does, and proves it.**

```bash
curl -fsSLO https://raw.githubusercontent.com/kerr20801/kmod-guard/main/kmod-guard.sh
chmod +x kmod-guard.sh

./kmod-guard.sh              # audit only, no changes, safe anywhere
sudo ./kmod-guard.sh --apply # disable + verify
sudo ./kmod-guard.sh --revert
```

---

## The thing most people get wrong

Every few years a kernel bug lands in one of the obscure network protocols —
DCCP, TIPC, RDS, and now SCTP. The advice is always "you're fine, nobody uses
SCTP." Then people check:

```console
$ lsmod | grep sctp
$
```

Nothing loaded. Case closed, right?

No. Check what your distro shipped:

```console
$ grep sctp /lib/modules/$(uname -r)/modules.alias
alias net-pf-2-proto-132 sctp
alias net-pf-10-proto-132 sctp
```

That alias means **any unprivileged process can pull the module in on demand**,
just by asking for a socket:

```c
socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);   /* kernel autoloads sctp.ko */
```

No root. No config change. The module goes from "not loaded" to "loaded and
reachable" the moment someone touches it. So *not loaded* tells you nothing
about whether the code is reachable.

### And `blacklist` doesn't fix it

This is the second trap:

```
blacklist sctp        # ← does NOT prevent the autoload above
```

`blacklist` only stops the module being pulled in as a *dependency* of another
module, and stops some init-time loading. Alias-driven on-demand loading walks
straight past it. You need modprobe to actively refuse:

```
install sctp /bin/false
```

That replaces the load action with a command that fails. Now the alias resolves,
modprobe runs `/bin/false`, and the socket call returns `EPROTONOSUPPORT`.

Keep the `blacklist` lines too — belt and braces — but the `install` line is the
one doing the work.

---

## Why verify instead of trusting the config

Writing the file is not the same as being protected, and there are at least
three ways to write it and still be exposed:

- The module is **already resident**. `modprobe.d` governs *loading*; it does
  nothing about a module that's already in memory. If the refcount is non-zero
  you can't unload it either, and you're exposed until reboot.
- Your config **didn't actually get written**. Anything involving `sudo -S` and
  a heredoc in the same command is a classic way to silently write nothing while
  your script prints "OK".
- A **different file** in `modprobe.d` re-enables it, or you typo'd the name.

So the script's last step is to actually create a socket and see what happens.
That's the only check that answers the real question.

```
  sctp   loaded=no   refs=-   module=yes  autoload=yes  config=yes  blocked
  dccp   loaded=no   refs=-   module=yes  autoload=no   config=yes  blocked
```

Note `autoload=no` for DCCP on that host — no alias was shipped, so it was never
reachable by an unprivileged process in the first place. Worth knowing which of
your "protections" are real and which are just the distro's defaults.

---

## Careful: some people genuinely use these

SCTP is real infrastructure in telecom — SS7/SIGTRAN, Diameter, some 4G/5G core
functions. RDS shows up in Oracle RAC interconnects. TIPC in some cluster
software.

The script refuses to disable a module whose refcount is non-zero or that has
dependent modules loaded, and tells you instead of ploughing ahead. `--force`
overrides that if you're sure.

Before rolling this out, the check I'd trust: does the module have a non-zero
refcount, are there sockets, and has the box been up long enough for the answer
to mean something? A fleet with 30–110 days of uptime and zero SCTP sockets
anywhere is telling you clearly that nothing needs it.

---

## Gotcha that bit me

Do not use `ss` to check for SCTP sockets.

```console
$ ss -a | grep -i sctp     # ← this loads sctp_diag
```

`ss` autoloads the `*_diag` helper modules so it can inspect sockets. On a host
where SCTP was resident, my own "is anything using this?" command bumped the
refcount and pulled in another module. I was changing the thing I was measuring.

The script tests with a raw `socket()` call for exactly this reason, and disables
`sctp_diag` alongside `sctp`.

---

## What it checks

| Field | Meaning |
|---|---|
| `loaded` | Module currently in memory (`lsmod`) |
| `refs` | Refcount — non-zero means it can't be unloaded |
| `module` | The `.ko` exists on disk and *could* be loaded |
| `autoload` | An alias exists, so an unprivileged socket call can trigger it |
| `config` | An `install ... /bin/false` rule is present |
| verdict | **Result of actually attempting to create a socket** |

Exit codes: `0` all target modules unreachable, `1` at least one reachable,
`2` error.

---

## Scope and limits

- Mitigates by **removing reachability**, so it holds regardless of whether your
  kernel is patched for any specific CVE. It is not a substitute for patching.
- Cannot unload a module that's in use — that needs a reboot. The script says so
  rather than pretending.
- Reachability test needs `python3`. Without it the verdict is `unknown` and the
  script won't claim success it can't demonstrate.
- Tested on Ubuntu 20.04/22.04/24.04 (kernels 5.15 and 6.8). Should work on any
  distro using `modprobe.d`; RHEL family untested.

---

## Rolling it out

Ansible, roughly:

```yaml
- hosts: all
  become: true
  tasks:
    - copy: { src: kmod-guard.sh, dest: /usr/local/sbin/kmod-guard.sh, mode: '0755' }
    - command: /usr/local/sbin/kmod-guard.sh --apply
      register: r
      changed_when: "'wrote ' in r.stdout"
      failed_when: r.rc == 2
```

`--apply` is idempotent — rerunning rewrites the same file and re-verifies.

Two things worth doing when you sweep a fleet: check that hosts you *couldn't*
reach are actually decommissioned rather than silently skipped, and confirm the
config landed on hosts where `sudo` needs a password, since that's where
scripted writes tend to fail quietly.

---

## Licence

MIT
