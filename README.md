# vandam - 0-day and RCE protection for Linux servers

vandam is a server security agent for Linux. It watches and enforces in the kernel through eBPF and
BPF LSM hooks, and vets HTTP requests and SQL queries from inside your applications through
lightweight runtime integrations (RASP) for PHP, Java, WordPress, Python, Node.js, Ruby and Perl.
It detects the services running on a host (web servers, databases, queues, containers, control
panels) and applies protection rules per service, so a web process that spawns a shell or runs an
executable from `/dev/shm` is stopped by behaviour, with or without a known signature.

Built on [vandam-core](https://github.com/kinnector/vandam-core), the Linux kernel telemetry and
enforcement engine.

## What's in this repository

| Path | What it is |
| --- | --- |
| `agent/` | `vandamd`, the daemon: kernel telemetry, heuristics, service discovery, file integrity, firewall, PTY session tracking, supply-chain monitoring, quarantine, and a local API on a Unix socket |
| `cli/` | `vandam`, the command-line client for the local API |
| `rules/` | the detection rules and service signatures, as JSON |
| `integrations/` | RASP integrations: `php` (extension), `jvm` (Java agent), `wordpress` (plugin), `python`, `node`, `ruby`, `perl` |

## How it works

```
[ kernel: eBPF / BPF LSM (vandam-core) ] --events--> [ vandamd ] <--vet request / query-- [ RASP in your app ]
                       ^                                   |
                       +------ deny rules, trust maps -----+--> local API (vandam CLI)
```

- **In the kernel**: process, file, network, memory and terminal events; BPF LSM hooks can refuse
  an operation before it happens, without a round trip to userspace, including container-boundary
  restrictions.
- **In the daemon**: process lineage per service, behaviour rules (a web or database process that
  spawns a shell, an executable run from `/dev/shm`), file integrity against a trusted baseline,
  outbound connection policy, quarantine of flagged files.
- **In the application**: the RASP integrations hand request buffers and SQL queries to the
  daemon over a Unix socket before they run, and abort the request when it is refused.

## Building

vandam builds on Linux against a sibling checkout of vandam-core:

```bash
git clone https://github.com/kinnector/vandam-core
git clone https://github.com/kinnector/vandam
cmake -S vandam-core -B vandam-core/build && cmake --build vandam-core/build -j
cd vandam && cargo build --release
```

`KINNECTOR_CORE_DIR` / `KINNECTOR_CORE_LIB_DIR` point the build at another vandam-core checkout or
build. Running `vandamd` needs root and a kernel with BPF LSM enabled (`bpf` in
`/sys/kernel/security/lsm`): it attaches enforcement hooks, so try it in a VM first.

## License

vandam is **source available**: free to use, copy, modify and run, including inside a business,
under the [PolyForm Shield License 1.0.0](./LICENSE.md). The one thing it does not allow is using
it to provide a product that competes with ours. The WordPress plugin
(`integrations/wordpress/`) is licensed under the GPL-2.0-or-later.

Contributions are welcome under the [Contributor License Agreement](./CLA.md).
Questions about the licence: <license@kinnector.dev>.
