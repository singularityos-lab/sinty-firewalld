# Contributing to sinty-firewalld

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-firewalld
cd sinty-firewalld
make build
make test
```

## Guidelines

- Keep changes additive and tested. sinty-firewalld runs as root and decides
  what the machine accepts from the network; prefer small, verifiable commits
  over large rewrites.
- Check a ruleset change on a real kernel: run the daemon in a network
  namespace and compare `sinty-firewalld -show` with `nft list ruleset`.
- Match the surrounding style. Comments explain WHY, not WHAT.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-only.
