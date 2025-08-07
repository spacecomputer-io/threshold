# SpaceComputer | Threshold 

**WARNING: This project is experimental and work-in-progress, DO NOT USE IN PRODUCTION.**

![Build & Test (Core)](https://github.com/spacecomputer-io/threshold/actions/workflows/core.yml/badge.svg?branch=main)
![Build & Test (CLI)](https://github.com/spacecomputer-io/threshold/actions/workflows/cli.yml/badge.svg?branch=main)

This repo contains the threshold cryptography (experimental) implementation for the SpaceComputer ecosystem.

It uses [github.com/poanetwork/threshold_crypto](https://github.com/poanetwork/threshold_crypto) as a base implementation and adds some additional functionality for managing keys and threshold committees.

## Crates

The following crates are included in this repo:

- [threshold](./threshold/README.md): The main crate that includes the core functionality / threshold cryptography implementation.
- [cli](./cli/README.md): A command line interface for generating keys and managing threshold committees.
- `threshold-peer` (WIP): A crate that includes the p2p functionality for running a threshold committee.

## Usage

See the [docs](https://docs.rs/threshold) for more information on how to use this crate.

## License

This project is licensed under the terms of the MIT License. See the [LICENSE](LICENSE) file for details.
