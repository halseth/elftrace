# Bitcoin Elftrace
Verify RISC-V binary execution in Bitcoin script.

## What is this?
`Bitcoin Elftrace` is a proof of concept tool used to trace the execution of
RISCV-32 binaries (ELFs), and and generate Bitcoin script that can be used to
verify this execution on-chain.

## How do I use it?
See the [compilation doc](./docs/compile.md) for an example of how to trace a
RISC-V binary.

## What is this useful for?
Using this you can use your favourite language to write arbitrary programs that
can be verified on Bitcoin. Paired with the "optimistic execution" smart
contracting paradigm, this opens up the possibility for Bitcoin smart contracts
to be arbitrary complex while still keeping the on-chain footprint low.

## What is optimistic execution?
The idea is to write your UTXO smart contracts in a way that gives any spender
the incentive to act honestly. If someone tries to spend the UTXO with an
improper execution of the contract, they can be punished efficiently using a
fraud proof.

## How can I use elftrace to write Bitcoin smart contracts?
`elftrace` only (currently) generates the scripts needed to validate the
program execution. You will need to wrap the program in a "MATT challenge"
style script in order to set up a proper smart contract. See
[mattlab](https://github.com/halseth/mattlab/blob/main/docs/challenge.md) for
an example.

## Are there any limitations?
This is very much in a POC stage. The compiler currently expects the compiled
program to take a single integer as input, and outputs a single integer. There
is also a few RISCV opcodes not yet implemented, I just wanted to build a few
more non-toy programs to test it on before making that effort.

## When can I use this on mainnet?
In order to use this on mainnet we would need to deploy a _covenant opcode_.
`elftrace` is based on the `OP_CHECKCONTRACTVERIFY` opcode proposed by
[MATT](https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2022-November/021182.html).

Come join us in getting covenants deployed on Bitcoin! 🤠

## What does this enable on Bitcoin?
Having a covenant deployed on bitcoin would enable us to use this to create
trustless two-way pegs, rollups, ZK verifiers... in general much more
flexible ways of handing custody of coins to an on-chain computer program.
