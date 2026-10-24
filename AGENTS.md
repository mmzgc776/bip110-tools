# AGENTS.md — bip110-tools

Project conventions for agents working in this repo.

## Language

- Conversation with the owner is in **Spanish**.
- **Everything in the repo is in English**: comments, docstrings, CLI help
  (`help=`), runtime messages, errors, `README.md`, `CONTEXTO.md`,
  `PLAN_SWEEP.md`, `AGENTS.md`, new identifiers and commit messages.
- Labels printed to the screen are interface: if one is renamed (`blake2b only`,
  `both chains`, `BEFORE`/`AFTER`/`UNCONF`, `OK`/`NO MATCH`), update the code,
  `README.md` and any doc that quotes it in the same change.

## Hard rules

- **Never** print, paste or write seeds, passphrases, xprvs or macaroons to
  disk. Keys come from environment variables, never from argv.
- **Never** commit `bip110-*/`, xpubs, addresses or amounts. Those folders are
  in `.gitignore`.
- The tool **does not broadcast**: it signs and writes the hex. The owner runs
  `sendrawtransaction`.
- Do not add personal references to the repo: no host names, IPs, usernames,
  SSH aliases or employer names.

## Before committing

```bash
python3 lib_secp256k1.py selftest
python3 lib_unified_sighash.py selftest
python3 lib_aezeed.py selftest
python3 lib_tx.py selftest
python3 -m pyflakes *.py
for f in *.sh; do bash -n "$f"; done
```

All four must end in `ALL OK`.

## Publishing

- The published repo is `mmzgc776/bip110-tools`.
- `main` is the development history. `public` is the snapshot that gets
  published. It is published as a **single root commit** (no development
  history), so the repository shows one commit with the current tree.
- To update it: `git checkout public && git merge --squash main && git commit`
  and then replace the remote `main` ref with that tree (force). Some harnesses
  block `git push`; in that case use the Git Data API with the stored
  credentials, building the tree from `git ls-tree -r public` so the blobs match
  the local tree byte for byte.
- Never publish the development history: it contains early, unsanitized notes.

## Context that is not in the code

- Two LND instances (`lnd1`, `lnd2`), each with its own seed; the nodes are one
  SHA256 (Core) and one BLAKE2b (Knots). Instance names are just labels: the code
  does not assume them.
- The split is at block **961632** (`--split-height`).
- Derivation chain and aezeed format details: `CONTEXTO.md`.
