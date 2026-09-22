# AGENTS.md

## Repository

Genesys' fork of OpenSIPS (`purecloudlabs/opensips`), tracking upstream
[`OpenSIPS/opensips`](https://github.com/OpenSIPS/opensips) with Genesys-specific
changes.

## Branches

Upstream has `master` and versioned branches (`3.6`, `4.0`, ...).
Our changes live on the matching `*-genesys` branch (`3.6-genesys`,
`4.0-genesys`, `master-genesys`, ...).

## Commits

Prefix every commit with the ticket number: `GCVCALLP-<NUMBER>: <summary>`. Ask
for a ticket number if you don't have one — don't invent it.

## Fixing bugs: check upstream first

Before writing a fix, check if it already exists upstream — in the matching
version branch **and** `master`. If it does, **backport it** instead of writing
your own. Avoid duplicated or divergent fixes. Only write an original fix if
the bug is unfixed upstream or is Genesys-specific.
