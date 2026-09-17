# Contributing to CEYO

CEYO is a proprietary protocol research project created and led by **Brian Covarrubias**.

The public repository is available for inspection, technical review, issue reporting, interoperability discussion, and controlled collaboration. Publication does **not** grant permission to reuse or commercialize the code or specifications beyond the rights expressly stated in `LICENSE`.

## Issues and technical review

Issues are welcome for:

- protocol ambiguities;
- specification errors;
- security findings;
- interoperability concerns;
- documentation defects;
- reproducible implementation bugs;
- conformance-test proposals.

Security vulnerabilities should be reported privately according to `SECURITY.md`.

## Code contributions

External code contributions are not accepted by default under an implied open-source inbound license.

Before submitting a pull request that contains substantive code, specification text, schemas, cryptographic design, or other potentially protectable material, obtain written confirmation that the contribution can be accepted under terms compatible with CEYO's proprietary licensing and IP model.

Pull requests submitted without prior agreement may be closed without merging.

## Protocol changes

Changes to normative protocol behavior require explicit review because they can affect interoperability and evidentiary meaning.

Examples include:

- artifact fields or signed scope;
- canonicalization rules;
- hashing or signature suites;
- key and trust-reference semantics;
- transparency-log behavior;
- verification outcomes;
- policy-binding semantics;
- version compatibility.

Large changes should begin as an issue describing:

1. the problem;
2. the proposed protocol change;
3. security and compatibility effects;
4. migration implications;
5. required test vectors or conformance updates.

## Design principles

Contributions and review should preserve:

- deterministic verification;
- model neutrality;
- explicit trust boundaries;
- minimal dependence on the originating system;
- constrained disclosure;
- protocol-version discipline;
- precise distinction between implemented and planned guarantees;
- clear evidentiary limitations.

## Authorship and project authority

CEYO was conceived and is directed by Brian Covarrubias. Accepted contributions do not alter project ownership, authorship, or licensing except through an explicit written agreement.

See `LICENSE` for the governing repository terms.
