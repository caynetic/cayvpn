# Reviewed release artifact locks

CayVPN signs a release only when both architecture wheelhouses and the complete
native-component bundle match a version-specific lock in this directory.

The checksum files shipped beside downloaded artifacts are transport checks
only. They are created with those artifacts and are not an independent signing
authority.

For each stable version:

1. Build the two wheelhouses and native components on the connected builders.
2. Independently review every Python package name and version, every native
   source URL, version, and commit, and every resulting SHA-256 digest.
3. Create `release-locks/<version>.json` with schema version 1.
4. Review and commit that lock separately before moving the artifacts to the
   offline signer.
5. Run `scripts/build-release.sh` from that clean reviewed commit.

The required JSON keys are:

- `schema_version`: `1`
- `release_version`: the exact stable version
- `python_version`: `"3.12"`
- `requirements_sha256`: SHA-256 of the committed `requirements.lock`
- `wheelhouses.amd64.files` and `wheelhouses.arm64.files`: exact wheel
  filename-to-SHA-256 mappings
- `components.files`: the exact filename-to-SHA-256 mapping for the component
  bundle, including `SHA256SUMS`, notices, licenses, source archive, and all
  ten architecture-specific executables
- `components.build_metadata`: the exact reviewed contents of
  `BUILD-METADATA.json`

`scripts/validate-release-artifacts.py` enforces the schema, complete
inventories, digests, wheel metadata, architecture compatibility,
`requirements.lock`, and native source metadata. The offline release builder
also requires the version lock to be tracked by Git. A missing, uncommitted, or
mismatched lock blocks signing.

`2.0.0.json` records the reviewed dependencies for CayVPN 2.0.0: 39 pinned
Python packages for each architecture and the complete native-component
bundle, including corresponding source and license notices. The
validator checks the full wheel target (CPython 3.12, ABI, architecture,
and Ubuntu-compatible manylinux baseline), including the architecture that
the signing host does not execute.
