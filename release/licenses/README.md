# Pinned upstream notice supplements

Some published crate archives omit their repository's license or NOTICE files.
`sources.json` pins the package name/version, published VCS commit, original URL
and SHA-256 of each supplemented file. Original bytes and line endings are kept.
The packager checks the published `.cargo_vcs_info.json` against the locked crate
archive and the supplement's exact revision before using these texts.

Kanaria 0.2.0's published repository URL is stale. Its exact published commit
`c994ccf06d179851a1c7c3285c3a408ccb6279ec` and LICENSE.txt remain available under
`sam-osamu/kanaria`; the manifest records both locations.

htmlescape 0.3.1 supplies an Apache-2.0 / MIT / MPL-2.0 declaration in Cargo.toml
and no repository license/NOTICE file. This distribution selects Apache-2.0,
retains the full license text and the exact published declaration, and binds
that supplement to the Cargo.lock crate checksum. No copyright holder or year
has been invented. All other package declarations remain unchanged.

These supplements are source data, not build instructions. Packaging uses only
the frozen copies and never downloads a changing branch or infers a license
from a project's current homepage. Nested license/notice files already supplied
in a crate are collected directly from its verified archive/source.
