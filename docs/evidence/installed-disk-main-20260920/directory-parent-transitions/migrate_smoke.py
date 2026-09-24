from pathlib import Path
r=Path('/Users/mtakemiya/dev/kasumi');p=r/'target/installed-disk-validation/directory-parent-transitions'
for rel in ('scripts/small_native_smoke.py','scripts/validation/small-native-smoke.md'):
 for side in ('base','proposed'):
  q=p/side/rel;q.parent.mkdir(parents=True,exist_ok=True);q.write_bytes((r/rel).read_bytes())
q=p/'proposed/scripts/small_native_smoke.py';s=q.read_text()
s=s.replace('        private_write(provenance / "Cargo.lock", lock)','''        private_write(provenance / "Cargo.lock", lock)
        with self.args.directory_policy.open("rb") as source:
            directory_policy_bytes = source.read(4097)
        require(len(directory_policy_bytes) <= 4096, "directory policy exceeds input bound")
        directory_policy = json.loads(directory_policy_bytes)
        require(isinstance(directory_policy, dict)
                and set(directory_policy) == {"extent_bytes", "max_entries"}
                and all(type(value) is int and value > 0 for value in directory_policy.values())
                and directory_policy["extent_bytes"] <= (1 << 63) - 1
                and directory_policy["max_entries"] <= (1 << 64) - 1,
                "invalid explicit directory policy")
        self.directory_policy_file = provenance / "directory-policy.json"
        private_write(self.directory_policy_file, directory_policy_bytes)
        self.record["directory_policy"] = {"file": str(self.directory_policy_file),
                                           "sha256": sha256(self.directory_policy_file),
                                           "policy": directory_policy}''')
s=s.replace('installation, "--tenant", "capacity-smoke"]','installation, "--directory-policy", self.directory_policy_file, "--tenant", "capacity-smoke"]')
s=s.replace('        certificate = Path(config["mcp"]["tls"]["certificate"]).read_text()','''        require(config["persistent_disk"]["directory_policy"] == self.record["directory_policy"]["policy"],
                "init changed the supplied directory admission policy")
        certificate = Path(config["mcp"]["tls"]["certificate"]).read_text()''')
s=s.replace('    parser.add_argument("--source", required=True)','    parser.add_argument("--directory-policy", type=Path, required=True)\n    parser.add_argument("--source", required=True)')
s=s.replace('    args.build_evidence = args.build_evidence.resolve(strict=True)','    args.build_evidence = args.build_evidence.resolve(strict=True)\n    args.directory_policy = args.directory_policy.resolve(strict=True)')
q.write_text(s)
q=p/'proposed/scripts/validation/small-native-smoke.md';s=q.read_text();a=s.index('For the existing failed `3a8d512`');b=s.index('\nThe description must match',a)
s=s[:a]+'''Provide `--directory-policy` pointing at the explicitly qualified directory policy
for the filesystem used by this diagnostic. Its two positive integer fields are
`extent_bytes` and `max_entries`; this runner supplies no production defaults and
does not establish filesystem qualification. It retains the exact input bytes and
hash and requires the generated installation to contain the same policy. Use
only binaries built from the current required-policy API; historical checkpoints
remain historical evidence and are not accepted through a compatibility path.

```sh
python3 /opt/kasumi-tools/small_native_smoke.py \\
  --binaries "$RELEASE_BINARIES" \\
  --build-evidence "$BUILD_EVIDENCE" \\
  --directory-policy /etc/kasumi/directory-policy.json \\
  --source "$RELEASE_COMMIT" \\
  --repository "$SOURCE_REPOSITORY" \\
  --output "$NEW_EVIDENCE_DIRECTORY" \\
  --execution-description 'Native Linux in the recorded isolated validation environment; outbound networking disabled'
```
'''+s[b:];q.write_text(s)
