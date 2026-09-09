# Pre-Cargo harness failure

The first runner invocation exited 1 before creating its output directory or
starting Cargo. System Python lacked `hashlib.file_digest`, which the prior root
runner used under bundled Python 3.12. The tool-returned failure was:

```text
AttributeError: module 'hashlib' has no attribute 'file_digest'
```

`receipt.json` records that observed tool output; there was no on-disk compiler
or test log because neither process started. The exact failed runner is retained.
Its source-only successor used bounded streaming hashing and ran the authorized
cohort. Its actual system-Python executable/version/hash was recorded after the
run, without claiming that it used bundled Python. Source 5c2a3bf did not change.
