# Standalone installation

Build the production binary without fixture features, then initialize an absolute directory that does not already exist:

```sh
cargo +1.97.1 build --release -p kasumi-server --bin kasumid
target/release/kasumid init --mode standalone /var/lib/kasumi --tenant default
target/release/kasumid serve /var/lib/kasumi/kasumi.json
```

Initialization creates private directories and files, an exclusive installation identity, independent application/custody/Control/security wrapping keyrings, an Ed25519 issuer, TLS identities, and two client profiles. Listeners default to loopback: MCP on 9443, native data on 9444, and native administration on 9445. Change listener addresses and the MCP public URL in the generated configuration before starting if different ports are required.

The native endpoints require TLS 1.3, a client certificate issued by the installed CA, an exact installed server certificate pin, and a bearer token. `profiles/default.json` names the database credential; `profiles/control.json` names the separate Control administrator credential. Each token is bound to one explicit incarnation and purpose. A Control token cannot access the document API.

MCP accepts preconfigured local bearer tokens over TLS. Supply `Authorization: Bearer <token from profiles/default.token>` and the current MCP protocol headers. Its protected-resource metadata does not advertise an OAuth authorization server. An actual external OAuth deployment uses the separate `auth.source.kind = "external_oauth"` configuration variant.

Local credentials expire after one hour. Keep each client credential file renewed:

```sh
kasumid credential watch /var/lib/kasumi/profiles/default.json
kasumid credential watch /var/lib/kasumi/profiles/control.json
```

The watcher saves a renewal identity before dispatch and atomically replaces the token file after a verified native response. It retries uncertain transport outcomes with the same identity. A restarted watcher renews immediately. Clients must reread token files per request. Renewal does not extend any existing request's deadline. Stopping a watcher does not revoke its family; use the explicit revocation command.

Create a credential from a private Control profile and a JSON specification:

```sh
kasumid credential create /var/lib/kasumi/profiles/control.json /path/create-credential.json /var/lib/kasumi/profiles/application.json
kasumid credential status /var/lib/kasumi/profiles/control.json FAMILY_UUID
kasumid credential revoke /var/lib/kasumi/profiles/control.json FAMILY_UUID
```

The specification contains `family_id`, `principal`, `tenant`, `resource`, `scopes`, and `lifetime_seconds` (1–3600, default 3600). Use a new UUID for `family_id`. Read the exact resource from the generated tenant profile. Scopes are `read`, `write`, `admin`, and `audit`; current database RBAC still determines effective access. Reusing a family UUID with different specifications is rejected. Revocation is permanent and fences already-running requests at their subsequent authorization or response-release checks. Revoking the credential used for the operation can suppress its own acknowledgement; another Control credential can inspect the durable result.

# Operator maintenance

Stop the standalone server and drain clients before the following commands. They require exclusive installation and database ownership and record their operations in encrypted security storage:

```sh
kasumid maintenance rotate-wrapping-keys /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-signer /var/lib/kasumi/kasumi.json
kasumid maintenance rotate-certificates /var/lib/kasumi/kasumi.json
kasumid backup-operator-keys /var/lib/kasumi/kasumi.json /secure/offline/kasumi-keys
kasumid recover-administrator /var/lib/kasumi/kasumi.json /var/lib/kasumi/recovered
```

Wrapping-key rotation retains previous generations and rewraps installed catalogs. Signer rotation retains previous verification keys. Certificate rotation retains the CA, replaces server keys and certificates, commits the new local Control certificate pin, and updates profiles inside the installation's `profiles` directory. Update any copied/external profiles using the returned pins before reconnecting. A failed rotation leaves a durable started event and can be rerun while the server remains stopped.

Administrator recovery issues new private profiles for administrators in the current policies. It does not silently replace policy or change existing credential-family outcomes. It requires the installed encryption and signing keys. Run the renewal watcher for recovered profiles before their one-hour lifetime expires.

The `operator` directory contains plaintext wrapping keys, signing keys, and the CA private key. It is separate from ordinary encrypted data backups. The key-backup command creates an owner-only keys-only backup; store it separately on a trusted encrypted host. Retain all generations needed by completed data backups. These facilities protect data against storage disclosure while trusting the host running Kasumi; possession of the operator keys and stopped installation is administrative authority.
