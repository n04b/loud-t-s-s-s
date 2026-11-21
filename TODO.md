# TODO

## MVP scope

The MVP covers one workflow: describe variables in one file, validate them, keep the values in git encrypted with per-environment keys, and export them to `.env` for running the app.

**Status:** implemented in Go: [cmd/loudtsss](cmd/loudtsss) and [internal/loudtsss](internal/loudtsss), with end-to-end tests (`go test ./...`).

### Decisions

- [x] **The config file is JSON**, not `.ts`: `pack`/`unpack` rewrite the file, which is only reliable for JSON. A JSON Schema generated from [types.ts](types.ts) provides IDE autocompletion; the TS types stay for the library.
- [x] **`environments` becomes a record in the MVP** (see [Types](#types)): the validator needs `protected` to know where plaintext secrets are forbidden. It is a breaking change, so it is done before the first release.
- [x] **No shared values.** Values live only in the blocks, one environment at a time; `value` exists only in the working file, and `values` is rejected in both files (open question: keep it for authoring and import, or drop it). This removes the question of keeping per-environment copies in sync.
- [x] **Symmetric keys only.** Asymmetric keys come later as a new block format (`enc:v2:`); `enc:v1:` stays readable.
- [x] **Storage: git only**, blocks inline in the committed file.

### In scope

- [x] Schema: the current `VarType` kinds plus `enum`; `value` (working file only), `required`/`allowEmpty` with `EnvCondition`, `sensitivity`, `exposure`, `description`, `example`.
- [x] `group`, `tags`, `aliases`, `deprecated` are accepted by the schema but have no runtime behavior (except the "`deprecated` together with `required` is an error" check).
- [x] Validator: every item in [Runtime checks](#runtime-checks) except `seed` and strict mode. Errors are loud: report all of them at once, each with the variable and the environment.
- [x] Encryption: AES-256-GCM, one block per environment, AAD with the environment name, `pending`/`encrypted` states.
- [x] Integrity: copies of `sensitivity` and `exposure` in each block, compared with the schema. The variable list is compared loosely: a variable missing from a block is not set there, an extra one is a warning (see [Integrity checks](#integrity-checks)).
- [x] A `version` counter in each block from the start, so rollback protection can be added later without changing the format.
- [x] CLI commands:
  - `keygen <env>`: generate an environment key;
  - `unpack <env>`: build the working file from the committed file;
  - `pack`: encrypt `pending` values, re-encrypt only the blocks that changed;
  - `check`: validate, no plaintext secrets in protected environments, the committed file is up to date (the same command runs in CI);
  - `export <env>`: write a `.env` file; also generate `.env.example`.
- [x] Keys are read from an environment variable or from a file outside the repository.
- [x] Git hook: pre-commit only, it runs `check` and rejects the commit if the working file is staged. It does not build the committed file itself; it fails and tells the user to run `pack`.

### If time permits

- [ ] `import` from an existing `.env` file.
- [ ] `rotate`. Until then rotation is manual: `unpack` with the old key, `pack` with the new one.

### After the MVP

- Asymmetric keys and signed blocks; rollback protection; `reference` values; generated values; `url`, `list` and `string` constraints; strict mode; the Docker image (init container); export to GitHub Actions secrets; storage backends other than git; interactive prompts; `aliases` behavior.

## Backlog

- [ ] In strict mode the fields `description`, `type`, `value`/`values`, `required`, `allowEmpty`, `sensitivity`, `exposure` are mandatory.
- [x] Add `value` `kind` concordance type check.
- [x] Different encryption keys for different environments 

## Runtime checks

Taking all decisions into account, the validator needs to check:
- [x] the JS type of the value matches `kind` (`number` → `int`/`float`/`port`, `boolean` → `bool`);
- [x] the value satisfies the type constraints (`min`, `max`, `pattern`, `enum` `values`, etc.);
- [x] keys in `values` and environments in `EnvCondition` are listed in `environments`;
- [x] `environments` has no duplicates;
- [x] the JSON has no duplicate variable keys;
- [x] `deprecated` together with `required` is an error;
- [ ] `seed` on a variable with `sensitivity: "secret"` is an error;
- [x] `sensitivity: "secret"` together with `exposure: "client"` is an error;
- [ ] in strict mode all mandatory fields are set.
- [x] all "secrets" (sensitive values) must be stored encrypted in the config, and decrypted at load time.

## Utility

- [ ] Import: extract variables and values from an existing `.env` file into the config.
- [ ] Export: unpack the config and decrypt secrets into a `.env` file.
- [ ] Export secrets to GitHub Actions secrets and other services.
- [ ] Generate encryption keys.
- [ ] Encrypt secrets in the config.
- [ ] Rotate keys: generate new keys (shared and per-environment) and re-encrypt the whole config with them.
- [ ] Optional: encrypt all values with a shared key before they are pushed to git (via a git hook). This is an extra layer on top of, not a replacement for, encrypting secrets with per-environment keys.
- [ ] Two distributions: a CLI utility and a Docker image.
  - [ ] The Docker image works as an init container: it pulls the latest config with encrypted secrets from git and unpacks/decrypts it; other containers depend on it and start only after it finishes.
  - [ ] Download config from alternative resources

## Encryption

> **Partly decided.** The architecture below is chosen; the open questions at the end are still being thought through.

### Committed file vs working file

- [ ] Two forms of the config:
  - **Committed file** (in git): the schema (variables keyed by name, metadata only, no values) plus one encrypted block per environment holding **all** values of that environment, public and secret.
  - **Working file** (in `.gitignore`): the unpacked form for one environment. Non-secret values are decrypted and placed into the schema; secret values stay in the block and are marked in the schema as `{ kind: "encrypted", state: "encrypted" }`.
- [ ] One block per environment, each encrypted with its own environment key:
  ```ts
  blob: {
    development: "enc:v1:<keyId>:<base64>",
    production:  "enc:v1:<keyId>:<base64>",
  }
  ```
  - Unpacking for an environment decrypts only that environment's block; the other blocks stay untouched.
  - AES-GCM over the whole block protects every value of the environment: values cannot be swapped, removed or replaced with plaintext without the environment key.
  - AAD of each block: `JSON.stringify(["loud-t-s-s-s/1", environment])`, so a block cannot be moved to another environment.
- [ ] A git hook builds the committed file from the working file. The working file never reaches git because it is ignored.
- [ ] The committed file must always be committed on its own: the hook rejects a commit that contains it together with other files.
- [ ] Re-encrypt a block only if its content changed (compare with the decrypted block from `HEAD`), so unchanged blocks keep the same ciphertext and do not show up in diffs.

### Adding a value by hand

- [ ] In the working file a new secret is written as
  ```ts
  { kind: "encrypted", state: "pending", valueToEncrypt: "token to encrypt" }
  ```
  On the next run the utility moves the value into the block and replaces the entry with `{ kind: "encrypted", state: "encrypted" }`.
- [ ] If the key for that environment is missing, the utility removes the plaintext value and fails with an error.
- [ ] `state` is required (no default), so a missing field is never treated as plaintext:
  ```ts
  type ValueEncrypted =
    | { kind: "encrypted"; state: "encrypted" }               // the value is in the block
    | { kind: "encrypted"; state: "pending"; value: string }; // encrypted on the next run
  ```

### Integrity checks

- [ ] Each block stores a copy of `sensitivity` and `exposure` for every variable that has a value in it; on load they are compared with the schema and a mismatch is an error. This stops editing a secret's `exposure`/`sensitivity` in the plaintext schema without the environment key.
- [ ] The variable list is **not** compared strictly, so adding or removing a variable does not need the keys of every environment:
  - a variable in the schema but not in a block is **not set** in that environment; this is not an integrity error, but `required` still applies, so a required variable fails validation until someone with that environment's key sets it;
  - a variable in a block but not in the schema is a **warning**: it is ignored on load and dropped on the next `pack` with that environment's key;
  - attack check: removing a secret from the schema and re-adding it as `public`/`client` is still caught, because the block keeps its value and the copies of `sensitivity`/`exposure`.
- [ ] Changing `sensitivity` or `exposure` of an existing variable still needs the keys of all environments: `pack` cannot tell which blocks hold a value for it without decrypting them.

### Open questions

- [ ] Asymmetric keys (preferred direction): encrypt with an environment's public key, decrypt only with its private key, so people can add secrets without being able to read them. Anyone with the public key can then forge values, so blocks must also be signed.
- [ ] How keys are identified (`keyId`), stored and delivered to the CLI and the init container.
- [ ] Rollback protection: store a `version` counter inside each block; decide where the trusted "latest version" comes from (`LOUD_T_S_S_S_MIN_VERSION` in the deployment, a pinned signed tag, state on a volume, `expiresAt`).
- [ ] Shared `value` of a secret: it is expanded per environment and encrypted into each environment's block; how to handle adding a new environment and keeping the copies in sync.
- [ ] Storage of the encrypted blocks is configurable; git is one option, not a requirement (see also "Download config from alternative resources" under Utility). **MVP: git only**, with blocks stored inline in the committed file; other backends and references come after the MVP. Think this through carefully:
  - the schema and the blocks can be stored separately: instead of an inline block, the config holds a reference to where the block lives, e.g.
    ```ts
    blob: {
      development: "enc:v1:<keyId>:<base64>",                                      // inline
      production:  { ref: "s3://bucket/app/production.enc", version: "<version or hash>" }, // stored elsewhere
    }
    ```
  - which backends: git, object storage (S3, GCS), a secret manager, plain HTTP;
  - git gives history, audit (who changed what), review and access control for free; other backends must provide them or the features are lost;
  - if the schema stays in git and the blocks live elsewhere, they can get out of sync: the schema must reference the exact block version it was built with;
  - where rollback protection and the trusted "latest version" come from for each backend;
  - how the hook, the "commit the file on its own" rule and the init container work when the blocks are not in git.

## Types

- [ ] Implement refrence values
```Typescript
export interface ValueReference {
kind: "reference";
provider: "vault" | "aws-secrets-manager" | "gcp-secret-manager" | "1password";
path: string; // secret location in the provider, e.g. "secret/data/db" or "op://vault/item"
field?: string; // field inside a multi-field secret; whole secret if omitted
version?: string; // pinned secret version; latest if omitted
}
```

- [ ] Implement generated values
```Typescript
export interface ValueGeneratedBase {
seed?: string; // same seed → same value
}

export interface RandomGen extends ValueGeneratedBase {
kind: "random";
length: number;
charset?: string; // characters to pick from
}

export interface UuidGen extends ValueGeneratedBase {
kind: "uuid";
}

export type ValueGenerated = RandomGen | UuidGen;
```

- [ ] Implement additional VarType kinds
```Typescript
type VarType =
  | { kind: "enum"; values: string[]; ignoreCase?: boolean } // case-sensitive by default
  | { kind: "url"; protocols?: string[] } // ["https", "postgres"]
  | { kind: "list"; of: ScalarKind; separator?: string }; // "a,b,c"
```

- [ ] Implement additional `string` VarType properties
```Typescript
export type VarType =
  | { kind: "string"; minLength?: number; maxLength?: number; pattern?: string; startsWith?: string } // pattern follows JS RegExp syntax, must match the whole value, "u" flag
```
- [ ] **MVP:** turn `environments` into a record of per-environment settings. `environments` says how and where; `blob` holds what (the inline block, or the pinned hash of a block stored elsewhere).
```Typescript
type EnvironmentSettings = {
  protected?: boolean;  // plaintext secrets forbidden, interactive prompts disabled
  storage?:             // where the encrypted block lives; inline in `blob` by default
    | { kind: "inline" }
    | { kind: "s3"; bucket: string; path: string };
  keyId?: string;       // default key for this environment
};

type Configuration<Environment extends string> = {
  version: 1;
  environments: Record<Environment, EnvironmentSettings>;
  variables: Record<string, Variable<Environment>>;
  blob?: Partial<Record<Environment,
    | string                    // inline: "enc:v1:<keyId>:<base64>"
    | { sha256: string }        // stored elsewhere: pinned hash of the exact block
  >>;
};
```
  - Duplicate environments become impossible, so the "`environments` has no duplicates" check is no longer needed.
  - `protected` tells the validator which environments must never have plaintext secrets.
  - Breaking change (`string[]` → record); the environment type becomes `keyof typeof environments`.
  - `storage` lives in the plaintext schema and can be redirected; the hash in `blob` stops an old or foreign block from being loaded.
