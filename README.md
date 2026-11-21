# loudTSSS

Typed environment config in one file: variable types, per-environment values, encrypted secrets and metadata. Secrets stay quiet, errors stay loud.

> **Status:** early design. The repo contains the TypeScript types ([types.ts](types.ts)) and an interactive explainer ([docs/how-it-works.html](docs/how-it-works.html)) that runs the planned workflow in the browser with real encryption. The validator, the loader and the CLI are not implemented yet. See the MVP scope in [TODO.md](TODO.md#mvp-scope).

> [!WARNING]
> **Before you start working with an encrypted config** (planned workflow, the utility is not implemented yet):
>
> 1. **Ignore the working file.** Add the working file (`loudtsss.local.json`) and every file the utility exports (e.g. `.env`) to `.gitignore`. They contain decrypted values and must never reach git.
> 2. **Install the git hook.** The pre-commit hook runs `check`: the committed file is up to date, holds no plaintext values, and the working file is not staged. Hooks run only locally, so the same check must also run in CI.
> 3. **Get the key for your environment only.** Store it outside the repository and never commit it. You do not need, and should not have, keys for environments you do not work with.
> 4. **Unpack before editing.** Unpack the config for your environment and edit only the working file; never edit the encrypted blocks by hand.
> 5. **Do not bypass the safeguards.** Never use `git commit --no-verify` or `git add -f` on the working file.

## How it works

The config is a JSON file that exists in two forms:

- **Committed file**, `loudtsss.json`, stored in git: the schema (variables with their metadata, without values) plus one encrypted block per environment. A block holds **all** values of its environment, public and secret, and is encrypted with that environment's key. Nobody can read, swap, remove or replace a value without the key.
- **Working file**, `loudtsss.local.json`, ignored by git: the config unpacked for one environment. Non-secret values are decrypted into place; secrets stay in the block and appear as `{ "kind": "encrypted", "state": "encrypted" }`.

The planned CLI commands:

| Command | What it does |
|---|---|
| `keygen <env>` | Generates the key of an environment. The key is stored outside the repository |
| `unpack <env>` | Decrypts the environment's block and writes the working file |
| `pack` | Validates the working file, encrypts `pending` values and re-encrypts only the blocks that changed, so unchanged blocks keep their ciphertext and stay out of diffs |
| `check` | Validates the committed file and every block it has a key for. Run by the pre-commit hook and in CI |
| `export <env>` | Decrypts an environment into `.env` and generates `.env.example` from the schema |

To see each step, and what catches a tampered block or a plaintext secret, open [docs/how-it-works.html](docs/how-it-works.html) in a browser.

## Example

The committed file, `loudtsss.json`:

```json
{
  "version": 1,
  "environments": {
    "development": {},
    "staging": { "protected": true },
    "production": { "protected": true }
  },
  "variables": {
    "PORT": {
      "type": { "kind": "port" },
      "sensitivity": "public",
      "exposure": "server",
      "example": "3000"
    },
    "REQUEST_TIMEOUT": {
      "description": "Timeout for outgoing HTTP requests",
      "type": { "kind": "duration" },
      "required": false
    },
    "LOG_LEVEL": {
      "type": { "kind": "enum", "values": ["debug", "info", "warn", "error"] },
      "sensitivity": "public",
      "exposure": "server"
    },
    "WORKERS": {
      "type": { "kind": "int", "min": 1, "max": 64 },
      "sensitivity": "internal",
      "exposure": "server",
      "required": { "in": ["production"] }
    },
    "SUPPORT_EMAIL": {
      "type": { "kind": "email" },
      "sensitivity": "public",
      "exposure": "client"
    },
    "DATABASE_URL": {
      "description": "Primary Postgres connection string",
      "type": { "kind": "string" },
      "sensitivity": "secret",
      "exposure": "server",
      "group": "database",
      "example": "postgres://localhost:5432/app"
    }
  },
  "blob": {
    "development": "enc:v1:development-k1:<base64>",
    "staging": "enc:v1:staging-k1:<base64>",
    "production": "enc:v1:production-k1:<base64>"
  }
}
```

The working file after `unpack staging`, with a new database password waiting for the next `pack` (abridged; the exact shape of the working file is not fixed yet):

```json
{
  "environment": "staging",
  "variables": {
    "PORT": { "value": 80, "type": { "kind": "port" }, "sensitivity": "public", "exposure": "server" },
    "LOG_LEVEL": { "value": "info", "type": { "kind": "enum", "values": ["debug", "info", "warn", "error"] } },
    "DATABASE_URL": {
      "value": { "kind": "encrypted", "state": "pending", "valueToEncrypt": "postgres://app:new-password@staging-db:5432/app" },
      "type": { "kind": "string" },
      "sensitivity": "secret",
      "exposure": "server"
    }
  }
}
```

## Configuration

| Field | Description |
|---|---|
| `version` | Schema version, currently `1` |
| `environments` | Every environment, keyed by name, with its [settings](#environment-settings): `{ "development": {}, "production": { "protected": true } }` |
| `variables` | Variable definitions keyed by variable name |
| `blob` | One encrypted block per environment: `{ "production": "enc:v1:<keyId>:<base64>", ... }`. Written by `pack`; never edit it by hand (see [Encryption](#encryption)) |

## Environment settings

| Field | Description |
|---|---|
| `protected` | Plaintext secrets are forbidden: in the working file a secret can only be written as `pending`, and interactive prompts are disabled. Default `false` |

## Variable

| Field | Description |
|---|---|
| `type` | Value type and its constraints (see [Types](#types)). Required |
| `description` | Human-readable description; goes to `.env.example` and docs |
| `value` | Working file only: the value for the unpacked environment (see [Values](#values)). `check` rejects it in the committed file |
| `values` | **Open question.** Per-environment overrides from the design before encrypted blocks. `check` rejects it in the committed file and the working file holds one environment, so it has no place in the MVP files |
| `required` | Whether the variable must have a value. Default `true` |
| `allowEmpty` | Whether `""` counts as a value. Default `false` |
| `example` | Sample value for `.env.example` and docs; never a real secret |
| `sensitivity` | `"public"`: may be shown anywhere; `"internal"`: not a secret, but not for the public; `"secret"`: credentials and tokens |
| `exposure` | Where the value may be used: `"server"`, `"client"` (may end up in client code; forbidden for secrets) or `"build"` |
| `group` | Grouping for UI and docs, e.g. `"database"`. No runtime behavior |
| `tags` | Free-form tags. No runtime behavior |
| `aliases` | Old names kept after a rename. Reading them at load time comes after the MVP |
| `deprecated` | `{ since?, replacedBy?, message? }`. A deprecated variable cannot be `required` |

`required` and `allowEmpty` accept either a boolean or an environment condition, an allowlist (`in`) or a denylist (`notIn`), never both:

```json
"required": { "in": ["production"] }
"allowEmpty": { "notIn": ["production"] }
```

The first makes the variable required only in production; the second allows an empty value everywhere except production.

## Types

| `kind` | Options | Value |
|---|---|---|
| `string` | — | any string |
| `int`, `float` | `min`, `max` | number |
| `bool` | — | `true` or `false` |
| `port` | — | integer from 1 to 65535 |
| `duration` | — | Go duration string, e.g. `"5s"`, `"1h30m"` |
| `email` | — | email address |
| `host` | — | host name |
| `enum` | `values` (required), `ignoreCase` (default `false`) | one of `values` |

The JSON type of a value must match its `kind`: a port is `80`, not `"80"`.

## Values

In the working file, `value` is either a literal (`string`, `number`, `boolean`) or an encrypted value, `{ "kind": "encrypted", "state", "algorithm"?, "keyId"? }`:

| Field | Description |
|---|---|
| `state` | `"encrypted"`: the value is in the environment's block, so the entry carries no value. `"pending"`: the value is still plaintext in `valueToEncrypt` and is moved into the block by the next `pack` |
| `valueToEncrypt` | Plaintext to encrypt; only with `state: "pending"`. If the environment's key is missing, `pack` deletes the plaintext and fails |
| `algorithm` | `"aes-256-gcm"`, the default and currently the only option |
| `keyId` | Key used for this value, for key rotation; the environment's default key if omitted |

`state` has no default, so an entry without it is never mistaken for plaintext.

In a `protected` environment a secret can only be written as `pending`; a plaintext literal fails `pack`.

## Encryption

Decided for the MVP:

- **One block per environment**, AES-256-GCM, encrypted with that environment's symmetric key. Unpacking an environment decrypts only its block.
- **Blocks are bound to their environment.** The AAD of each block is `["loud-t-s-s-s/1", <environment>]`, so a block moved to another environment fails to decrypt.
- **Each block keeps copies of `sensitivity` and `exposure`** for every variable it holds a value for. On load they are compared with the schema, and a mismatch is an error. This stops anyone without the key from turning a secret into `public` or `client` in the plaintext schema. Changing a variable's `sensitivity` or `exposure` therefore needs the keys of all environments.
- **The variable list is compared loosely.** Adding or removing a variable needs only your own key: a variable missing from a block is not set in that environment (but `required` still applies), and a variable left in a block after it was removed from the schema is a warning and is dropped on the next `pack` with that environment's key.
- **Each block has a version counter**, so rollback protection can be added later without changing the format.
- **Storage is git only**, blocks inline in the committed file.

Still open: asymmetric keys (anyone can add secrets, only key holders can read them), how keys are identified and delivered, and rollback protection. See [TODO.md](TODO.md#encryption).

## Planned

After the MVP; see [TODO.md](TODO.md):

- **More types:** `url` (`protocols`), `list` (`of`, `separator`), and `string` constraints (`minLength`, `maxLength`, `pattern`, `startsWith`).
- **Generated values:** `{ "kind": "random", "length", "charset"? }` and `{ "kind": "uuid" }`, with an optional `seed` for a deterministic result.
- **References:** `{ "kind": "reference", "provider", "path", "field"?, "version"? }` for values stored in an external secret manager (`vault`, `aws-secrets-manager`, `gcp-secret-manager`, `1password`).
- **Environment settings:** a default `keyId` and `storage` for blocks kept outside the file (e.g. S3).
- **Utility:** a Docker image (an init container that fetches and decrypts the config before other containers start), import from `.env`, key rotation, strict mode.
- **Docs:** [generating environment variables in Docker Compose](docs/docker-compose-env-generation.md).
