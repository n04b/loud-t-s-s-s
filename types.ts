// Types of the loudTSSS config, MVP design (see TODO.md, "MVP scope", and docs/how-it-works.html, "Types reference").
// Types planned after the MVP (url, list and string constraints, references, generated values, storage) are listed in TODO.md.

// Kinds allowed as list items; used by the "list" type after the MVP
export type ScalarKind = "string" | "int" | "float" | "url" | "email" | "host";

export type VarType =
  | { kind: "string" }
  | { kind: "int" | "float"; min?: number; max?: number }
  | { kind: "bool" }
  // "port" is an integer from 1 to 65535
  // "duration" is a Go duration string, e.g. "5s", "1h30m"
  | { kind: "port" | "duration" | "email" | "host" }
  // One of `values`; case-sensitive unless `ignoreCase` is true
  | { kind: "enum"; values: string[]; ignoreCase?: boolean };

// Restricts a rule to a set of environments: either an allowlist or a denylist, never both
export type EnvCondition<Environment extends string> =
  | { in: Environment[]; notIn?: never }
  | { notIn: Environment[]; in?: never };

// "public": may be shown anywhere; "internal": not a secret, but not for the public;
// "secret": credentials and tokens, never with exposure "client"
export type Sensitivity = "public" | "internal" | "secret";

// "server": server-side code only; "client": may end up in client code (forbidden for secrets); "build": build time
export type Exposure = "server" | "client" | "build";

export type Deprecation = { since?: string; replacedBy?: string; message?: string };

export type ValueEncryptedBase = {
  kind: "encrypted";
  algorithm?: "aes-256-gcm"; // the default and the only option
  keyId?: string; // key for this value, for key rotation; the environment's default key if omitted
};

// Marks a secret in the working file. `state` has no default, so a missing field is never taken for plaintext.
export type ValueEncrypted =
  | (ValueEncryptedBase & { state: "encrypted" }) // the value is in the environment's block; the entry carries nothing
  | (ValueEncryptedBase & { state: "pending"; valueToEncrypt: string }); // plaintext, moved into the block by the next `pack`

export type Value = string | number | boolean | ValueEncrypted;

// Definition of a single environment variable.
// In the committed file it carries metadata only; values live in the encrypted blocks.
export interface Variable<Environment extends string> {
  type: VarType;
  description?: string; // goes to .env.example and docs

  // Working file only: the value for the unpacked environment. `check` rejects it in the committed file.
  value?: Value;

  // OPEN QUESTION: per-environment overrides from the design before blocks. `check` rejects it in the committed
  // file and the working file holds one environment, so it has no place in the MVP files.
  // Keep it for authoring and import, or drop it.
  values?: Partial<Record<Environment, Value>>;

  // Whether the variable must have a value. `true` by default.
  // EnvCondition: required only in the matching environments, e.g. { in: ["production"] }
  required?: boolean | EnvCondition<Environment>;

  // Whether an empty string ("") counts as a value. `false` by default.
  // Same forms as `required`; e.g. { notIn: ["production"] } allows empty values outside production
  allowEmpty?: boolean | EnvCondition<Environment>;

  example?: string; // sample value for .env.example and docs, never a real secret

  // Copied into every block that holds a value for this variable and compared with the schema on load,
  // so they cannot be changed without that environment's key. Mandatory in strict mode.
  sensitivity?: Sensitivity;
  exposure?: Exposure;

  group?: string; // "database", "payments": for UI and docs, no runtime behavior
  tags?: string[]; // no runtime behavior
  aliases?: string[]; // old names after a rename; reading them at load time comes after the MVP
  deprecated?: Deprecation; // a deprecated variable cannot be `required`
}

// Settings of one environment: how and where. What it holds lives in its block.
export type EnvironmentSettings = {
  // Plaintext secrets are forbidden: in the working file a secret can only be written as `pending`.
  // Interactive prompts are disabled. `false` by default.
  protected?: boolean;
};

// One environment's values, encrypted with AES-256-GCM using that environment's key.
// AAD: JSON.stringify(["loud-t-s-s-s/1", environment]), so a block cannot be moved to another environment.
export type EncryptedBlock = `enc:v1:${string}:${string}`; // "enc:v1:<keyId>:<base64>"

// The committed file, loudtsss.json
export type Configuration<Environment extends string> = {
  version: 1;
  environments: Record<Environment, EnvironmentSettings>; // keyed by environment name
  variables: Record<string, Variable<Environment>>; // keyed by variable name

  // One block per environment, written by `pack`; never edit by hand
  blob?: Partial<Record<Environment, EncryptedBlock>>;
};

// Decrypted content of an EncryptedBlock. Illustrative: TODO.md fixes what goes in, not the field names.
export type BlockPayload = {
  version: number; // +1 each time the block changes; for rollback protection after the MVP
  values: Record<string, string | number | boolean>; // a variable missing here is not set in this environment
  meta: Record<string, { sensitivity?: Sensitivity; exposure?: Exposure }>; // for each variable in `values`
};

// The working file, loudtsss.local.json (gitignored): the config unpacked for one environment. Illustrative.
export type WorkingFile<Environment extends string> = {
  environment: Environment;
  variables: Record<string, Variable<Environment>>; // the schema with this environment's `value`
};
