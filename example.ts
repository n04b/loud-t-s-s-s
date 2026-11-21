import type { Configuration } from "./types";

type Env = "development" | "staging" | "production";

export const config: Configuration<Env> = {
  version: 1,
  environments: {
    development: {},
    staging: { protected: true },
    production: { protected: true },
  },
  variables: {
    PORT: {
      type: { kind: "port" },
      values: {
        development: 3000,
        staging: 80,
        production: 80
      }
    },
    LOG_LEVEL: {
      type: { kind: "enum", values: ["debug", "info", "warn", "error"] },
      sensitivity: "public",
      exposure: "server",
    },
  },
};
