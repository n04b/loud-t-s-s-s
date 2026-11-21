package loudtsss

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const initialConfig = `{
  "version": 1,
  "environments": {
    "development": {},
    "staging": { "protected": true },
    "production": { "protected": true }
  },
  "variables": {
    "PORT": { "type": { "kind": "port" }, "sensitivity": "public", "exposure": "server", "example": "3000" },
    "LOG_LEVEL": { "type": { "kind": "enum", "values": ["debug", "info", "warn", "error"] }, "sensitivity": "public", "exposure": "server", "required": false },
    "DATABASE_URL": { "description": "Primary Postgres connection string", "type": { "kind": "string" }, "sensitivity": "secret", "exposure": "server" },
    "API_TOKEN": { "type": { "kind": "string" }, "sensitivity": "secret", "exposure": "server", "required": { "in": ["production"] } }
  }
}
`

type sandbox struct {
	t    *testing.T
	dir  string
	keys string
	vars map[string]string
}

func newSandbox(t *testing.T) *sandbox {
	t.Helper()
	s := &sandbox{t: t, dir: t.TempDir(), keys: filepath.Join(t.TempDir(), "keys"), vars: map[string]string{}}
	s.write("loudtsss.json", initialConfig)
	return s
}

func (s *sandbox) path(name string) string { return filepath.Join(s.dir, name) }

func (s *sandbox) write(name, body string) {
	s.t.Helper()
	if err := os.WriteFile(s.path(name), []byte(body), 0o644); err != nil {
		s.t.Fatal(err)
	}
}

func (s *sandbox) read(name string) string {
	s.t.Helper()
	b, err := os.ReadFile(s.path(name))
	if err != nil {
		s.t.Fatal(err)
	}
	return string(b)
}

func (s *sandbox) run(args ...string) (int, string, string) {
	var out, errw bytes.Buffer
	args = append(args, "--keys-dir", s.keys)
	code := Main(args, &out, &errw, func(k string) string { return s.vars[k] }, s.dir)
	return code, out.String(), errw.String()
}

func (s *sandbox) ok(args ...string) string {
	s.t.Helper()
	code, out, errw := s.run(args...)
	if code != 0 {
		s.t.Fatalf("loudtsss %s: exit %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, out, errw)
	}
	return out + errw
}

// fails runs a command that must exit 1 and print every wanted fragment.
func (s *sandbox) fails(want []string, args ...string) string {
	s.t.Helper()
	code, out, errw := s.run(args...)
	if code != 1 {
		s.t.Fatalf("loudtsss %s: exit %d, want 1\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), code, out, errw)
	}
	for _, w := range want {
		if !strings.Contains(errw, w) {
			s.t.Fatalf("loudtsss %s: stderr lacks %q\nstderr:\n%s", strings.Join(args, " "), w, errw)
		}
	}
	return errw
}

// setValue edits one value in the working file, as a user would.
func (s *sandbox) setValue(name, raw string) {
	s.t.Helper()
	s.editWorking(func(wf *WorkingFile) {
		v, _ := wf.Variables.Get(name)
		v.Value = json.RawMessage(raw)
		wf.Variables.Set(name, v)
	})
}

func (s *sandbox) editWorking(fn func(*WorkingFile)) {
	s.t.Helper()
	var wf WorkingFile
	if err := json.Unmarshal([]byte(s.read("loudtsss.local.json")), &wf); err != nil {
		s.t.Fatal(err)
	}
	fn(&wf)
	b, err := marshalFile(&wf)
	if err != nil {
		s.t.Fatal(err)
	}
	s.write("loudtsss.local.json", string(b))
}

func (s *sandbox) editConfig(fn func(*Config)) {
	s.t.Helper()
	var c Config
	if err := decodeStrict([]byte(s.read("loudtsss.json")), &c); err != nil {
		s.t.Fatal(err)
	}
	fn(&c)
	b, err := marshalFile(c)
	if err != nil {
		s.t.Fatal(err)
	}
	s.write("loudtsss.json", string(b))
}

func (s *sandbox) keyFile(env string) string {
	s.t.Helper()
	m, _ := filepath.Glob(filepath.Join(s.keys, env+"-*.key"))
	if len(m) != 1 {
		s.t.Fatalf("want one key file for %s, got %v", env, m)
	}
	return m[0]
}

// filled returns a sandbox with keys and valid values in every environment.
func filled(t *testing.T) *sandbox {
	s := newSandbox(t)
	for _, e := range []string{"development", "staging", "production"} {
		s.ok("keygen", e)
	}
	s.ok("unpack", "development")
	s.setValue("PORT", "3000")
	s.setValue("LOG_LEVEL", `"debug"`)
	s.setValue("DATABASE_URL", `"postgres://localhost:5432/app"`) // plaintext is fine: development is not protected
	s.ok("pack")
	s.ok("unpack", "staging")
	s.setValue("PORT", "80")
	s.setValue("DATABASE_URL", `{"kind":"encrypted","state":"pending","valueToEncrypt":"postgres://app:s7Qe@staging-db:5432/app"}`)
	s.ok("pack")
	s.ok("unpack", "production")
	s.setValue("PORT", "80")
	s.setValue("LOG_LEVEL", `"warn"`)
	s.setValue("DATABASE_URL", `{"kind":"encrypted","state":"pending","valueToEncrypt":"postgres://app:Xk29&q=1@prod-db:5432/app"}`)
	s.setValue("API_TOKEN", `{"kind":"encrypted","state":"pending","valueToEncrypt":"tok_prod_9c41d2e8"}`)
	s.ok("pack")
	return s
}

func TestWorkflow(t *testing.T) {
	s := newSandbox(t)
	for _, e := range []string{"development", "staging", "production"} {
		out := s.ok("keygen", e)
		if !strings.Contains(out, "added an empty "+e+" block") {
			t.Fatalf("keygen output: %s", out)
		}
		info, err := os.Stat(s.keyFile(e))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("key file mode: %v %v", info.Mode(), err)
		}
	}
	// Empty blocks: every required variable is reported, all at once.
	s.fails([]string{"development: PORT: required but not set", "production: API_TOKEN: required but not set", "check failed"}, "check")

	s = filled(t)
	out := s.ok("check", "--all-keys")
	if !strings.Contains(out, "production: block v2 decrypted") {
		t.Fatalf("check output: %s", out)
	}
	committed := s.read("loudtsss.json")
	for _, secret := range []string{"postgres://", "tok_prod", `"value"`} {
		if strings.Contains(committed, secret) {
			t.Fatalf("committed file leaks %q:\n%s", secret, committed)
		}
	}
	working := s.read("loudtsss.local.json")
	if strings.Contains(working, "Xk29") || !strings.Contains(working, `"state": "encrypted"`) {
		t.Fatalf("working file after pack should hold no plaintext secret:\n%s", working)
	}

	// Nothing changed: the committed file stays byte-for-byte the same.
	before := s.read("loudtsss.json")
	if out := s.ok("pack"); !strings.Contains(out, "nothing changed") {
		t.Fatalf("pack output: %s", out)
	}
	if s.read("loudtsss.json") != before {
		t.Fatal("pack without changes rewrote loudtsss.json")
	}

	// A change re-encrypts only its own block.
	s.setValue("LOG_LEVEL", `"error"`)
	out = s.ok("pack")
	if !strings.Contains(out, "production: re-encrypted, v2 -> v3") || !strings.Contains(out, "staging: unchanged") {
		t.Fatalf("pack output: %s", out)
	}

	s.ok("export", "production", "-o", ".env")
	env := s.read(".env")
	for _, w := range []string{"PORT=80", "LOG_LEVEL=error", `DATABASE_URL="postgres://app:Xk29&q=1@prod-db:5432/app"`, "API_TOKEN=tok_prod_9c41d2e8"} {
		if !strings.Contains(env, w) {
			t.Fatalf(".env lacks %q:\n%s", w, env)
		}
	}
	if info, _ := os.Stat(s.path(".env")); info.Mode().Perm() != 0o600 {
		t.Fatalf(".env mode %v", info.Mode().Perm())
	}
	if ex := s.read(".env.example"); !strings.Contains(ex, "PORT=3000") || !strings.Contains(ex, "one of debug | info | warn | error") {
		t.Fatalf(".env.example:\n%s", ex)
	}
	code, stdout, _ := s.run("export", "development", "-o", "-", "--example", "")
	if code != 0 || !strings.Contains(stdout, "DATABASE_URL=postgres://localhost:5432/app") || !strings.Contains(stdout, "# API_TOKEN is not set in development") {
		t.Fatalf("export to stdout: %d\n%s", code, stdout)
	}
}

func TestTamperingIsCaught(t *testing.T) {
	t.Run("flipped byte", func(t *testing.T) {
		s := filled(t)
		s.editConfig(func(c *Config) {
			b, _ := c.Blob.Get("production")
			i := len(b) - 10
			r := byte('A')
			if b[i] == 'A' {
				r = 'B'
			}
			c.Blob.Set("production", b[:i]+string(r)+b[i+1:])
		})
		s.fails([]string{"production: AES-GCM authentication failed"}, "check")
	})
	t.Run("blocks swapped between environments", func(t *testing.T) {
		s := filled(t)
		s.editConfig(func(c *Config) {
			a, _ := c.Blob.Get("staging")
			b, _ := c.Blob.Get("production")
			c.Blob.Set("staging", b)
			c.Blob.Set("production", a)
		})
		// The key ids no longer match the environments' keys, and even with the right key the AAD would fail.
		s.fails([]string{"staging:", "production:"}, "check")
	})
	t.Run("block moved with the matching key", func(t *testing.T) {
		s := filled(t)
		// Give production the staging key under its own name: only the AAD stops the moved block.
		k, _ := os.ReadFile(s.keyFile("staging"))
		s.vars["LOUD_T_S_S_S_KEY_PRODUCTION"] = string(k)
		s.editConfig(func(c *Config) {
			b, _ := c.Blob.Get("staging")
			c.Blob.Set("production", b)
		})
		s.fails([]string{"production: AES-GCM authentication failed"}, "check")
	})
	t.Run("secret made public in the schema", func(t *testing.T) {
		s := filled(t)
		s.editConfig(func(c *Config) {
			v, _ := c.Variables.Get("DATABASE_URL")
			v.Sensitivity = "public"
			c.Variables.Set("DATABASE_URL", v)
		})
		s.fails([]string{`development: DATABASE_URL.sensitivity is "public" in the schema but "secret" in the block`}, "check")
		s.fails([]string{"DATABASE_URL.sensitivity"}, "unpack", "staging", "--force")
	})
	t.Run("plaintext value in the committed file", func(t *testing.T) {
		s := filled(t)
		s.editConfig(func(c *Config) {
			v, _ := c.Variables.Get("API_TOKEN")
			v.Value = json.RawMessage(`"tok_prod_9c41d2e8"`)
			c.Variables.Set("API_TOKEN", v)
		})
		s.fails([]string{`API_TOKEN: loudtsss.json holds a plaintext "value"`}, "check")
	})
}

func TestLoudErrors(t *testing.T) {
	t.Run("unknown field", func(t *testing.T) {
		s := newSandbox(t)
		s.write("loudtsss.json", strings.Replace(initialConfig, `"required": false`, `"requird": false`, 1))
		s.fails([]string{`unknown field "requird"`}, "check")
	})
	t.Run("duplicate variable", func(t *testing.T) {
		s := newSandbox(t)
		s.write("loudtsss.json", strings.Replace(initialConfig, `"LOG_LEVEL"`, `"PORT"`, 1))
		s.fails([]string{`duplicate key "PORT"`}, "check")
	})
	t.Run("schema rules", func(t *testing.T) {
		s := newSandbox(t)
		s.editConfig(func(c *Config) {
			v, _ := c.Variables.Get("DATABASE_URL")
			v.Exposure = "client"
			v.Required = &Cond{hasIn: true, In: []string{"prod"}}
			c.Variables.Set("DATABASE_URL", v)
			c.Variables.Set("RATE", Variable{Type: VarType{Kind: "port", Values: []string{"x"}}})
		})
		s.fails([]string{`a secret cannot have exposure "client"`, `unknown environment "prod"`, `kind "port" has no option "values"`}, "check")
	})
	t.Run("invalid value leaves the committed file alone", func(t *testing.T) {
		s := filled(t)
		before := s.read("loudtsss.json")
		s.setValue("PORT", "70000")
		s.setValue("LOG_LEVEL", `"verbose"`)
		s.fails([]string{"production: PORT: port 70000 is outside 1–65535", `"verbose" is not one of debug | info | warn | error`, "loudtsss.json not changed"}, "pack")
		if s.read("loudtsss.json") != before {
			t.Fatal("failed pack changed loudtsss.json")
		}
	})
	t.Run("plaintext secret in a protected environment", func(t *testing.T) {
		s := filled(t)
		s.setValue("API_TOKEN", `"tok_plain"`)
		s.fails([]string{"production: API_TOKEN is a secret written in plaintext in a protected environment"}, "pack")
	})
	t.Run("missing state", func(t *testing.T) {
		s := filled(t)
		s.setValue("API_TOKEN", `{"kind":"encrypted"}`)
		s.fails([]string{`"state" is required`}, "pack")
	})
	t.Run("unpack keeps unpacked changes", func(t *testing.T) {
		s := filled(t)
		s.setValue("PORT", "81")
		s.fails([]string{"has changes for production that are not packed"}, "unpack", "staging")
		s.ok("unpack", "staging", "--force")
	})
	t.Run("keygen twice", func(t *testing.T) {
		s := filled(t)
		s.fails([]string{"already has a block encrypted with key production-"}, "keygen", "production")
	})
	t.Run("key file readable by others", func(t *testing.T) {
		s := filled(t)
		os.Chmod(s.keyFile("production"), 0o644)
		s.fails([]string{"is readable by other users"}, "unpack", "production", "--force")
	})
	t.Run("usage errors exit 2", func(t *testing.T) {
		s := newSandbox(t)
		for _, args := range [][]string{{"frobnicate"}, {"unpack"}, {"pack", "--hook"}, {"check", "extra"}} {
			if code, _, _ := s.run(args...); code != 2 {
				t.Fatalf("%v: exit %d, want 2", args, code)
			}
		}
	})
}

func TestKeys(t *testing.T) {
	t.Run("missing key strips pending plaintext", func(t *testing.T) {
		s := filled(t)
		s.setValue("API_TOKEN", `{"kind":"encrypted","state":"pending","valueToEncrypt":"tok_new"}`)
		os.Rename(s.keyFile("production"), s.path("moved.key"))
		s.fails([]string{"production: key production-", "is not on this machine"}, "pack")
		if strings.Contains(s.read("loudtsss.local.json"), "tok_new") {
			t.Fatal("pending plaintext left in the working file")
		}
	})
	t.Run("key from an environment variable", func(t *testing.T) {
		s := filled(t)
		k, _ := os.ReadFile(s.keyFile("production"))
		os.Remove(s.keyFile("production"))
		s.fails([]string{"is not on this machine"}, "export", "production")
		s.vars["LOUD_T_S_S_S_KEY_PRODUCTION"] = strings.TrimSpace(string(k))
		s.ok("export", "production")
		s.vars["LOUD_T_S_S_S_KEY_PRODUCTION"] = "loudtsss-key:v1:production-00000000:" + strings.Repeat("A", 43) + "="
		s.fails([]string{"holds key production-00000000"}, "export", "production")
	})
}

func TestSchemaChanges(t *testing.T) {
	t.Run("adding and removing a variable needs only your key", func(t *testing.T) {
		s := filled(t)
		s.ok("unpack", "development", "--force")
		prodKey := s.keyFile("production")
		os.Rename(prodKey, s.path("away.key"))
		s.editWorking(func(wf *WorkingFile) {
			wf.Variables.Set("FEATURE_X", Variable{Value: json.RawMessage("true"), Type: VarType{Kind: "bool"}, Sensitivity: "public", Exposure: "server", Required: &Cond{hasIn: true, In: []string{"development"}}})
			wf.Variables.Delete("LOG_LEVEL")
		})
		out := s.ok("pack")
		for _, w := range []string{"added FEATURE_X", "removed LOG_LEVEL", "production: not touched, no key; removed variables stay"} {
			if !strings.Contains(out, w) {
				t.Fatalf("pack output lacks %q:\n%s", w, out)
			}
		}
		s.ok("check")
		os.Rename(s.path("away.key"), prodKey)
		out = s.ok("check", "--all-keys")
		if !strings.Contains(out, "production: LOG_LEVEL is in the block but no longer in the schema") {
			t.Fatalf("check output: %s", out)
		}
		// The next pack with the production key drops the stale variable.
		s.ok("unpack", "production", "--force")
		if out := s.ok("pack"); strings.Contains(out, "nothing changed") {
			t.Fatalf("pack should drop the stale variable: %s", out)
		}
		if out := s.ok("check", "--all-keys"); strings.Contains(out, "no longer in the schema") {
			t.Fatalf("stale variable still there: %s", out)
		}
	})
	t.Run("changing exposure needs every key", func(t *testing.T) {
		s := filled(t)
		s.ok("unpack", "development", "--force")
		os.Remove(s.keyFile("production"))
		s.editWorking(func(wf *WorkingFile) {
			v, _ := wf.Variables.Get("PORT")
			v.Exposure = "build"
			wf.Variables.Set("PORT", v)
		})
		s.fails([]string{"changed PORT.exposure", "missing key(s): production"}, "pack")
	})
	t.Run("changing exposure with every key updates every block", func(t *testing.T) {
		s := filled(t)
		s.ok("unpack", "development", "--force")
		s.editWorking(func(wf *WorkingFile) {
			v, _ := wf.Variables.Get("PORT")
			v.Exposure = "build"
			wf.Variables.Set("PORT", v)
		})
		out := s.ok("pack")
		if !strings.Contains(out, "staging: re-encrypted") || !strings.Contains(out, "production: re-encrypted") {
			t.Fatalf("pack output: %s", out)
		}
		s.ok("check", "--all-keys")
	})
}

func TestGit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s := filled(t)
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = s.dir
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	s.write(".gitignore", "loudtsss.local.json\n.env\n")
	git("add", ".gitignore", "loudtsss.json")

	out := s.ok("install-hook")
	hook := s.read(".git/hooks/pre-commit")
	if !strings.Contains(out, "installed") || !strings.Contains(hook, "loudtsss check --hook") {
		t.Fatalf("hook:\n%s", hook)
	}
	s.ok("check", "--hook")

	s.setValue("PORT", "81")
	s.fails([]string{"has changes for production that are not packed", "commit rejected"}, "check", "--hook")
	s.ok("pack")
	s.fails([]string{"loudtsss.json has changes that are not staged"}, "check", "--hook")
	git("add", "loudtsss.json")
	s.ok("check", "--hook")

	git("add", "-f", "loudtsss.local.json")
	s.fails([]string{"loudtsss.local.json is in git"}, "check")
	git("rm", "-q", "--cached", "loudtsss.local.json")

	s.fails([]string{"refusing to write secrets.env: it is not ignored by git"}, "export", "production", "-o", "secrets.env")
	s.ok("export", "production")
}
