package loudtsss

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// loadValid loads the committed file and validates it; problems go to the report.
func (a *App) loadValid(r *report) *Config {
	c, err := a.loadConfig()
	if err != nil {
		r.err("%s", err)
		return nil
	}
	r.errs(validateEnvironments(c))
	r.errs(validateCommitted(c))
	r.errs(validateSchema(&c.Variables, &c.Environments))
	if r.errors > 0 {
		return nil
	}
	return c
}

func (a *App) knownEnv(r *report, c *Config, env string) bool {
	if c.Environments.Has(env) {
		return true
	}
	r.err("unknown environment %q; environments: %s", env, strings.Join(c.Environments.Keys(), ", "))
	return false
}

// Keygen creates the key of an environment and its first, empty block.
func (a *App) Keygen(env string) int {
	r := a.newReport()
	c := a.loadValid(r)
	if c == nil || !a.knownEnv(r, c, env) {
		return r.fail("no key generated")
	}
	if s, ok := c.Blob.Get(env); ok {
		id, _, _ := blockKeyID(s)
		r.err("%s already has a block encrypted with key %s; key rotation comes after the MVP", env, id)
		return r.fail("no key generated")
	}
	k, err := generateKey(env)
	if err != nil {
		r.err("%s", err)
		return r.fail("no key generated")
	}
	path, err := a.Keys.Save(k)
	if err != nil {
		r.err("%s", err)
		return r.fail("no key generated")
	}
	s, err := seal(env, k, &Payload{Version: 1})
	if err == nil {
		c.Blob.Set(env, s)
		err = a.writeConfig(c)
	}
	if err != nil {
		r.err("%s", err)
		return r.fail(fmt.Sprintf("the key was saved to %s, but %s was not updated", path, a.configName()))
	}
	r.ok("generated key %s", k.ID)
	r.ok("saved it to %s (mode 600)", path)
	r.ok("added an empty %s block to %s", env, a.configName())
	r.note("keep the key outside the repository; on another machine, put the file in its keys directory or set %s to the file's contents", envVarFor(env))
	return 0
}

// Unpack decrypts an environment's block into the working file.
func (a *App) Unpack(env string, force bool) int {
	r := a.newReport()
	c := a.loadValid(r)
	if c == nil || !a.knownEnv(r, c, env) {
		return r.fail(a.workingName() + " not written")
	}
	if !force {
		exists, inSync, wenv, err := a.workingState(c)
		switch {
		case exists && err != nil:
			r.err("cannot tell whether %s has changes that are not packed: %v", a.workingName(), err)
			r.note("pack it first, or pass --force to overwrite it")
			return r.fail(a.workingName() + " not written")
		case exists && !inSync:
			r.err("%s has changes for %s that are not packed", a.workingName(), wenv)
			r.note("run loudtsss pack, or pass --force to discard them")
			return r.fail(a.workingName() + " not written")
		}
	}
	p, k, err := a.openBlock(c, env)
	if err != nil {
		r.err("%s", err)
		return r.fail(a.workingName() + " not written")
	}
	r.errs(integrity(env, p, &c.Variables))
	if r.errors > 0 {
		return r.fail(a.workingName() + " not written")
	}
	// Invalid or missing values are what you unpack to fix, so they are warnings here; pack and check fail on them.
	for _, w := range validateValues(env, &p.Values, &c.Variables) {
		r.warn("%s", w)
	}
	if err := a.writeWorking(workingFor(c, env, p)); err != nil {
		r.err("%s", err)
		return r.fail(a.workingName() + " not written")
	}
	r.ok("decrypted the %s block (v%d) with key %s", env, p.Version, k.ID)
	r.ok("wrote %s; %d secret(s) stay in the block", a.workingName(), secretCount(c, p))
	for _, n := range staleVars(p, &c.Variables) {
		r.warn("%s: %s is in the block but no longer in the schema; it is ignored and dropped on the next pack with the %s key", env, n, env)
	}
	if a.inRepo() && !a.gitIgnored(a.WorkingPath) {
		r.warn("%s is not ignored by git; add it to .gitignore", a.workingName())
	}
	return 0
}

// Pack validates the working file, encrypts pending values and re-encrypts only the blocks that changed.
func (a *App) Pack() int {
	r := a.newReport()
	const notChanged = "loudtsss.json not changed"
	c, err := a.loadConfig()
	if err != nil {
		r.err("%s", err)
		return r.fail(notChanged)
	}
	r.errs(validateEnvironments(c))
	r.errs(validateCommitted(c))
	if r.errors > 0 {
		return r.fail(notChanged)
	}
	wf, _, err := a.readWorking()
	if errors.Is(err, os.ErrNotExist) {
		r.err("nothing to pack: %s does not exist; run loudtsss unpack <env> first", a.workingName())
		return r.fail(notChanged)
	}
	if err != nil {
		r.err("%s", err)
		return r.fail(notChanged)
	}
	env := wf.Environment
	if !a.knownEnv(r, c, env) {
		return r.fail(notChanged)
	}
	settings, _ := c.Environments.Get(env)

	blockStr, key, err := a.blockKey(c, env)
	var nk noKeyError
	if errors.As(err, &nk) {
		removed := 0
		for _, n := range wf.Variables.Keys() {
			v, _ := wf.Variables.Get(n)
			if _, enc, _ := parseValue(v.Value); enc != nil && enc.State == "pending" {
				v.Value = nil
				wf.Variables.Set(n, v)
				removed++
			}
		}
		if removed > 0 {
			if werr := a.writeWorking(wf); werr == nil {
				r.warn("removed %d pending plaintext value(s) from %s: they cannot be encrypted", removed, a.workingName())
			}
		}
		r.err("%s", err)
		return r.fail(notChanged)
	}
	if err != nil {
		r.err("%s", err)
		return r.fail(notChanged)
	}
	old, err := open(env, key, blockStr)
	if err != nil {
		r.err("%s: %v", env, err)
		return r.fail(notChanged)
	}

	// Split the working file into the new schema and this environment's values.
	schema := &Ordered[Variable]{}
	values := map[string]json.RawMessage{}
	pending := 0
	for _, n := range wf.Variables.Keys() {
		v, _ := wf.Variables.Get(n)
		raw := v.Value
		v.Value = nil
		schema.Set(n, v)
		if raw == nil {
			continue
		}
		lit, enc, err := parseValue(raw)
		switch {
		case err != nil:
			r.err("%s: %s: %v", env, n, err)
		case enc != nil && enc.State == "encrypted":
			if prev, ok := old.Values.Get(n); ok {
				values[n] = prev
			} else {
				r.err("%s: %s is marked encrypted, but the %s block has no value for it", env, n, env)
			}
		case enc != nil:
			values[n] = rawOf(*enc.ValueToEncrypt)
			pending++
		default:
			if v.Sensitivity == "secret" && settings.Protected {
				r.err(`%s: %s is a secret written in plaintext in a protected environment; write it as { "kind": "encrypted", "state": "pending", "valueToEncrypt": "..." }`, env, n)
			}
			values[n] = lit
		}
	}
	r.errs(validateSchema(schema, &c.Environments))
	mine := newPayload(old.Version, values, schema)
	r.errs(validateValues(env, &mine.Values, schema))
	if r.errors > 0 {
		return r.fail(notChanged)
	}

	// Other environments: re-encrypt the blocks we have keys for if their content changes.
	changes := metaChanges(&c.Variables, schema)
	updates := map[string]*Payload{}
	keys := map[string]Key{env: key}
	from := map[string]int{}
	var missing, noBlock []string
	for _, e := range c.Environments.Keys() {
		if e == env {
			continue
		}
		p, k, err := a.openBlock(c, e)
		var nk noKeyError
		switch {
		case errors.As(err, &nk):
			missing = append(missing, e)
			continue
		case err != nil && !c.Blob.Has(e):
			noBlock = append(noBlock, e)
			continue
		case err != nil:
			r.err("%s", err)
			return r.fail(notChanged)
		}
		nv := map[string]json.RawMessage{}
		for _, n := range p.Values.Keys() {
			if schema.Has(n) {
				nv[n], _ = p.Values.Get(n)
			}
		}
		np := newPayload(p.Version, nv, schema)
		if !sameContent(np, p) {
			np.Version = p.Version + 1
			updates[e], keys[e], from[e] = np, k, p.Version
		}
		for _, w := range validateValues(e, &np.Values, schema) {
			r.warn("%s (check will fail until it is set)", w)
		}
	}
	if len(changes) > 0 && len(missing) > 0 {
		r.err("changed %s: every block that holds a value keeps a copy of sensitivity/exposure, and pack cannot tell which blocks hold one without decrypting them; missing key(s): %s",
			strings.Join(changes, ", "), strings.Join(missing, ", "))
		return r.fail(notChanged)
	}
	if !sameContent(mine, old) {
		mine.Version = old.Version + 1
		updates[env], from[env] = mine, old.Version
	}

	oldSchema, _ := marshal(c.Variables)
	newSchema, _ := marshal(schema)
	if len(updates) == 0 && bytes.Equal(oldSchema, newSchema) {
		r.ok("nothing changed: %s stays byte-for-byte the same", a.configName())
		return a.rewriteWorking(r, c, env, old)
	}
	for e, p := range updates {
		s, err := seal(e, keys[e], p)
		if err != nil {
			r.err("%s", err)
			return r.fail(notChanged)
		}
		c.Blob.Set(e, s)
	}
	for _, n := range schema.Keys() {
		if !c.Variables.Has(n) {
			r.ok("added %s: other environments treat it as not set until someone sets it there", n)
		}
	}
	removed := false
	for _, n := range c.Variables.Keys() {
		if !schema.Has(n) {
			r.ok("removed %s from the schema", n)
			removed = true
		}
	}
	c.Variables = *schema
	if err := a.writeConfig(c); err != nil {
		r.err("%s", err)
		return r.fail(notChanged)
	}
	for _, e := range c.Environments.Keys() {
		switch {
		case updates[e] != nil:
			r.ok("%s: re-encrypted, v%d -> v%d", e, from[e], updates[e].Version)
		case contains(missing, e) && removed:
			r.note("%s: not touched, no key; removed variables stay in its block until the next pack with its key", e)
		case contains(missing, e):
			r.note("%s: not touched, no key", e)
		case contains(noBlock, e):
			r.note("%s: no block yet; run loudtsss keygen %s", e, e)
		default:
			r.note("%s: unchanged, ciphertext kept", e)
		}
	}
	if pending > 0 {
		r.ok("moved %d pending value(s) into the %s block; the plaintext is gone from %s", pending, env, a.workingName())
	}
	final := old
	if updates[env] != nil {
		final = updates[env]
	}
	return a.rewriteWorking(r, c, env, final)
}

func (a *App) rewriteWorking(r *report, c *Config, env string, p *Payload) int {
	if err := a.writeWorking(workingFor(c, env, p)); err != nil {
		r.err("%s", err)
		return r.fail(a.workingName() + " not rewritten")
	}
	return 0
}

// Check validates the committed file and every block it has a key for.
// With hook, it also checks the git index and the working file, as the pre-commit hook.
func (a *App) Check(hook, allKeys bool) int {
	r := a.newReport()
	what := "check failed"
	if hook {
		what = "commit rejected"
	}
	c, err := a.loadConfig()
	if err != nil {
		r.err("%s", err)
		return r.fail(what)
	}
	r.errs(validateEnvironments(c))
	r.errs(validateCommitted(c))
	r.errs(validateSchema(&c.Variables, &c.Environments))
	for _, env := range c.Environments.Keys() {
		p, k, err := a.openBlock(c, env)
		var nk noKeyError
		switch {
		case errors.As(err, &nk) && !allKeys:
			r.note("%s: not verified, key %s is not on this machine (format only)", env, nk.keyID)
			continue
		case err != nil:
			r.err("%s", err)
			continue
		}
		errs := append(integrity(env, p, &c.Variables), validateValues(env, &p.Values, &c.Variables)...)
		r.errs(errs)
		if len(errs) == 0 {
			r.ok("%s: block v%d decrypted with %s and valid", env, p.Version, k.ID)
		}
		for _, n := range staleVars(p, &c.Variables) {
			r.warn("%s: %s is in the block but no longer in the schema; dropped on the next pack with the %s key", env, n, env)
		}
	}
	if a.inRepo() {
		if a.gitTrackedOrStaged(a.WorkingPath) {
			r.err("%s is in git: it holds decrypted values and must never be committed; run: git rm --cached %s", a.workingName(), a.workingName())
		}
		if hook && a.gitUnstaged(a.ConfigPath) {
			r.err("%s has changes that are not staged; git add it, so the commit contains what was checked", a.configName())
		}
	}
	if hook {
		exists, inSync, wenv, err := a.workingState(c)
		switch {
		case exists && err != nil:
			r.note("%s: cannot compare with the block (%v)", a.workingName(), err)
		case exists && !inSync:
			r.err("%s has changes for %s that are not packed; run loudtsss pack, then commit", a.workingName(), wenv)
		}
	}
	if r.errors > 0 {
		return r.fail(what)
	}
	r.ok("check passed")
	return 0
}

var reBareEnv = regexp.MustCompile(`^[A-Za-z0-9_./:@,+=%-]*$`)

func envValue(raw json.RawMessage) string {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return string(raw) // number or boolean
	}
	if reBareEnv.MatchString(s) {
		return s
	}
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`", "\n", `\n`).Replace(s) + `"`
}

// Export decrypts one environment into a .env file and writes .env.example from the schema.
func (a *App) Export(env, out, example string, force bool) int {
	r := a.newReport()
	if out == "-" {
		r.out = a.Stderr
	}
	c := a.loadValid(r)
	if c == nil || !a.knownEnv(r, c, env) {
		return r.fail("nothing written")
	}
	p, _, err := a.openBlock(c, env)
	if err != nil {
		r.err("%s", err)
		return r.fail("nothing written")
	}
	r.errs(integrity(env, p, &c.Variables))
	r.errs(validateValues(env, &p.Values, &c.Variables))
	if r.errors > 0 {
		return r.fail("nothing written")
	}

	var env1, ex strings.Builder
	fmt.Fprintf(&env1, "# Exported by loudtsss from %s: %s, block v%d\n# Contains decrypted secrets. Keep this file out of git.\n\n", a.configName(), env, p.Version)
	fmt.Fprintf(&ex, "# Generated by loudtsss from %s. Example values only.\n", a.configName())
	count := 0
	for _, n := range c.Variables.Keys() {
		v, _ := c.Variables.Get(n)
		if raw, ok := p.Values.Get(n); ok {
			fmt.Fprintf(&env1, "%s=%s\n", n, envValue(raw))
			count++
		} else {
			fmt.Fprintf(&env1, "# %s is not set in %s\n", n, env)
		}
		kind := v.Type.Kind
		if kind == "enum" {
			kind = "one of " + strings.Join(v.Type.Values, " | ")
		}
		parts := []string{}
		for _, s := range []string{v.Description, kind, v.Sensitivity} {
			if s != "" {
				parts = append(parts, s)
			}
		}
		fmt.Fprintf(&ex, "\n# %s\n%s=%s\n", strings.Join(parts, " · "), n, envValue(rawOf(v.Example)))
	}

	if out == "-" {
		fmt.Fprint(a.Stdout, env1.String())
	} else {
		if a.inRepo() && !a.gitIgnored(out) && !force {
			r.err("refusing to write %s: it is not ignored by git and would hold decrypted secrets; add it to .gitignore, or pass --force", a.display(out))
			return r.fail("nothing written")
		}
		if err := writeFileAtomic(out, []byte(env1.String()), 0o600); err != nil {
			r.err("%s", err)
			return r.fail("nothing written")
		}
		r.ok("wrote %s: %d variable(s), %d secret(s) in plaintext (mode 600)", a.display(out), count, secretCount(c, p))
	}
	if example != "" {
		if err := writeFileAtomic(example, []byte(ex.String()), 0o644); err != nil {
			r.err("%s", err)
			return r.fail(a.display(example) + " not written")
		}
		r.ok("wrote %s", a.display(example))
	}
	return 0
}

const hookMarker = "# loudtsss pre-commit hook"

// InstallHook writes a pre-commit hook that runs `loudtsss check --hook`.
func (a *App) InstallHook(force bool) int {
	r := a.newReport()
	if !a.inRepo() {
		r.err("not inside a git repository")
		return r.fail("no hook installed")
	}
	top, _, _ := a.git("rev-parse", "--show-toplevel")
	hookRel, _, _ := a.git("rev-parse", "--git-path", "hooks/pre-commit")
	top, hookRel = strings.TrimSpace(top), strings.TrimSpace(hookRel)
	hook := hookRel
	if !filepath.IsAbs(hook) {
		hook = filepath.Join(filepath.Dir(a.ConfigPath), hookRel)
	}
	if b, err := os.ReadFile(hook); err == nil && !bytes.Contains(b, []byte(hookMarker)) && !force {
		r.err("%s already exists and is not a loudtsss hook; add `loudtsss check --hook` to it yourself, or pass --force to replace it", hook)
		return r.fail("no hook installed")
	}
	cfgRel, err1 := filepath.Rel(top, a.ConfigPath)
	wRel, err2 := filepath.Rel(top, a.WorkingPath)
	if err1 != nil || err2 != nil {
		r.err("cannot place %s relative to the repository root %s", a.ConfigPath, top)
		return r.fail("no hook installed")
	}
	script := fmt.Sprintf(`#!/bin/sh
%s
if ! command -v loudtsss >/dev/null 2>&1; then
  echo "loudtsss pre-commit hook: loudtsss is not in PATH, so %s cannot be checked" >&2
  exit 1
fi
exec loudtsss check --hook --config %s --working %s
`, hookMarker, cfgRel, shellQuote(cfgRel), shellQuote(wRel))
	if err := os.MkdirAll(filepath.Dir(hook), 0o755); err != nil {
		r.err("%s", err)
		return r.fail("no hook installed")
	}
	if err := writeFileAtomic(hook, []byte(script), 0o755); err != nil {
		r.err("%s", err)
		return r.fail("no hook installed")
	}
	r.ok("installed %s", hook)
	r.note("hooks run only on this machine and can be skipped with --no-verify; run loudtsss check in CI too")
	return 0
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
