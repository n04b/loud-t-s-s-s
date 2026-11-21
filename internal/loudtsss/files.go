package loudtsss

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// App holds the paths and I/O of one CLI run.
type App struct {
	ConfigPath  string // loudtsss.json
	WorkingPath string // loudtsss.local.json
	Keys        KeyStore
	Stdout      io.Writer
	Stderr      io.Writer
}

func (a *App) configName() string  { return filepath.Base(a.ConfigPath) }
func (a *App) workingName() string { return filepath.Base(a.WorkingPath) }

// report prints results: ok and notes to out, warnings and errors to stderr. Errors are counted.
type report struct {
	out, errw io.Writer
	errors    int
}

func (a *App) newReport() *report { return &report{out: a.Stdout, errw: a.Stderr} }

func (r *report) ok(f string, x ...any)   { fmt.Fprintf(r.out, "ok: "+f+"\n", x...) }
func (r *report) note(f string, x ...any) { fmt.Fprintf(r.out, "note: "+f+"\n", x...) }
func (r *report) warn(f string, x ...any) { fmt.Fprintf(r.errw, "warning: "+f+"\n", x...) }
func (r *report) err(f string, x ...any) {
	r.errors++
	fmt.Fprintf(r.errw, "error: "+f+"\n", x...)
}
func (r *report) errs(list []string) {
	for _, e := range list {
		r.err("%s", e)
	}
}

// fail prints the error count and what was (not) done, and returns exit code 1.
func (r *report) fail(what string) int {
	fmt.Fprintf(r.errw, "error: %d error(s): %s\n", r.errors, what)
	return 1
}

// ---------- config files ----------

func (a *App) loadConfig() (*Config, error) {
	b, err := os.ReadFile(a.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%s not found", a.ConfigPath)
	}
	if err != nil {
		return nil, err
	}
	var c Config
	if err := decodeStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %v", a.configName(), err)
	}
	if c.Blob == nil {
		c.Blob = &Ordered[string]{}
	}
	return &c, nil
}

func (a *App) writeConfig(c *Config) error {
	blob := &Ordered[string]{}
	for _, e := range c.Environments.Keys() {
		if s, ok := c.Blob.Get(e); ok {
			blob.Set(e, s)
		}
	}
	out := *c
	out.Blob = blob
	if blob.Len() == 0 {
		out.Blob = nil
	}
	b, err := marshalFile(out)
	if err != nil {
		return err
	}
	return writeFileAtomic(a.ConfigPath, b, 0o644)
}

func (a *App) readWorking() (*WorkingFile, []byte, error) {
	b, err := os.ReadFile(a.WorkingPath)
	if err != nil {
		return nil, nil, err
	}
	var wf WorkingFile
	if err := decodeStrict(b, &wf); err != nil {
		return nil, b, fmt.Errorf("%s: %v", a.workingName(), err)
	}
	return &wf, b, nil
}

func (a *App) writeWorking(wf *WorkingFile) error {
	b, err := marshalFile(wf)
	if err != nil {
		return err
	}
	return writeFileAtomic(a.WorkingPath, b, 0o600)
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// ---------- blocks and keys ----------

type noKeyError struct{ env, keyID, dir string }

func (e noKeyError) Error() string {
	where := envVarFor(e.env)
	if e.dir != "" {
		where = filepath.Join(e.dir, e.keyID+".key") + " or " + where
	}
	return fmt.Sprintf("%s: key %s is not on this machine (looked in %s)", e.env, e.keyID, where)
}

// blockKey finds the key of an environment's block. A missing key is a noKeyError.
func (a *App) blockKey(c *Config, env string) (string, Key, error) {
	s, ok := c.Blob.Get(env)
	if !ok {
		return "", Key{}, fmt.Errorf("%s: no block yet; run: loudtsss keygen %s", env, env)
	}
	id, _, err := blockKeyID(s)
	if err != nil {
		return "", Key{}, fmt.Errorf("%s: %v", env, err)
	}
	k, found, err := a.Keys.Find(env, id)
	if err != nil {
		return "", Key{}, err
	}
	if !found {
		return "", Key{}, noKeyError{env, id, a.Keys.Dir}
	}
	return s, k, nil
}

func (a *App) openBlock(c *Config, env string) (*Payload, Key, error) {
	s, k, err := a.blockKey(c, env)
	if err != nil {
		return nil, Key{}, err
	}
	p, err := open(env, k, s)
	if err != nil {
		return nil, Key{}, fmt.Errorf("%s: %v", env, err)
	}
	return p, k, nil
}

// workingFor builds the working file of env: the schema plus this environment's values; secrets stay in the block.
func workingFor(c *Config, env string, p *Payload) *WorkingFile {
	wf := &WorkingFile{Environment: env}
	for _, n := range c.Variables.Keys() {
		v, _ := c.Variables.Get(n)
		v.Value, v.Values = nil, nil
		if raw, ok := p.Values.Get(n); ok {
			if v.Sensitivity == "secret" {
				v.Value = encryptedMarker
			} else {
				v.Value = raw
			}
		}
		wf.Variables.Set(n, v)
	}
	return wf
}

// workingState reports whether the working file exists and matches what unpack would write now.
func (a *App) workingState(c *Config) (exists, inSync bool, env string, err error) {
	wf, b, err := a.readWorking()
	if errors.Is(err, os.ErrNotExist) {
		return false, false, "", nil
	}
	if err != nil {
		return true, false, "", err
	}
	p, _, err := a.openBlock(c, wf.Environment)
	if err != nil {
		return true, false, wf.Environment, err
	}
	want, err := marshalFile(workingFor(c, wf.Environment, p))
	if err != nil {
		return true, false, wf.Environment, err
	}
	return true, bytes.Equal(compactJSON(want), compactJSON(b)), wf.Environment, nil
}

func secretCount(c *Config, p *Payload) int {
	n := 0
	for _, name := range p.Values.Keys() {
		if v, ok := c.Variables.Get(name); ok && v.Sensitivity == "secret" {
			n++
		}
	}
	return n
}

func rawOf(v string) json.RawMessage {
	b, _ := marshal(v)
	return b
}

// ---------- git ----------

// git runs a git command next to the config file. A start error (git missing) is returned as err.
func (a *App) git(args ...string) (string, int, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = filepath.Dir(a.ConfigPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return out.String(), ee.ExitCode(), nil
	}
	if err != nil {
		return "", -1, err
	}
	return out.String(), 0, nil
}

func (a *App) inRepo() bool {
	out, code, err := a.git("rev-parse", "--is-inside-work-tree")
	return err == nil && code == 0 && strings.TrimSpace(out) == "true"
}

func (a *App) gitIgnored(path string) bool {
	_, code, err := a.git("check-ignore", "-q", "--", path)
	return err == nil && code == 0
}

func (a *App) gitTrackedOrStaged(path string) bool {
	if _, code, err := a.git("ls-files", "--error-unmatch", "--", path); err == nil && code == 0 {
		return true
	}
	out, _, err := a.git("diff", "--cached", "--name-only", "--", path)
	return err == nil && strings.TrimSpace(out) != ""
}

func (a *App) gitUnstaged(path string) bool {
	_, code, err := a.git("diff", "--quiet", "--", path)
	return err == nil && code == 1
}

// display shortens a path relative to the config file's directory for messages.
func (a *App) display(p string) string {
	if rel, err := filepath.Rel(filepath.Dir(a.ConfigPath), p); err == nil && !strings.HasPrefix(rel, "..") {
		return rel
	}
	return p
}
