package loudtsss

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

var (
	reEnvName = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,62}$`)
	reVarName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	reEmail   = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reHost    = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)
)

var kindOptions = map[string][]string{
	"string": nil, "bool": nil, "port": nil, "duration": nil, "email": nil, "host": nil,
	"int": {"min", "max"}, "float": {"min", "max"},
	"enum": {"values", "ignoreCase"},
}

// validateEnvironments checks the environment names.
func validateEnvironments(cfg *Config) []string {
	var errs []string
	if cfg.Version != 1 {
		errs = append(errs, fmt.Sprintf("version must be 1, got %d", cfg.Version))
	}
	if cfg.Environments.Len() == 0 {
		errs = append(errs, `"environments" must list at least one environment`)
	}
	for _, e := range cfg.Environments.Keys() {
		if !reEnvName.MatchString(e) {
			errs = append(errs, fmt.Sprintf("environment %q: names are lowercase letters, digits, - and _, starting with a letter", e))
		}
	}
	return errs
}

// validateSchema checks every variable definition against the environments.
func validateSchema(vars *Ordered[Variable], envs *Ordered[EnvironmentSettings]) []string {
	var errs []string
	add := func(n, f string, a ...any) { errs = append(errs, n+": "+fmt.Sprintf(f, a...)) }
	for _, n := range vars.Keys() {
		v, _ := vars.Get(n)
		if !reVarName.MatchString(n) {
			add(n, "not a valid environment variable name (letters, digits and _, not starting with a digit)")
		}
		t := v.Type
		opts, known := kindOptions[t.Kind]
		switch {
		case t.Kind == "":
			add(n, `"type" is required, e.g. { "kind": "string" }`)
		case !known:
			add(n, "unknown type kind %q", t.Kind)
		default:
			used := map[string]bool{"min": t.Min != nil, "max": t.Max != nil, "values": t.Values != nil, "ignoreCase": t.IgnoreCase}
			for opt, set := range used {
				if set && !contains(opts, opt) {
					add(n, "kind %q has no option %q", t.Kind, opt)
				}
			}
		}
		if t.Kind == "enum" && len(t.Values) == 0 {
			add(n, `enum needs a non-empty "values" list`)
		}
		if t.Min != nil && t.Max != nil && *t.Min > *t.Max {
			add(n, "min %v is greater than max %v", *t.Min, *t.Max)
		}
		if v.Sensitivity != "" && !contains([]string{"public", "internal", "secret"}, v.Sensitivity) {
			add(n, `sensitivity must be "public", "internal" or "secret", got %q`, v.Sensitivity)
		}
		if v.Exposure != "" && !contains([]string{"server", "client", "build"}, v.Exposure) {
			add(n, `exposure must be "server", "client" or "build", got %q`, v.Exposure)
		}
		if v.Sensitivity == "secret" && v.Exposure == "client" {
			add(n, `a secret cannot have exposure "client"`)
		}
		for field, c := range map[string]*Cond{"required": v.Required, "allowEmpty": v.AllowEmpty} {
			if c == nil || c.Bool != nil {
				continue
			}
			if c.hasIn == c.hasNotIn {
				add(n, `%s: use exactly one of "in" and "notIn"`, field)
			}
			for _, e := range append(append([]string(nil), c.In...), c.NotIn...) {
				if !envs.Has(e) {
					add(n, "%s: unknown environment %q", field, e)
				}
			}
		}
		if v.Deprecated != nil && v.Required.truthy() {
			add(n, "a deprecated variable cannot be required")
		}
		if v.Values != nil {
			add(n, `"values" is not supported: values live in the encrypted blocks, and the working file holds one environment ("value")`)
		}
	}
	return errs
}

// validateCommitted checks that the committed file carries no values.
func validateCommitted(cfg *Config) []string {
	var errs []string
	for _, n := range cfg.Variables.Keys() {
		v, _ := cfg.Variables.Get(n)
		if v.Value != nil {
			errs = append(errs, fmt.Sprintf("%s: loudtsss.json holds a plaintext \"value\"; values belong only in the encrypted blocks", n))
		}
	}
	if cfg.Blob != nil {
		for _, e := range cfg.Blob.Keys() {
			if !cfg.Environments.Has(e) {
				errs = append(errs, fmt.Sprintf("blob.%s: not an environment listed in \"environments\"", e))
			}
		}
	}
	return errs
}

// validateValue checks one value against its definition; raw is nil when the variable is not set.
func validateValue(v Variable, raw json.RawMessage, env string) string {
	if raw == nil {
		if v.Required.Match(env, true) {
			return "required but not set"
		}
		return ""
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return "invalid JSON value"
	}
	if s, ok := x.(string); ok && s == "" {
		if v.AllowEmpty.Match(env, false) {
			return ""
		}
		return "empty string is not allowed (set allowEmpty to allow it)"
	}
	t := v.Type
	got := fmt.Sprintf("got %s", strings.TrimSpace(string(raw)))
	str, isStr := x.(string)
	num, isNum := x.(json.Number)
	switch t.Kind {
	case "string":
		if !isStr {
			return "expected a string, " + got
		}
	case "bool":
		if _, ok := x.(bool); !ok {
			return "expected true or false, " + got
		}
	case "port":
		i, err := num.Int64()
		if !isNum || err != nil {
			return "expected an integer port, " + got
		}
		if i < 1 || i > 65535 {
			return fmt.Sprintf("port %d is outside 1–65535", i)
		}
	case "int", "float":
		if !isNum {
			return fmt.Sprintf("expected a number (%s), %s", t.Kind, got)
		}
		f, err := num.Float64()
		if err != nil {
			return "invalid number, " + got
		}
		if t.Kind == "int" {
			if _, err := num.Int64(); err != nil {
				return "expected an integer, " + got
			}
		}
		if t.Min != nil && f < *t.Min {
			return fmt.Sprintf("%s is below min %v", num, *t.Min)
		}
		if t.Max != nil && f > *t.Max {
			return fmt.Sprintf("%s is above max %v", num, *t.Max)
		}
	case "duration":
		if !isStr {
			return `expected a duration string such as "5s", ` + got
		}
		if _, err := time.ParseDuration(str); err != nil {
			return fmt.Sprintf(`%q is not a Go duration such as "5s" or "1h30m"`, str)
		}
	case "email":
		if !isStr || !reEmail.MatchString(str) {
			return "expected an email address, " + got
		}
	case "host":
		if !isStr || (net.ParseIP(str) == nil && !reHost.MatchString(str)) {
			return "expected a host name or IP address, " + got
		}
	case "enum":
		if !isStr {
			return "expected a string, " + got
		}
		for _, e := range t.Values {
			if e == str || (t.IgnoreCase && strings.EqualFold(e, str)) {
				return ""
			}
		}
		return fmt.Sprintf("%q is not one of %s", str, strings.Join(t.Values, " | "))
	}
	return ""
}

// validateValues checks every variable of the schema in one environment.
func validateValues(env string, values *Ordered[json.RawMessage], vars *Ordered[Variable]) []string {
	var errs []string
	for _, n := range vars.Keys() {
		v, _ := vars.Get(n)
		var raw json.RawMessage
		if values.Has(n) {
			raw, _ = values.Get(n)
		}
		if e := validateValue(v, raw, env); e != "" {
			errs = append(errs, fmt.Sprintf("%s: %s: %s", env, n, e))
		}
	}
	return errs
}

// integrity compares the copies of sensitivity/exposure in a block with the schema.
// Only variables present in the block are compared: a variable missing from a block is not set there.
func integrity(env string, p *Payload, vars *Ordered[Variable]) []string {
	var errs []string
	for _, n := range vars.Keys() {
		m, ok := p.Meta.Get(n)
		if !ok {
			continue
		}
		v, _ := vars.Get(n)
		if v.Sensitivity != m.Sensitivity {
			errs = append(errs, fmt.Sprintf("%s: %s.sensitivity is %q in the schema but %q in the block", env, n, v.Sensitivity, m.Sensitivity))
		}
		if v.Exposure != m.Exposure {
			errs = append(errs, fmt.Sprintf("%s: %s.exposure is %q in the schema but %q in the block", env, n, v.Exposure, m.Exposure))
		}
	}
	for _, n := range p.Values.Keys() {
		if !p.Meta.Has(n) {
			errs = append(errs, fmt.Sprintf("%s: %s has a value but no metadata in the block", env, n))
		}
	}
	return errs
}

// staleVars lists variables kept in a block after they were removed from the schema.
func staleVars(p *Payload, vars *Ordered[Variable]) []string {
	var out []string
	for _, n := range p.Values.Keys() {
		if !vars.Has(n) {
			out = append(out, n)
		}
	}
	return out
}

// metaChanges lists sensitivity/exposure changes of variables that exist in both schemas.
// Adding or removing a variable is not listed: it does not touch other environments' blocks.
func metaChanges(old, new *Ordered[Variable]) []string {
	var out []string
	for _, n := range new.Keys() {
		o, ok := old.Get(n)
		if !ok {
			continue
		}
		v, _ := new.Get(n)
		if o.Sensitivity != v.Sensitivity {
			out = append(out, n+".sensitivity")
		}
		if o.Exposure != v.Exposure {
			out = append(out, n+".exposure")
		}
	}
	return out
}
