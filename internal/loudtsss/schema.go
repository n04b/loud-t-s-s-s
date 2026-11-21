package loudtsss

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
)

// FormatID is part of every block's AAD; it changes only with an incompatible block format.
const FormatID = "loud-t-s-s-s/1"

// Config is the committed file, loudtsss.json. See types.ts for the TypeScript description.
type Config struct {
	Version      int                          `json:"version"`
	Environments Ordered[EnvironmentSettings] `json:"environments"`
	Variables    Ordered[Variable]            `json:"variables"`
	Blob         *Ordered[string]             `json:"blob,omitempty"`
}

type EnvironmentSettings struct {
	// Plaintext secrets are forbidden: in the working file a secret can only be written as pending.
	Protected bool `json:"protected,omitempty"`
}

type Variable struct {
	Value       json.RawMessage `json:"value,omitempty"`  // working file only
	Values      json.RawMessage `json:"values,omitempty"` // open question; rejected in both files
	Type        VarType         `json:"type"`
	Description string          `json:"description,omitempty"`
	Required    *Cond           `json:"required,omitempty"`
	AllowEmpty  *Cond           `json:"allowEmpty,omitempty"`
	Example     string          `json:"example,omitempty"`
	Sensitivity string          `json:"sensitivity,omitempty"`
	Exposure    string          `json:"exposure,omitempty"`
	Group       string          `json:"group,omitempty"`
	Tags        []string        `json:"tags,omitempty"`
	Aliases     []string        `json:"aliases,omitempty"`
	Deprecated  *Deprecation    `json:"deprecated,omitempty"`
}

// VarType is a superset of every kind's options; validation rejects options that do not belong to the kind.
type VarType struct {
	Kind       string   `json:"kind"`
	Min        *float64 `json:"min,omitempty"`
	Max        *float64 `json:"max,omitempty"`
	Values     []string `json:"values,omitempty"`
	IgnoreCase bool     `json:"ignoreCase,omitempty"`
}

type Deprecation struct {
	Since      string `json:"since,omitempty"`
	ReplacedBy string `json:"replacedBy,omitempty"`
	Message    string `json:"message,omitempty"`
}

// Cond is `boolean | { in: Environment[] } | { notIn: Environment[] }`.
type Cond struct {
	Bool     *bool
	In       []string
	NotIn    []string
	hasIn    bool
	hasNotIn bool
}

func (c *Cond) UnmarshalJSON(b []byte) error {
	var bv bool
	if err := json.Unmarshal(b, &bv); err == nil {
		c.Bool = &bv
		return nil
	}
	var obj struct {
		In    *[]string `json:"in"`
		NotIn *[]string `json:"notIn"`
	}
	if err := decodeStrict(b, &obj); err != nil {
		return fmt.Errorf(`expected true, false, {"in": [...]} or {"notIn": [...]}: %v`, err)
	}
	if obj.In != nil {
		c.hasIn, c.In = true, *obj.In
	}
	if obj.NotIn != nil {
		c.hasNotIn, c.NotIn = true, *obj.NotIn
	}
	return nil
}

func (c Cond) MarshalJSON() ([]byte, error) {
	if c.Bool != nil {
		return marshal(*c.Bool)
	}
	var o Ordered[[]string]
	if c.hasIn {
		o.Set("in", c.In)
	}
	if c.hasNotIn {
		o.Set("notIn", c.NotIn)
	}
	return o.MarshalJSON()
}

// Match reports whether the rule applies in env; a nil Cond means the default.
func (c *Cond) Match(env string, dflt bool) bool {
	switch {
	case c == nil:
		return dflt
	case c.Bool != nil:
		return *c.Bool
	case c.hasIn:
		return contains(c.In, env)
	case c.hasNotIn:
		return !contains(c.NotIn, env)
	}
	return dflt
}

// truthy reports whether the condition can be true in some environment.
func (c *Cond) truthy() bool {
	return c != nil && (c.Bool == nil || *c.Bool)
}

// Encrypted is the value object `{ kind: "encrypted", state, valueToEncrypt?, algorithm?, keyId? }`.
type Encrypted struct {
	Kind           string  `json:"kind"`
	State          string  `json:"state"`
	ValueToEncrypt *string `json:"valueToEncrypt,omitempty"`
	Algorithm      string  `json:"algorithm,omitempty"`
	KeyID          string  `json:"keyId,omitempty"`
}

var encryptedMarker = json.RawMessage(`{"kind":"encrypted","state":"encrypted"}`)

// parseValue splits a working-file value into a literal or an encrypted marker.
func parseValue(raw json.RawMessage) (literal json.RawMessage, enc *Encrypted, err error) {
	raw = compactJSON(raw)
	if len(raw) == 0 {
		return nil, nil, nil
	}
	switch raw[0] {
	case '{':
		var e Encrypted
		if err := decodeStrict(raw, &e); err != nil {
			return nil, nil, err
		}
		if e.Kind != "encrypted" {
			return nil, nil, fmt.Errorf(`a value object must have "kind": "encrypted", got %q`, e.Kind)
		}
		switch e.State {
		case "encrypted":
			if e.ValueToEncrypt != nil {
				return nil, nil, errors.New(`"valueToEncrypt" is only allowed with "state": "pending"`)
			}
		case "pending":
			if e.ValueToEncrypt == nil {
				return nil, nil, errors.New(`"state": "pending" needs "valueToEncrypt"`)
			}
		case "":
			return nil, nil, errors.New(`"state" is required ("encrypted" or "pending"); it has no default, so a value is never taken for plaintext by mistake`)
		default:
			return nil, nil, fmt.Errorf(`"state" must be "encrypted" or "pending", got %q`, e.State)
		}
		if e.Algorithm != "" && e.Algorithm != "aes-256-gcm" {
			return nil, nil, fmt.Errorf(`"algorithm" must be "aes-256-gcm", got %q`, e.Algorithm)
		}
		if e.KeyID != "" {
			return nil, nil, errors.New(`"keyId" per value comes with key rotation, after the MVP; the block's key is used`)
		}
		return nil, &e, nil
	case '[':
		return nil, nil, errors.New("a value cannot be an array")
	case 'n':
		return nil, nil, errors.New(`a value cannot be null; remove "value" to leave the variable unset`)
	}
	return raw, nil, nil
}

// Payload is the decrypted content of a block. Values are compact JSON literals.
type Payload struct {
	Version int                      `json:"version"`
	Values  Ordered[json.RawMessage] `json:"values"`
	Meta    Ordered[Meta]            `json:"meta"`
}

// Meta keeps copies of sensitivity and exposure for every variable that has a value in the block.
type Meta struct {
	Sensitivity string `json:"sensitivity,omitempty"`
	Exposure    string `json:"exposure,omitempty"`
}

func metaOf(v Variable) Meta { return Meta{Sensitivity: v.Sensitivity, Exposure: v.Exposure} }

// newPayload builds a payload whose values and meta follow the schema's order.
func newPayload(version int, values map[string]json.RawMessage, schema *Ordered[Variable]) *Payload {
	p := &Payload{Version: version}
	for _, n := range schema.Keys() {
		if v, ok := values[n]; ok {
			def, _ := schema.Get(n)
			p.Values.Set(n, compactJSON(v))
			p.Meta.Set(n, metaOf(def))
		}
	}
	return p
}

// sameContent compares values and meta, ignoring the version and the key order,
// so reordering variables in the schema does not re-encrypt any block.
func sameContent(a, b *Payload) bool { return canonical(a) == canonical(b) }

func canonical(p *Payload) string {
	b, _ := marshal(struct {
		V Ordered[json.RawMessage]
		M Ordered[Meta]
	}{p.Values, p.Meta})
	var x any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	_ = dec.Decode(&x)
	out, _ := marshal(x) // maps marshal with sorted keys
	return string(out)
}

// WorkingFile is loudtsss.local.json: the config unpacked for one environment.
type WorkingFile struct {
	Environment string            `json:"environment"`
	Variables   Ordered[Variable] `json:"variables"`
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
