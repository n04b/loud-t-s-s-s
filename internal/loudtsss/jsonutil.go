package loudtsss

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Ordered is a JSON object that keeps its key order and rejects duplicate keys.
// Key order matters: pack rewrites loudtsss.json, and a stable order keeps git diffs small.
type Ordered[V any] struct {
	keys []string
	m    map[string]V
}

func (o *Ordered[V]) Keys() []string { return append([]string(nil), o.keys...) }
func (o *Ordered[V]) Len() int       { return len(o.keys) }
func (o *Ordered[V]) Has(k string) bool {
	_, ok := o.m[k]
	return ok
}
func (o *Ordered[V]) Get(k string) (V, bool) {
	v, ok := o.m[k]
	return v, ok
}

func (o *Ordered[V]) Set(k string, v V) {
	if o.m == nil {
		o.m = map[string]V{}
	}
	if _, ok := o.m[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.m[k] = v
}

func (o *Ordered[V]) Delete(k string) {
	if _, ok := o.m[k]; !ok {
		return
	}
	delete(o.m, k)
	for i, key := range o.keys {
		if key == k {
			o.keys = append(o.keys[:i:i], o.keys[i+1:]...)
			break
		}
	}
}

func (o Ordered[V]) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := marshal(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := marshal(o.m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (o *Ordered[V]) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	t, err := dec.Token()
	if err != nil {
		return err
	}
	if d, ok := t.(json.Delim); !ok || d != '{' {
		return errors.New("expected an object")
	}
	*o = Ordered[V]{m: map[string]V{}}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		k, _ := t.(string)
		if o.Has(k) {
			return fmt.Errorf("duplicate key %q", k)
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		var v V
		if err := decodeStrict(raw, &v); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		o.Set(k, v)
	}
	_, err = dec.Token()
	return err
}

// decodeStrict decodes one JSON value and rejects unknown fields, so a typo such as "requird" is an error.
func decodeStrict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	if err := dec.Decode(v); err != nil {
		return cleanJSONError(err)
	}
	if dec.More() {
		return errors.New("unexpected data after the JSON value")
	}
	return nil
}

func cleanJSONError(err error) error {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		if te.Field != "" {
			return fmt.Errorf("%s: expected %s, got JSON %s", te.Field, jsonTypeName(te.Type.Kind().String()), te.Value)
		}
		return fmt.Errorf("expected %s, got JSON %s", jsonTypeName(te.Type.Kind().String()), te.Value)
	}
	return errors.New(strings.TrimPrefix(err.Error(), "json: "))
}

func jsonTypeName(kind string) string {
	switch kind {
	case "string":
		return "a string"
	case "bool":
		return "true or false"
	case "slice":
		return "an array"
	case "struct", "map":
		return "an object"
	case "int", "int64", "float64":
		return "a number"
	}
	return kind
}

// marshal encodes without escaping <, > and &, so URLs stay readable.
func marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// marshalFile encodes a file body: two-space indent and a trailing newline.
func marshalFile(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func compactJSON(b []byte) []byte {
	var buf bytes.Buffer
	if err := json.Compact(&buf, b); err != nil {
		return b
	}
	return buf.Bytes()
}
