// Package durablejson preserves arbitrary byte strings in internal checkpoints.
// Ordinary UTF-8 records keep their original JSON representation. Native and
// CSV database rows may contain invalid UTF-8, which encoding/json otherwise
// silently replaces and changes an indicator's identity on crash recovery.
package durablejson

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"unicode/utf8"
)

const encoding = "base64-strings-v1"

type envelope struct {
	Encoding string          `json:"_qpot_encoding"`
	Data     json.RawMessage `json:"data"`
}

func Marshal(value any) ([]byte, error) {
	v := reflect.ValueOf(value)
	if !invalidUTF8(v) {
		return json.Marshal(value)
	}
	encoded, err := stringsTransform(v, false)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(encoded.Interface())
	if err != nil {
		return nil, err
	}
	return json.Marshal(envelope{Encoding: encoding, Data: data})
}

func Unmarshal(data []byte, target any) error {
	var record envelope
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	if record.Encoding == "" {
		return json.Unmarshal(data, target)
	}
	if record.Encoding != encoding {
		return fmt.Errorf("unsupported durable JSON encoding %q", record.Encoding)
	}
	v := reflect.ValueOf(target)
	if v.Kind() != reflect.Pointer || v.IsNil() {
		return fmt.Errorf("durable JSON destination must be a non-nil pointer")
	}
	tmp := reflect.New(v.Elem().Type())
	if err := json.Unmarshal(record.Data, tmp.Interface()); err != nil {
		return err
	}
	decoded, err := stringsTransform(tmp.Elem(), true)
	if err != nil {
		return err
	}
	v.Elem().Set(decoded)
	return nil
}

func invalidUTF8(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	switch v.Kind() {
	case reflect.String:
		return !utf8.ValidString(v.String())
	case reflect.Pointer, reflect.Interface:
		if !v.IsNil() {
			return invalidUTF8(v.Elem())
		}
	case reflect.Struct:
		for n := 0; n < v.NumField(); n++ {
			if v.Type().Field(n).IsExported() && invalidUTF8(v.Field(n)) {
				return true
			}
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			if invalidUTF8(iter.Key()) || invalidUTF8(iter.Value()) {
				return true
			}
		}
	case reflect.Slice, reflect.Array:
		// Byte payloads and RawMessage already have lossless JSON encodings.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return false
		}
		for n := 0; n < v.Len(); n++ {
			if invalidUTF8(v.Index(n)) {
				return true
			}
		}
	}
	return false
}

// Transform exported strings, including map keys. Private fields (notably
// time.Time) retain their original representation and standard JSON methods.
// JSON's stable key ordering makes retries byte-for-byte deterministic too.
func stringsTransform(v reflect.Value, decode bool) (reflect.Value, error) {
	if !v.IsValid() {
		return v, nil
	}
	out := reflect.New(v.Type()).Elem()
	out.Set(v)
	switch v.Kind() {
	case reflect.String:
		if decode {
			b, err := base64.StdEncoding.DecodeString(v.String())
			if err != nil {
				return reflect.Value{}, fmt.Errorf("invalid durable JSON string: %w", err)
			}
			out.SetString(string(b))
		} else {
			out.SetString(base64.StdEncoding.EncodeToString([]byte(v.String())))
		}
	case reflect.Pointer:
		if !v.IsNil() {
			x, err := stringsTransform(v.Elem(), decode)
			if err != nil {
				return reflect.Value{}, err
			}
			out = reflect.New(v.Type().Elem())
			out.Elem().Set(x)
		}
	case reflect.Interface:
		if !v.IsNil() {
			x, err := stringsTransform(v.Elem(), decode)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Set(x)
		}
	case reflect.Struct:
		for n := 0; n < v.NumField(); n++ {
			if v.Type().Field(n).IsExported() {
				x, err := stringsTransform(v.Field(n), decode)
				if err != nil {
					return reflect.Value{}, err
				}
				out.Field(n).Set(x)
			}
		}
	case reflect.Map:
		if v.IsNil() {
			break
		}
		out = reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			key, err := stringsTransform(iter.Key(), decode)
			if err != nil {
				return reflect.Value{}, err
			}
			value, err := stringsTransform(iter.Value(), decode)
			if err != nil {
				return reflect.Value{}, err
			}
			if out.MapIndex(key).IsValid() {
				return reflect.Value{}, fmt.Errorf("duplicate decoded durable JSON map key")
			}
			out.SetMapIndex(key, value)
		}
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			break
		}
		if v.Kind() == reflect.Slice {
			if v.IsNil() {
				break
			}
			out = reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		}
		for n := 0; n < v.Len(); n++ {
			x, err := stringsTransform(v.Index(n), decode)
			if err != nil {
				return reflect.Value{}, err
			}
			out.Index(n).Set(x)
		}
	}
	return out, nil
}
