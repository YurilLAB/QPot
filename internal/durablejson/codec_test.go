package durablejson

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
	"time"
)

func TestRoundTripBinaryStringsAndKeys(t *testing.T) {
	type sample struct {
		ID      string
		Keys    map[string]string
		Values  []string
		When    time.Time
		Payload []byte
		Raw     json.RawMessage
		Child   *sample
	}
	in := sample{ID: "a\xff", Keys: map[string]string{"x\xff": "\x80", "x�": "valid"}, Values: []string{"\xc0", "same"}, When: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC), Payload: []byte{0xff, 0}, Raw: json.RawMessage(`{"keep":"raw"}`), Child: &sample{ID: "child", Raw: json.RawMessage(`null`)}}
	data, err := Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	repeat, _ := Marshal(in)
	if !bytes.Equal(data, repeat) {
		t.Fatal("encoding is not deterministic")
	}
	if !json.Valid(data) {
		t.Fatal("not valid JSON")
	}
	var out sample
	if err := Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, out) {
		t.Fatalf("binary strings changed: %#v", out)
	}
	if in.ID != "a\xff" || in.Child.ID != "child" {
		t.Fatal("encoding mutated input")
	}
}
func TestLegacyJSONAndCorruptEncoding(t *testing.T) {
	in := map[string]string{"normal": "value"}
	got, _ := Marshal(in)
	want, _ := json.Marshal(in)
	if !bytes.Equal(got, want) {
		t.Fatal("ordinary JSON changed")
	}
	for _, data := range []string{`{"_qpot_encoding":"unknown","data":{}}`, `{"_qpot_encoding":"base64-strings-v1","data":{"%%%":"bad"}}`} {
		var out map[string]string
		if err := Unmarshal([]byte(data), &out); err == nil {
			t.Fatal("invalid encoding accepted")
		}
	}
}

func FuzzRoundTrip(f *testing.F) {
	f.Add("plain", "key", []byte{0, 255})
	f.Add("root\xff", "key\xfe", []byte("raw"))
	f.Add("root�", "\n\"\\", []byte{})
	f.Fuzz(func(t *testing.T, value, key string, payload []byte) {
		type record struct {
			Value   string
			Keys    map[string]string
			Payload []byte
			List    []string
		}
		in := record{Value: value, Keys: map[string]string{key: value, key + "�": value + "\xff"}, Payload: payload, List: []string{value, key}}
		original := record{Value: value, Keys: map[string]string{key: value, key + "�": value + "\xff"}, Payload: append([]byte{}, payload...), List: []string{value, key}}
		if payload == nil {
			original.Payload = nil
		}
		data, err := Marshal(in)
		if err != nil {
			t.Fatal(err)
		}
		repeat, err := Marshal(in)
		if err != nil || !bytes.Equal(data, repeat) {
			t.Fatal("non-deterministic checkpoint encoding")
		}
		var out record
		if err := Unmarshal(data, &out); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(in, out) {
			t.Fatal("checkpoint changed byte-string identity")
		}
		if !reflect.DeepEqual(in, original) {
			t.Fatal("encoding mutated input")
		}
	})
}
