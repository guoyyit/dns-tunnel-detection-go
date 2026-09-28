package config

import (
	"bytes"
	"encoding/json"
	"os"
)

// LoadFile reads a JSON configuration file. An empty path returns defaults.
// Unknown fields are rejected to catch configuration typos.
func LoadFile(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return Default(), err
	}
	return cfg, nil
}
