package config

import (
	"fmt"
	"maps"

	"gopkg.in/yaml.v3"
)

// SetHoneypotCustomConfig replaces one configured honeypot's custom_config
// under the honeypot lock, so it is safe while the web server reads the
// config. It reports false (and changes nothing) for a honeypot the config
// does not have.
func (c *Config) SetHoneypotCustomConfig(name string, custom map[string]string) bool {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	hp, ok := c.Honeypots[name]
	if !ok {
		return false
	}
	hp.CustomConfig = maps.Clone(custom)
	c.Honeypots[name] = hp
	return true
}

// ReplaceHoneypots makes the honeypot settings those of hps (a snapshot of
// another Config, such as the config file as it is now), under the honeypot
// lock.
func (c *Config) ReplaceHoneypots(hps map[string]HoneypotConfig) {
	c.hpMu.Lock()
	defer c.hpMu.Unlock()
	c.Honeypots = make(map[string]HoneypotConfig, len(hps))
	for name, hp := range hps {
		hp.CustomConfig = maps.Clone(hp.CustomConfig)
		hp.Environment = maps.Clone(hp.Environment)
		c.Honeypots[name] = hp
	}
}

// Clone returns an independent copy of the config, as Parse would read it
// back from the file Save writes.
func (c *Config) Clone() (*Config, error) {
	c.hpMu.RLock()
	data, err := yaml.Marshal(c)
	c.hpMu.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to copy config: %w", err)
	}
	return Parse(data, c.ConfigPath)
}
