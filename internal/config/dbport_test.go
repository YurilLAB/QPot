package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeCompose writes the instance's compose file.
func writeCompose(t *testing.T, c *Config, body string) {
	t.Helper()
	if err := os.MkdirAll(c.DataPath, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(c.GetDockerComposePath(), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestDatabaseHostPortReadsOwnComposeFile: the client dials the port the
// instance's own compose file publishes the database's container port on,
// and the derived default when the file has none.
func TestDatabaseHostPortReadsOwnComposeFile(t *testing.T) {
	c := Default("dbport")
	c.DataPath = filepath.Join(t.TempDir(), "dbport")
	def := c.DefaultDatabaseHostPort()
	if got := c.DatabaseHostPort(); got != def {
		t.Fatalf("no compose file: %d, want the default %d", got, def)
	}
	cases := []struct {
		dbType, body string
		want         int
	}{
		{"clickhouse", "services:\n  database:\n    ports:\n      - \"127.0.0.1:12345:9000\"\n", 12345},
		{"clickhouse", "services:\n  database:\n    ports:\n      - \"[::1]:12346:9000\"\n", 12346},
		{"timescaledb", "services:\n  database:\n    ports:\n      - \"127.0.0.1:12347:5432\"\n", 12347},
		// Another container port (the type changed since it was rendered).
		{"timescaledb", "services:\n  database:\n    ports:\n      - \"127.0.0.1:12348:9000\"\n", 0},
		// Another service's port, no host port, out of range, not YAML.
		{"clickhouse", "services:\n  cowrie:\n    ports:\n      - \"12349:9000\"\n", 0},
		{"clickhouse", "services:\n  database:\n    ports:\n      - \"9000\"\n", 0},
		{"clickhouse", "services:\n  database:\n    ports:\n      - \"127.0.0.1:70000:9000\"\n", 0},
		{"clickhouse", "services: [", 0},
	}
	for _, tc := range cases {
		c.Database.Type = tc.dbType
		writeCompose(t, c, tc.body)
		want := tc.want
		if want == 0 {
			want = c.DefaultDatabaseHostPort()
		}
		if got := c.DatabaseHostPort(); got != want {
			t.Errorf("%s %q: %d, want %d", tc.dbType, tc.body, got, want)
		}
		if got := c.DatabaseClient().Port; got != want {
			t.Errorf("%s %q: the client dials %d, want %d", tc.dbType, tc.body, got, want)
		}
	}

	// Without a data path there is no compose file to read: one in the
	// working directory is someone else's.
	c.Database.Type = "clickhouse"
	c.DataPath = ""
	t.Chdir(t.TempDir())
	if err := os.WriteFile("docker-compose.yml", []byte("services:\n  database:\n    ports:\n      - \"127.0.0.1:12350:9000\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := c.DatabaseHostPort(); got != c.DefaultDatabaseHostPort() {
		t.Errorf("no data path: %d read from the working directory, want the default %d", got, c.DefaultDatabaseHostPort())
	}
}

// FuzzDatabaseHostPort: whatever the compose file holds, reading it back
// neither panics nor gives anything but a valid TCP port.
func FuzzDatabaseHostPort(f *testing.F) {
	f.Add("services:\n  database:\n    ports:\n      - \"127.0.0.1:19000:9000\"\n", false)
	f.Add("services:\n  database:\n    ports:\n      - \"0:9000\"\n      - \":5432\"\n", true)
	f.Add("services:\n  database:\n    ports: 9000\n", false)
	f.Add("\x00", true)
	c := Default("fuzz")
	c.DataPath = f.TempDir()
	f.Fuzz(func(t *testing.T, body string, timescale bool) {
		c.Database.Type = "clickhouse"
		if timescale {
			c.Database.Type = "timescaledb"
		}
		if err := os.WriteFile(c.GetDockerComposePath(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if p := c.DatabaseHostPort(); p < 1 || p > 65535 {
			t.Fatalf("port %d from %q", p, body)
		}
	})
}
