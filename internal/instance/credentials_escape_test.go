package instance

import (
	"net/url"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/qpot/qpot/internal/config"
	"github.com/qpot/qpot/internal/security"
)

// Operator-chosen database credentials can contain characters that are
// significant to YAML, to docker compose / Vector interpolation ($) and to URLs.
// They must reach every consumer unchanged.
func TestDatabaseCredentialsAreEscaped(t *testing.T) {
	hostile := []string{"!Secr3t", "p@ss: word #1", `a"b\c`, "abc$HOME", "x/y?z#w", "&anchor", "it's"}
	for _, dbType := range []string{"clickhouse", "timescaledb"} {
		for _, pw := range hostile {
			cfg := config.Default("esc-test")
			cfg.QPotID = "qp_escapetest0000000000001"
			cfg.Database.Type = dbType
			cfg.Database.Username = "qpot user"
			cfg.Database.Password = pw

			var compose struct {
				Services map[string]struct {
					Environment interface{} `yaml:"environment"`
					Healthcheck struct {
						Test []string `yaml:"test"`
					} `yaml:"healthcheck"`
				} `yaml:"services"`
			}
			out := renderComposeCfg(t, cfg)
			if err := yaml.Unmarshal([]byte(out), &compose); err != nil {
				t.Fatalf("%s %q: compose is not valid YAML: %v", dbType, pw, err)
			}
			env := map[string]string{}
			if m, ok := compose.Services["database"].Environment.(map[string]interface{}); ok {
				for k, v := range m {
					env[k], _ = v.(string)
				}
			}
			wantPw := strings.ReplaceAll(pw, "$", "$$") // compose turns $$ back into $
			gotPw, gotUser := env["CLICKHOUSE_PASSWORD"], env["CLICKHOUSE_USER"]
			if dbType == "timescaledb" {
				gotPw, gotUser = env["POSTGRES_PASSWORD"], env["POSTGRES_USER"]
				hc := compose.Services["database"].Healthcheck.Test
				if len(hc) != 2 || hc[1] != "pg_isready -U 'qpot user' -d 'qpot'" {
					t.Errorf("healthcheck = %q", hc)
				}
			}
			if gotPw != wantPw || gotUser != "qpot user" {
				t.Errorf("%s %q: compose env user=%q password=%q", dbType, pw, gotUser, gotPw)
			}

			vec, err := (&ComposeGenerator{Config: cfg, Sandbox: mustSandbox(t, cfg)}).GenerateVectorConfig()
			if err != nil {
				t.Fatal(err)
			}
			var v struct {
				Sinks map[string]struct {
					Endpoint string `yaml:"endpoint"`
					Auth     struct {
						User     string `yaml:"user"`
						Password string `yaml:"password"`
					} `yaml:"auth"`
				} `yaml:"sinks"`
			}
			if err := yaml.Unmarshal([]byte(vec), &v); err != nil {
				t.Fatalf("%s %q: vector.yaml is not valid YAML: %v", dbType, pw, err)
			}
			if dbType == "clickhouse" {
				a := v.Sinks["clickhouse"].Auth
				if a.Password != wantPw || a.User != "qpot user" {
					t.Errorf("vector clickhouse auth = %+v", a)
				}
			} else {
				dsn := strings.ReplaceAll(v.Sinks["timescaledb"].Endpoint, "$$", "$")
				u, err := url.Parse(dsn)
				if err != nil {
					t.Fatalf("vector DSN %q: %v", dsn, err)
				}
				p, _ := u.User.Password()
				if u.User.Username() != "qpot user" || p != pw || u.Host != "database:5432" || u.Path != "/qpot" {
					t.Errorf("vector DSN %q decodes to user=%q pw=%q host=%q path=%q", dsn, u.User.Username(), p, u.Host, u.Path)
				}
			}
		}
	}
}

func mustSandbox(t *testing.T, cfg *config.Config) *security.Sandbox {
	t.Helper()
	sb, err := security.NewSandbox(&cfg.Security)
	if err != nil {
		t.Fatal(err)
	}
	return sb
}
