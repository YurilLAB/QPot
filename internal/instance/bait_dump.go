package instance

// bait_dump.go: the database dump root made before an upgrade (see bait.go).
// A dump of the internal application's database as mysqldump 8.0 or pg_dump
// 14 write it: its users with their password hashes, its settings with the
// SMTP relay's password (a canary), and an audit log that gives it the size of
// a database in use. Timestamps are {{date:...|OFFSET}} placeholders before
// the dump's own time, which only the running persona knows.

import (
	"fmt"
	"strings"
)

// The server versions the dumps name: releases of early 2023, older than any
// time a persona places the dump at.
const (
	baitMySQLVersion    = "8.0.32"
	baitPostgresVersion = "14.7"
)

type baitUser struct {
	ID                          int
	Login, Name, Role, Hash     string
	Active                      bool
	CreatedOff, LastLoginOffset int // seconds before the dump; LastLoginOffset 0: never
}

type baitAudit struct {
	ID, User int
	Action   string
	IP       string
	Off      int
}

type baitKV struct{ Key, Value string }

// bcryptChars is the alphabet of a bcrypt hash.
const bcryptChars = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func (s *baitScene) dumpData() ([]baitUser, []baitKV, []baitAudit) {
	st := s.d.Stream("dump-users")
	n := 18 + st.Intn(20)
	seen := map[string]bool{}
	var users []baitUser
	for i := 0; len(users) < n; i++ {
		first, last := s.admin.First, s.admin.Last
		if i > 0 {
			first, last = baitFirst[st.Intn(len(baitFirst))], baitLast[st.Intn(len(baitLast))]
		}
		login := first + "." + last
		if seen[login] {
			continue
		}
		seen[login] = true
		role := []string{"agent", "agent", "agent", "staff", "staff", "viewer"}[st.Intn(6)]
		if len(users) < 2 {
			role = "admin"
		}
		u := baitUser{ID: len(users) + 1, Login: login, Name: title(first) + " " + title(last), Role: role,
			Hash:       "$2y$10$" + st.Chars(53, bcryptChars),
			Active:     st.Intn(10) < 8,
			CreatedOff: 86400 * (30 + st.Intn(670))}
		if u.Active {
			u.LastLoginOffset = 3600 + st.Intn(20*86400)
		}
		users = append(users, u)
	}
	settings := []baitKV{
		{"app.name", title(s.dbName)},
		{"app.url", "https://" + s.dbName + "." + s.domain},
		{"mail.from", s.dbName + "@" + s.domain},
		{"mail.host", "smtp." + s.domain},
		{"mail.password", s.smtpPass},
		{"mail.port", "587"},
		{"mail.username", s.dbName + "@" + s.domain},
		{"session.lifetime", "120"},
	}
	at := s.d.Stream("dump-audit")
	actions := []string{"login", "login", "login", "logout", "record.create", "record.update", "record.update",
		"comment.add", "export.csv", "password.change", "settings.view"}
	office := fmt.Sprintf("192.168.%d", 1+at.Intn(254))
	if at.Intn(2) == 0 {
		office = fmt.Sprintf("10.%d.%d", at.Intn(255), at.Intn(255))
	}
	rows := 1500 + at.Intn(1500)
	span := 86400 * (180 + at.Intn(180))
	audit := make([]baitAudit, rows)
	for i := range audit {
		// oldest first, the last ones hours before the dump
		off := span - span*i/rows - at.Intn(span/rows+1)
		if off < 600 {
			off = 600 + at.Intn(3000)
		}
		audit[i] = baitAudit{ID: i + 1, User: 1 + at.Intn(len(users)), Action: actions[at.Intn(len(actions))],
			IP: fmt.Sprintf("%s.%d", office, 2+at.Intn(250)), Off: off}
	}
	return users, settings, audit
}

// dumpTime is the placeholder of a timestamp off seconds before the dump.
func dumpTime(off int) string {
	return fmt.Sprintf("{{date:%%Y-%%m-%%d %%H:%%M:%%S|-%d}}", off)
}

// sqlEscape escapes a quoted value as mysqldump does.
var sqlEscape = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// sqlQuote quotes a value as mysqldump does (the values here hold no quote
// or backslash).
func sqlQuote(v string) string {
	return "'" + sqlEscape.Replace(v) + "'"
}

func (s *baitScene) dumpFile() {
	users, settings, audit := s.dumpData()
	var text string
	if s.engine == "mysql" {
		text = s.mysqlDump(users, settings, audit)
	} else {
		text = s.pgDump(users, settings, audit)
	}
	s.file(baitFile{ID: "dump", Path: s.dumpPath, Owner: "root", Mode: 0o644, At: s.at("dump", 0.55, 0.85),
		Gzip: true, Text: text})
}

func (s *baitScene) mysqlDump(users []baitUser, settings []baitKV, audit []baitAudit) string {
	var b strings.Builder
	fmt.Fprintf(&b, "-- MySQL dump 10.13  Distrib %s, for Linux (x86_64)\n--\n-- Host: localhost    Database: %s\n"+
		"-- ------------------------------------------------------\n-- Server version\t%s\n\n", baitMySQLVersion, s.dbName, baitMySQLVersion)
	b.WriteString(`/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;
`)
	table := func(name, create string, rows []string, next int) {
		fmt.Fprintf(&b, "\n--\n-- Table structure for table `%s`\n--\n\nDROP TABLE IF EXISTS `%s`;\n"+
			"/*!40101 SET @saved_cs_client     = @@character_set_client */;\n/*!50503 SET character_set_client = utf8mb4 */;\n"+
			"CREATE TABLE `%s` (\n%s\n) ENGINE=InnoDB", name, name, name, create)
		if next > 0 {
			fmt.Fprintf(&b, " AUTO_INCREMENT=%d", next)
		}
		fmt.Fprintf(&b, " DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;\n/*!40101 SET character_set_client = @saved_cs_client */;\n"+
			"\n--\n-- Dumping data for table `%s`\n--\n\nLOCK TABLES `%s` WRITE;\n/*!40000 ALTER TABLE `%s` DISABLE KEYS */;\n",
			name, name, name)
		fmt.Fprintf(&b, "INSERT INTO `%s` VALUES %s;\n", name, strings.Join(rows, ","))
		fmt.Fprintf(&b, "/*!40000 ALTER TABLE `%s` ENABLE KEYS */;\nUNLOCK TABLES;\n", name)
	}
	var rows []string
	for _, a := range audit {
		rows = append(rows, fmt.Sprintf("(%d,%d,%s,%s,%s)", a.ID, a.User, sqlQuote(a.Action), sqlQuote(a.IP), sqlQuote(dumpTime(a.Off))))
	}
	table("audit_log", "  `id` bigint unsigned NOT NULL AUTO_INCREMENT,\n  `user_id` int unsigned NOT NULL,\n"+
		"  `action` varchar(64) NOT NULL,\n  `ip` varchar(45) DEFAULT NULL,\n  `created_at` datetime NOT NULL,\n"+
		"  PRIMARY KEY (`id`),\n  KEY `audit_log_user_id_index` (`user_id`)", rows, len(audit)+1)
	rows = rows[:0]
	for _, kv := range settings {
		rows = append(rows, fmt.Sprintf("(%s,%s)", sqlQuote(kv.Key), sqlQuote(kv.Value)))
	}
	table("settings", "  `key` varchar(191) NOT NULL,\n  `value` text,\n  PRIMARY KEY (`key`)", rows, 0)
	rows = rows[:0]
	for _, u := range users {
		last := "NULL"
		if u.LastLoginOffset > 0 {
			last = sqlQuote(dumpTime(u.LastLoginOffset))
		}
		active := 0
		if u.Active {
			active = 1
		}
		rows = append(rows, fmt.Sprintf("(%d,%s,%s,%s,%s,%d,%s,%s)", u.ID, sqlQuote(u.Login), sqlQuote(u.Name),
			sqlQuote(u.Role), sqlQuote(u.Hash), active, sqlQuote(dumpTime(u.CreatedOff)), last))
	}
	table("users", "  `id` int unsigned NOT NULL AUTO_INCREMENT,\n  `username` varchar(64) NOT NULL,\n"+
		"  `full_name` varchar(128) NOT NULL,\n  `role` varchar(16) NOT NULL DEFAULT 'agent',\n"+
		"  `password` varchar(255) NOT NULL,\n  `is_active` tinyint(1) NOT NULL DEFAULT '1',\n"+
		"  `created_at` datetime NOT NULL,\n  `last_login_at` datetime DEFAULT NULL,\n  PRIMARY KEY (`id`),\n"+
		"  UNIQUE KEY `users_username_unique` (`username`)", rows, len(users)+1)
	b.WriteString(`/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

`)
	// mysqldump pads the hour with a space
	b.WriteString("-- Dump completed on {{date:%Y-%m-%d %k:%M:%S}}\n")
	return b.String()
}

func (s *baitScene) pgDump(users []baitUser, settings []baitKV, audit []baitAudit) string {
	owner := s.dbName
	var b strings.Builder
	fmt.Fprintf(&b, "--\n-- PostgreSQL database dump\n--\n\n-- Dumped from database version %s\n-- Dumped by pg_dump version %s\n\n",
		baitPostgresVersion, baitPostgresVersion)
	b.WriteString(`SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;
`)
	type col struct{ name, typ string }
	tables := []struct {
		name string
		cols []col
		seq  bool
	}{
		{"audit_log", []col{{"id", "bigint NOT NULL"}, {"user_id", "integer NOT NULL"}, {"action", "character varying(64) NOT NULL"},
			{"ip", "inet"}, {"created_at", "timestamp without time zone NOT NULL"}}, true},
		{"settings", []col{{"key", "character varying(191) NOT NULL"}, {"value", "text"}}, false},
		{"users", []col{{"id", "integer NOT NULL"}, {"username", "character varying(64) NOT NULL"},
			{"full_name", "character varying(128) NOT NULL"}, {"role", "character varying(16) DEFAULT 'agent'::character varying NOT NULL"},
			{"password", "character varying(255) NOT NULL"}, {"is_active", "boolean DEFAULT true NOT NULL"},
			{"created_at", "timestamp without time zone NOT NULL"}, {"last_login_at", "timestamp without time zone"}}, true},
	}
	for _, t := range tables {
		fmt.Fprintf(&b, "\n--\n-- Name: %s; Type: TABLE; Schema: public; Owner: %s\n--\n\nCREATE TABLE public.%s (\n", t.name, owner, t.name)
		for i, c := range t.cols {
			sep := ","
			if i == len(t.cols)-1 {
				sep = ""
			}
			fmt.Fprintf(&b, "    %s %s%s\n", c.name, c.typ, sep)
		}
		fmt.Fprintf(&b, ");\n\n\nALTER TABLE public.%s OWNER TO %s;\n", t.name, owner)
		if t.seq {
			typ := "integer"
			if t.name == "audit_log" {
				typ = ""
			}
			fmt.Fprintf(&b, "\n--\n-- Name: %s_id_seq; Type: SEQUENCE; Schema: public; Owner: %s\n--\n\nCREATE SEQUENCE public.%s_id_seq\n", t.name, owner, t.name)
			if typ != "" {
				fmt.Fprintf(&b, "    AS %s\n", typ)
			}
			fmt.Fprintf(&b, "    START WITH 1\n    INCREMENT BY 1\n    NO MINVALUE\n    NO MAXVALUE\n    CACHE 1;\n\n\n"+
				"ALTER TABLE public.%s_id_seq OWNER TO %s;\n\n--\n-- Name: %s_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: %s\n--\n\n"+
				"ALTER SEQUENCE public.%s_id_seq OWNED BY public.%s.id;\n", t.name, owner, t.name, owner, t.name, t.name)
		}
	}
	for _, t := range tables {
		if t.seq {
			fmt.Fprintf(&b, "\n\n--\n-- Name: %s id; Type: DEFAULT; Schema: public; Owner: %s\n--\n\n"+
				"ALTER TABLE ONLY public.%s ALTER COLUMN id SET DEFAULT nextval('public.%s_id_seq'::regclass);\n", t.name, owner, t.name, t.name)
		}
	}
	data := func(name string, cols string, rows []string) {
		fmt.Fprintf(&b, "\n\n--\n-- Data for Name: %s; Type: TABLE DATA; Schema: public; Owner: %s\n--\n\nCOPY public.%s (%s) FROM stdin;\n",
			name, owner, name, cols)
		for _, r := range rows {
			b.WriteString(r + "\n")
		}
		b.WriteString("\\.\n")
	}
	var rows []string
	for _, a := range audit {
		rows = append(rows, fmt.Sprintf("%d\t%d\t%s\t%s\t%s", a.ID, a.User, a.Action, a.IP, dumpTime(a.Off)))
	}
	data("audit_log", "id, user_id, action, ip, created_at", rows)
	rows = rows[:0]
	for _, kv := range settings {
		rows = append(rows, kv.Key+"\t"+kv.Value)
	}
	data("settings", "key, value", rows)
	rows = rows[:0]
	for _, u := range users {
		last := `\N`
		if u.LastLoginOffset > 0 {
			last = dumpTime(u.LastLoginOffset)
		}
		active := "f"
		if u.Active {
			active = "t"
		}
		rows = append(rows, fmt.Sprintf("%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s", u.ID, u.Login, u.Name, u.Role, u.Hash, active,
			dumpTime(u.CreatedOff), last))
	}
	data("users", "id, username, full_name, role, password, is_active, created_at, last_login_at", rows)
	for _, t := range []struct {
		name string
		last int
	}{{"audit_log", len(audit)}, {"users", len(users)}} {
		fmt.Fprintf(&b, "\n\n--\n-- Name: %s_id_seq; Type: SEQUENCE SET; Schema: public; Owner: %s\n--\n\n"+
			"SELECT pg_catalog.setval('public.%s_id_seq', %d, true);\n", t.name, owner, t.name, t.last)
	}
	for _, t := range []struct{ name, key string }{{"audit_log", "id"}, {"settings", "key"}, {"users", "id"}} {
		fmt.Fprintf(&b, "\n\n--\n-- Name: %s %s_pkey; Type: CONSTRAINT; Schema: public; Owner: %s\n--\n\n"+
			"ALTER TABLE ONLY public.%s\n    ADD CONSTRAINT %s_pkey PRIMARY KEY (%s);\n", t.name, t.name, owner, t.name, t.name, t.key)
	}
	b.WriteString("\n\n--\n-- PostgreSQL database dump complete\n--\n\n")
	return b.String()
}
