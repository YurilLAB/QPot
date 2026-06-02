#!/usr/bin/env python3
"""Tests for the QPot ClickHouse-Kibana connector's query translation.

These cover the SQL-safety guarantees: values from Elasticsearch DSL (which are
ultimately attacker-influenced - usernames, source IPs, commands an attacker
sends to a honeypot get indexed and later queried) must never break out of
their SQL string literal, identifiers must never inject, and LIMIT must always
be an integer.

Stdlib only (unittest + random) so it runs without pytest/hypothesis. The
FastAPI/ClickHouse imports in main.py are stubbed so the pure translation
functions can be imported and exercised without the real dependencies.
"""

import importlib.util
import random
import sys
import types
import unittest


def _load_main():
    for mod in ("fastapi", "fastapi.responses", "uvicorn", "clickhouse_driver"):
        sys.modules[mod] = types.ModuleType(mod)
    fa = sys.modules["fastapi"]

    def _decorator_factory(*a, **k):
        def _decorator(fn):
            return fn
        return _decorator

    fa.FastAPI = lambda *a, **k: types.SimpleNamespace(
        get=_decorator_factory, post=_decorator_factory, put=_decorator_factory,
        head=_decorator_factory, on_event=_decorator_factory,
    )
    fa.Request = object
    fa.Response = object
    fa.HTTPException = Exception
    far = sys.modules["fastapi.responses"]
    far.JSONResponse = object
    far.PlainTextResponse = object
    sys.modules["clickhouse_driver"].Client = object

    spec = importlib.util.spec_from_file_location(
        "qpot_ch_main",
        __file__.replace("test_main.py", "main.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


main = _load_main()


def structural_part(sql: str) -> str:
    """Return SQL with the contents of all string literals removed, so the
    remaining text is only the structural part (keywords, identifiers,
    operators). Walks ClickHouse string literals: delimited by ', escaped by \\.
    Raises AssertionError if a literal is left unterminated (unbalanced quotes).
    """
    out = []
    i = 0
    n = len(sql)
    in_str = False
    while i < n:
        c = sql[i]
        if not in_str:
            if c == "'":
                in_str = True
            else:
                out.append(c)
        else:
            if c == "\\":
                i += 2  # skip the escaped char
                continue
            if c == "'":
                in_str = False
        i += 1
    assert not in_str, f"unbalanced/unterminated string literal in SQL: {sql!r}"
    return "".join(out)


# Tokens that, if they appear in the STRUCTURAL part of the SQL (outside any
# string literal), indicate the attacker's payload escaped its literal. These
# are tokens the connector NEVER legitimately emits. Note the connector DOES
# legitimately emit " OR " (its query_string OR feature) and "1=1" (its
# match-all default WHERE), so those are not injection markers.
INJECTION_MARKERS = ["--", "/*", "*/", ";", " UNION ", "DROP", "SLEEP("]


def assert_no_structural_injection(sql: str):
    struct = structural_part(sql).upper()
    for marker in INJECTION_MARKERS:
        assert marker.upper() not in struct, (
            f"injection marker {marker!r} reached SQL structure: {struct!r}\nfull SQL: {sql!r}"
        )


class TestHelpers(unittest.TestCase):
    def test_ch_quote_escapes_quotes(self):
        self.assertEqual(main.ch_quote("O'Brien"), "'O\\'Brien'")

    def test_ch_quote_escapes_backslash(self):
        self.assertEqual(main.ch_quote("a\\b"), "'a\\\\b'")

    def test_ch_quote_numbers_unquoted(self):
        self.assertEqual(main.ch_quote(42), "42")
        self.assertEqual(main.ch_quote(True), "1")

    def test_ch_quote_injection_is_trapped(self):
        out = main.ch_quote("x') OR 1=1 --")
        # The whole payload must be a single quoted literal with the inner
        # quote escaped; nothing escapes to the structural layer.
        self.assertEqual(out, "'x\\') OR 1=1 --'")
        assert_no_structural_injection(f"WHERE col = {out}")

    def test_safe_ident_strips_injection(self):
        self.assertEqual(main.safe_ident("evil) OR 1=1 --"), "evil")
        self.assertEqual(main.safe_ident("src.ip"), "src_ip")
        self.assertEqual(main.safe_ident(""), "timestamp")
        self.assertEqual(main.safe_ident("1abc"), "abc")
        # result is always a bare identifier
        import re
        for probe in ["a;b", "'; DROP", "col-name", "x)("]:
            self.assertRegex(main.safe_ident(probe), r"^[A-Za-z_][A-Za-z0-9_]*$")

    def test_safe_limit(self):
        self.assertEqual(main.safe_limit("10 UNION SELECT"), 10)  # default on non-int
        self.assertEqual(main.safe_limit("50"), 50)
        self.assertEqual(main.safe_limit(-5), 10)
        self.assertEqual(main.safe_limit(10**9), 10000)
        self.assertEqual(main.safe_limit(None), 10)


class TestSchemaMapping(unittest.TestCase):
    """Guard that the connector targets QPot's real ClickHouse schema (the
    `events` table with `source_ip`/`country`/... columns), not the
    non-existent T-Pot logstash schema (honeypot_logs / src_ip / geoip_*) it
    originally assumed - which made every query return nothing."""

    def test_table_is_events(self):
        for index in ("logstash-*", "events", "anything-else"):
            sql = main.build_ch_query(index, {})
            self.assertIn("FROM events", sql, f"index {index!r} -> {sql!r}")
            self.assertNotIn("honeypot_logs", sql)

    def test_field_mappings_match_real_columns(self):
        # Real columns from internal/database/clickhouse.go.
        real = {
            "timestamp", "honeypot", "source_ip", "source_port", "dest_port",
            "protocol", "event_type", "username", "password", "command",
            "payload", "country", "city", "asn", "technique_id",
            "technique_name", "tactic_id", "tactic_name", "kill_chain_stage",
        }
        for es_field, ch_col in main.FIELD_MAPPINGS.items():
            self.assertIn(ch_col, real, f"{es_field!r} maps to unknown column {ch_col!r}")

    def test_es_spellings_resolve(self):
        # The spellings Kibana/attack map actually send must resolve to columns.
        self.assertEqual(main.es_field_to_ch("src_ip"), "source_ip")
        self.assertEqual(main.es_field_to_ch("geoip.country_name"), "country")
        self.assertEqual(main.es_field_to_ch("geoip.ip"), "source_ip")


class TestQueryTranslation(unittest.TestCase):
    def test_apostrophe_value_is_valid_sql(self):
        q = {"bool": {"must": [{"query_string": {"query": "username:O'Brien"}}]}}
        where = main.es_query_to_ch_where(q)
        self.assertEqual(where, "username = 'O\\'Brien'")
        assert_no_structural_injection(f"SELECT * FROM t WHERE {where}")

    def test_terms_injection_trapped(self):
        q = {"bool": {"filter": [{"terms": {"honeypot": ["cowrie", "x') OR 1=1 --"]}}]}}
        where = main.es_query_to_ch_where(q)
        assert_no_structural_injection(f"SELECT * FROM t WHERE {where}")

    def test_build_ch_query_limit_is_int(self):
        sql = main.build_ch_query("logstash-*", {}, size="5; DROP TABLE x")
        # safe_limit rejects the non-int and falls back to default 10
        self.assertIn("LIMIT 10", sql)
        assert_no_structural_injection(sql)


class TestFuzz(unittest.TestCase):
    """Throw randomized, injection-laden ES queries at the translator and
    assert the generated SQL never lets a payload escape a string literal,
    never leaves quotes unbalanced, and never crashes."""

    PAYLOADS = [
        "x", "1.2.3.4", "cowrie",
        "x' OR '1'='1", "x') OR 1=1 --", "'; DROP TABLE honeypot_logs; --",
        "a\\'; DROP", "x' UNION ALL SELECT password FROM users --",
        "O'Brien", "back\\slash", "quote'inside", "/* comment */",
        "\x00\x01", "日本語'", "' OR sleep(5) --", "]}{[",
    ]
    FIELDS = ["src_ip", "username", "honeypot", "evil) OR 1=1 --", "a.b.c",
              "1starts_bad", "weird-field", "qpot_id"]

    def _random_query(self, rnd):
        def val():
            return rnd.choice(self.PAYLOADS)

        def field():
            return rnd.choice(self.FIELDS)

        must = []
        for _ in range(rnd.randint(0, 3)):
            if rnd.random() < 0.5:
                must.append({"query_string": {"query": f"{field()}:{val()}"}})
            else:
                terms = " OR ".join(f"{field()}:{val()}" for _ in range(rnd.randint(1, 3)))
                must.append({"query_string": {"query": terms}})
        filt = []
        for _ in range(rnd.randint(0, 3)):
            kind = rnd.choice(["range", "terms", "exists"])
            if kind == "range":
                filt.append({"range": {field(): {"gte": val(), "lte": val()}}})
            elif kind == "terms":
                filt.append({"terms": {field(): [val() for _ in range(rnd.randint(0, 3))]}})
            else:
                filt.append({"exists": {"field": field()}})
        es = {"query": {"bool": {"must": must, "filter": filt}}}
        if rnd.random() < 0.5:
            es["size"] = rnd.choice([10, "10", "5; DROP", -1, 10**9, None, "abc"])
        if rnd.random() < 0.5:
            es["_source"] = [field() for _ in range(rnd.randint(1, 3))]
        if rnd.random() < 0.5:
            es["sort"] = [{field(): {"order": rnd.choice(["asc", "desc", "'; DROP"])}}]
        return es

    def test_fuzz_translation(self):
        rnd = random.Random(1337)
        for i in range(20000):
            es = self._random_query(rnd)
            try:
                where = main.es_query_to_ch_where(es["query"])
                sql = main.build_ch_query("logstash-*", es, size=es.get("size", 10))
            except Exception as e:  # robustness: must not crash on any input
                self.fail(f"translation crashed on {es!r}: {e!r}")
            # Structural-injection + balanced-quote oracle on both outputs.
            assert_no_structural_injection(f"SELECT * FROM t WHERE {where}")
            assert_no_structural_injection(sql)
            # LIMIT is always an integer literal.
            limit_line = [l for l in sql.splitlines() if "LIMIT" in l]
            self.assertTrue(limit_line, sql)
            int(limit_line[0].strip().split()[-1])  # raises if not an int


if __name__ == "__main__":
    unittest.main(verbosity=2)
