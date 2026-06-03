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
import json
import os
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
        head=_decorator_factory, delete=_decorator_factory,
        patch=_decorator_factory, on_event=_decorator_factory,
    )
    fa.Request = object
    fa.Response = lambda *a, **k: None
    fa.HTTPException = Exception
    far = sys.modules["fastapi.responses"]
    far.JSONResponse = lambda *a, **k: (a[0] if a else None)
    far.PlainTextResponse = lambda *a, **k: (a[0] if a else None)
    sys.modules["clickhouse_driver"].Client = object

    # main.py does `import geo`; make the connector directory importable.
    here = os.path.dirname(os.path.abspath(__file__))
    if here not in sys.path:
        sys.path.insert(0, here)

    spec = importlib.util.spec_from_file_location(
        "qpot_ch_main",
        os.path.join(here, "main.py"),
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


class TestAttackMap(unittest.TestCase):
    """The T-Pot attack map's actual queries and the hit shape it reads."""

    def test_grouped_query_string_to_in(self):
        # The map's main selector: type:(Cowrie OR Dionaea OR Heralding)
        cond = main.query_string_to_condition("type:(Cowrie OR Dionaea OR Heralding)")
        # type -> honeypot, case-insensitive IN, lowercased values.
        self.assertEqual(
            cond, "lower(honeypot) IN ('cowrie', 'dionaea', 'heralding')")
        assert_no_structural_injection(f"WHERE {cond}")

    def test_query_string_case_insensitive_equality(self):
        cond = main.query_string_to_condition("type:Cowrie")
        self.assertEqual(cond, "lower(honeypot) = lower('Cowrie')")

    def test_grouped_query_string_injection_trapped(self):
        cond = main.query_string_to_condition("type:(Cowrie OR x') OR 1=1 --)")
        assert_no_structural_injection(f"SELECT * FROM events WHERE {cond}")

    def test_full_attack_map_query_builds_safe_sql(self):
        es_query = {
            "query": {
                "bool": {
                    "must": [{"query_string": {"query": "type:(Cowrie OR Dionaea)"}}],
                    "filter": [{"range": {"@timestamp": {"gte": "now-1m", "lte": "now"}}}],
                }
            }
        }
        sql = main.build_ch_query("logstash-*", es_query, size=100)
        self.assertIn("FROM events", sql)
        self.assertIn("lower(honeypot) IN", sql)
        self.assertIn("timestamp >=", sql)
        assert_no_structural_injection(sql)

    def test_hit_shape_has_geo_for_attack_map(self):
        # A row mirroring SELECT * FROM events.
        columns = ["timestamp", "honeypot", "source_ip", "source_port",
                   "dest_port", "event_type", "country", "city"]
        from datetime import datetime
        row = (datetime(2026, 6, 2, 12, 0, 0), "cowrie", "203.0.113.7",
               54321, 22, "login", "US", "Ashburn")
        hit = main.ch_row_to_es_hit(row, columns)
        src = hit["_source"]
        self.assertEqual(src["type"], "Cowrie")           # capitalized honeypot
        self.assertEqual(src["src_ip"], "203.0.113.7")
        self.assertEqual(src["dest_port"], 22)
        geoip = src["geoip"]
        self.assertEqual(geoip["country_code2"], "US")
        self.assertEqual(geoip["country_name"], "United States")
        # Latitude/longitude derived from the country centroid so the map plots.
        self.assertAlmostEqual(geoip["latitude"], 37.09, places=1)
        self.assertAlmostEqual(geoip["longitude"], -95.71, places=1)
        self.assertEqual(geoip["location"], {"lat": geoip["latitude"], "lon": geoip["longitude"]})

    def test_time_range_now_resolves(self):
        # Regression: the attack map sends lte:"now"; it must become a real
        # timestamp, not the literal SQL `<= 'now'` (which ClickHouse rejects).
        where = main.es_query_to_ch_where(
            {"bool": {"filter": [{"range": {"@timestamp": {"gte": "now-1m", "lte": "now"}}}]}})
        self.assertNotIn("'now'", where)
        self.assertNotIn("now-", where)
        # Both bounds present as quoted timestamps.
        self.assertIn("timestamp >=", where)
        self.assertIn("timestamp <=", where)
        self.assertRegex(where, r"timestamp <= '\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'")

    def test_resolve_time_value_forms(self):
        import re as _re
        ts = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$"
        self.assertRegex(main.resolve_time_value("now"), ts)
        self.assertRegex(main.resolve_time_value("now-2h"), ts)
        # ISO with T/Z is normalized to a ClickHouse-friendly form.
        self.assertEqual(main.resolve_time_value("2026-06-02T19:30:00Z"), "2026-06-02 19:30:00")
        self.assertEqual(main.resolve_time_value("2026-06-02T19:30:00.123+00:00"), "2026-06-02 19:30:00")

    def test_hit_shape_unknown_country_has_no_coords(self):
        columns = ["timestamp", "honeypot", "source_ip", "country"]
        from datetime import datetime
        row = (datetime(2026, 6, 2, 12, 0, 0), "dionaea", "10.0.0.1", "unknown")
        hit = main.ch_row_to_es_hit(row, columns)
        # No bogus (0,0) coordinate when geo is unknown.
        self.assertNotIn("geoip", hit["_source"])


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


class TestAggregations(unittest.TestCase):
    """ES aggregation -> ClickHouse GROUP BY translation (Kibana viz)."""

    def plan(self, aggs):
        return main.agg_translate.plan_aggregations(aggs, main.es_field_to_ch, main.ch_quote)

    def test_terms_agg_sql(self):
        p = self.plan({"by_hp": {"terms": {"field": "type", "size": 5}}})
        self.assertIsNotNone(p)
        sql = main.agg_translate.build_agg_sql("events", "1=1", p)
        # type -> honeypot; grouped + ordered by count desc + size limit.
        self.assertIn("honeypot AS b0", sql)
        self.assertIn("count() AS doc_count", sql)
        self.assertIn("GROUP BY b0", sql)
        self.assertIn("LIMIT 5", sql)
        assert_no_structural_injection(sql)

    def test_date_histogram_sql(self):
        p = self.plan({"ot": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}})
        sql = main.agg_translate.build_agg_sql("events", "1=1", p)
        self.assertIn("toStartOfInterval(timestamp, INTERVAL 1 HOUR)", sql)
        self.assertIn("ORDER BY b0 ASC", sql)

    def test_terms_with_metric(self):
        p = self.plan({"by_hp": {"terms": {"field": "type"},
                                 "aggs": {"avg_port": {"avg": {"field": "dest_port"}}}}})
        self.assertEqual(len(p.buckets), 1)
        self.assertEqual(len(p.metrics), 1)
        sql = main.agg_translate.build_agg_sql("events", "1=1", p)
        self.assertIn("avg(dest_port) AS m0", sql)

    def test_nested_terms_plan(self):
        p = self.plan({"by_country": {"terms": {"field": "geoip.country_name"},
                                      "aggs": {"by_hp": {"terms": {"field": "type", "size": 3}}}}})
        self.assertEqual(len(p.buckets), 2)
        self.assertEqual(p.buckets[0].expr, "country")   # geoip.country_name -> country
        self.assertEqual(p.buckets[1].expr, "honeypot")

    def test_three_levels_unsupported(self):
        p = self.plan({"a": {"terms": {"field": "type"},
                             "aggs": {"b": {"terms": {"field": "country"},
                                            "aggs": {"c": {"terms": {"field": "city"}}}}}}})
        self.assertIsNone(p)  # >2 bucket levels -> caller falls back gracefully

    def test_shape_terms_response(self):
        p = self.plan({"by_hp": {"terms": {"field": "type", "size": 5}}})
        cols = ["b0", "doc_count"]
        rows = [("cowrie", 10), ("dionaea", 4)]
        out = main.agg_translate.shape_agg_response(p, rows, cols)
        buckets = out["by_hp"]["buckets"]
        self.assertEqual(buckets[0], {"doc_count": 10, "key": "cowrie"})
        self.assertEqual(buckets[1]["key"], "dionaea")

    def test_shape_metric_only(self):
        p = self.plan({"uniq_ips": {"cardinality": {"field": "src_ip"}}})
        out = main.agg_translate.shape_agg_response(p, [(7,)], ["m0"])
        self.assertEqual(out["uniq_ips"], {"value": 7})


class TestSavedObjects(unittest.TestCase):
    """Kibana system-index document store."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        self.store = main.savedobjects.SavedObjectStore(self.tmp.name)

    def tearDown(self):
        os.remove(self.tmp.name)

    def test_is_system_index(self):
        self.assertTrue(main.savedobjects.is_system_index(".kibana"))
        self.assertTrue(main.savedobjects.is_system_index(".kibana_8.11.0_001"))
        self.assertFalse(main.savedobjects.is_system_index("logstash-*"))
        self.assertFalse(main.savedobjects.is_system_index("events"))

    def test_crud_roundtrip(self):
        r = self.store.index_doc(".kibana", "config:8.11.0", {"type": "config", "buildNum": 1})
        self.assertEqual(r["result"], "created")
        got = self.store.get_doc(".kibana", "config:8.11.0")
        self.assertTrue(got["found"])
        self.assertEqual(got["_source"]["buildNum"], 1)
        self.store.update_doc(".kibana", "config:8.11.0", {"doc": {"buildNum": 2}})
        self.assertEqual(self.store.get_doc(".kibana", "config:8.11.0")["_source"]["buildNum"], 2)
        d = self.store.delete_doc(".kibana", "config:8.11.0")
        self.assertEqual(d["result"], "deleted")
        self.assertFalse(self.store.get_doc(".kibana", "config:8.11.0")["found"])

    def test_create_conflict(self):
        self.store.index_doc(".kibana", "x", {"a": 1}, create=True)
        with self.assertRaises(KeyError):
            self.store.index_doc(".kibana", "x", {"a": 2}, create=True)

    def test_search_term_and_ids(self):
        self.store.index_doc(".kibana", "index-pattern:1", {"type": "index-pattern", "title": "logstash-*"})
        self.store.index_doc(".kibana", "visualization:1", {"type": "visualization", "title": "v"})
        res = self.store.search(".kibana", {"query": {"term": {"type": "index-pattern"}}})
        self.assertEqual(res["hits"]["total"]["value"], 1)
        self.assertEqual(res["hits"]["hits"][0]["_source"]["title"], "logstash-*")
        # ids query
        res = self.store.search(".kibana", {"query": {"ids": {"values": ["visualization:1"]}}})
        self.assertEqual(res["hits"]["total"]["value"], 1)
        # match_all
        self.assertEqual(self.store.search(".kibana", {"query": {"match_all": {}}})["hits"]["total"]["value"], 2)
        self.assertEqual(self.store.count(".kibana", {})["count"], 2)

    def test_persistence(self):
        self.store.index_doc(".kibana", "k", {"v": 1})
        reopened = main.savedobjects.SavedObjectStore(self.tmp.name)
        self.assertTrue(reopened.get_doc(".kibana", "k")["found"])

    def test_versioned_index_canonicalized(self):
        self.store.index_doc(".kibana_8.11.0_001", "a", {"x": 1})
        # readable via the family name too
        self.assertTrue(self.store.get_doc(".kibana", "a")["found"])


class TestAggFuzz(unittest.TestCase):
    """Throw randomized aggregation trees at the planner/SQL builder; it must
    never crash and never emit an injectable SQL fragment."""

    FIELDS = ["type", "honeypot", "geoip.country_name", "dest_port", "src_ip",
              "evil) OR 1=1 --", "@timestamp", "city"]
    METRICS = ["avg", "min", "max", "sum", "cardinality", "value_count"]

    def _rand_agg(self, rnd, depth=0):
        kind = rnd.choice(["terms", "date_histogram", "metric"])
        if kind == "metric" or depth > 2:
            m = rnd.choice(self.METRICS)
            return {rnd.choice(["m1", "m2"]): {m: {"field": rnd.choice(self.FIELDS)}}}
        body = {}
        if kind == "terms":
            body["terms"] = {"field": rnd.choice(self.FIELDS),
                             "size": rnd.choice([5, 10, "bad", -1, 99999])}
        else:
            body["date_histogram"] = {"field": "@timestamp",
                                      "fixed_interval": rnd.choice(["1h", "30m", "1d", "bad", "5"])}
        if rnd.random() < 0.6:
            body["aggs"] = self._rand_agg(rnd, depth + 1)
        return {rnd.choice(["a", "b", "c"]): body}

    def test_fuzz_agg_planner(self):
        rnd = random.Random(7)
        for _ in range(5000):
            tree = self._rand_agg(rnd)
            try:
                p = main.agg_translate.plan_aggregations(tree, main.es_field_to_ch, main.ch_quote)
            except Exception as e:
                self.fail(f"planner crashed on {tree!r}: {e!r}")
            if p is None:
                continue
            try:
                sql = main.agg_translate.build_agg_sql("events", "1=1", p)
            except Exception as e:
                self.fail(f"build_agg_sql crashed on {tree!r}: {e!r}")
            assert_no_structural_injection(sql)


class TestEnrichment(unittest.TestCase):
    """p0f/fatt -> connection enrichment (attacker OS / JA3 joined by IP)."""

    def test_build_enrichment_query(self):
        sql = main.build_enrichment_query(["1.2.3.4", "5.6.7.8"])
        self.assertIn("FROM events", sql)
        self.assertIn("honeypot IN ('p0f', 'fatt')", sql)
        self.assertIn("argMax(command, timestamp)", sql)
        self.assertIn("'1.2.3.4'", sql)
        self.assertIn("GROUP BY source_ip, honeypot", sql)
        assert_no_structural_injection(sql)

    def test_build_enrichment_query_escapes_ips(self):
        # An injection-y "IP" must stay inside its quoted literal.
        sql = main.build_enrichment_query(["x') OR 1=1 --"])
        assert_no_structural_injection(sql)

    def test_apply_enrichment_attaches_os_and_ja3(self):
        hits = [
            {"_source": {"source_ip": "1.1.1.1", "type": "Cowrie"}},
            {"_source": {"source_ip": "2.2.2.2", "type": "Dionaea"}},
            {"_source": {"source_ip": "9.9.9.9", "type": "Heralding"}},
        ]
        emap = {
            "1.1.1.1": {"p0f": "Linux 3.x", "fatt": "769,47-53,..."},
            "2.2.2.2": {"p0f": "Windows NT"},
        }
        main.apply_enrichment(hits, emap)
        self.assertEqual(hits[0]["_source"]["qpot_enrichment"], {"os": "Linux 3.x", "ja3": "769,47-53,..."})
        self.assertEqual(hits[1]["_source"]["qpot_enrichment"], {"os": "Windows NT"})
        # No data for 9.9.9.9 -> no enrichment object.
        self.assertNotIn("qpot_enrichment", hits[2]["_source"])

    def test_fuzz_enrichment_query_ips(self):
        # Source IPs come from stored events (attacker-influenced), so the
        # enrichment query must never let one escape its quoted literal.
        rnd = random.Random(99)
        payloads = ["1.2.3.4", "::1", "x') OR 1=1 --", "'; DROP TABLE events; --",
                    "a\\'b", "", "日本", "' UNION SELECT password FROM events --"]
        for _ in range(3000):
            ips = [rnd.choice(payloads) for _ in range(rnd.randint(1, 4))]
            sql = main.build_enrichment_query(ips)
            assert_no_structural_injection(sql)

    def test_enrichment_fields_in_schema(self):
        self.assertEqual(main.EVENTS_FIELD_TYPES.get("qpot_enrichment.os"), "keyword")
        self.assertEqual(main.EVENTS_FIELD_TYPES.get("qpot_enrichment.ja3"), "keyword")
        # _field_caps exposes them so Kibana can show/aggregate them.
        caps = main._field_caps_payload("logstash-*")["fields"]
        self.assertIn("qpot_enrichment.os", caps)


class TestEndpointRouting(unittest.TestCase):
    """Exercise the real handlers: Kibana system-index ops route to the saved-
    object store (never ClickHouse), and _bulk applies there."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        self.tmp.close()
        self._orig = main.SO
        main.SO = main.savedobjects.SavedObjectStore(self.tmp.name)

    def tearDown(self):
        main.SO = self._orig
        os.remove(self.tmp.name)

    def _req(self, js=None, body=b"", path="/", method="POST"):
        class Req:
            def __init__(s):
                s.url = types.SimpleNamespace(path=path)
                s.method = method

            async def json(s):
                if js is None:
                    raise ValueError("no json")
                return js

            async def body(s):
                return body
        return Req()

    def test_system_index_doc_and_search_route_to_store(self):
        import asyncio
        asyncio.run(main.put_doc(".kibana", "index-pattern:1",
                                 self._req(js={"type": "index-pattern", "title": "logstash-*"},
                                           path="/.kibana/_doc/index-pattern:1")))
        # root version is reported for Kibana's compat check
        root = asyncio.run(main.root())
        self.assertEqual(root["version"]["number"], main.ES_VERSION)
        # search the system index -> served from the store, not ClickHouse
        res = asyncio.run(main.search(".kibana",
                                      self._req(js={"query": {"term": {"type": "index-pattern"}}})))
        self.assertEqual(res["hits"]["total"]["value"], 1)
        self.assertEqual(res["hits"]["hits"][0]["_source"]["title"], "logstash-*")
        # get the doc back
        got = asyncio.run(main.get_doc(".kibana", "index-pattern:1", self._req(path="/.kibana/_doc/index-pattern:1", method="GET")))
        self.assertTrue(got["found"])

    def test_bulk_applies_to_store(self):
        nd = (
            b'{"index":{"_index":".kibana","_id":"a"}}\n'
            b'{"type":"config","buildNum":1}\n'
            b'{"create":{"_index":".kibana","_id":"b"}}\n'
            b'{"type":"dashboard"}\n'
            b'{"delete":{"_index":".kibana","_id":"a"}}\n'
        )
        res = main._process_bulk(nd, None)
        self.assertFalse(res["errors"])
        self.assertEqual(len(res["items"]), 3)
        # 'a' created then deleted; 'b' remains.
        self.assertFalse(main.SO.get_doc(".kibana", "a")["found"])
        self.assertTrue(main.SO.get_doc(".kibana", "b")["found"])

    def test_data_index_write_is_noop(self):
        # Writing to a data index must not raise and must not create a saved obj.
        res = main._process_bulk(b'{"index":{"_index":"logstash-x","_id":"1"}}\n{"a":1}\n', None)
        self.assertFalse(res["errors"])
        self.assertFalse(main.savedobjects.is_system_index("logstash-x"))


class TestDefaultObjects(unittest.TestCase):
    """The auto-provisioned Kibana data view + dashboard."""

    def setUp(self):
        self.objs = main.default_objects.build_saved_objects(main.EVENTS_FIELD_TYPES, main.ES_VERSION)
        self.by_id = {o["_id"]: o["_source"] for o in self.objs}

    def test_has_data_view_config_and_dashboard(self):
        types = [s["type"] for s in self.by_id.values()]
        self.assertIn("index-pattern", types)
        self.assertIn("config", types)
        self.assertIn("dashboard", types)
        self.assertGreaterEqual(types.count("visualization"), 6)

    def test_config_default_index_points_at_data_view(self):
        cfg = next(s for s in self.by_id.values() if s["type"] == "config")
        self.assertEqual(cfg["config"]["defaultIndex"], main.default_objects.INDEX_PATTERN_ID)

    def test_data_view_fields_cover_schema(self):
        ip = self.by_id[f"index-pattern:{main.default_objects.INDEX_PATTERN_ID}"]
        self.assertEqual(ip["index-pattern"]["title"], "logstash-*")
        self.assertEqual(ip["index-pattern"]["timeFieldName"], "@timestamp")
        fields = json.loads(ip["index-pattern"]["fields"])
        names = {f["name"] for f in fields}
        for required in ("@timestamp", "type", "src_ip", "geoip.country_name",
                         "dest_port", "username"):
            self.assertIn(required, names)

    def test_visualizations_reference_the_data_view_and_valid_visstate(self):
        for sid, src in self.by_id.items():
            if src["type"] != "visualization":
                continue
            json.loads(src["visualization"]["visState"])  # valid JSON
            refs = src["references"]
            self.assertTrue(any(r["type"] == "index-pattern" and
                                r["id"] == main.default_objects.INDEX_PATTERN_ID for r in refs),
                            f"{sid} does not reference the data view")

    def test_dashboard_panel_references_resolve(self):
        dash = self.by_id[f"dashboard:{main.default_objects.DASHBOARD_ID}"]
        panels = json.loads(dash["dashboard"]["panelsJSON"])
        refs = {r["name"]: r["id"] for r in dash["references"]}
        viz_ids = {sid.split(":", 1)[1] for sid in self.by_id if sid.startswith("visualization:")}
        self.assertEqual(len(panels), len(refs))
        for p in panels:
            ref_id = refs[p["panelRefName"]]
            self.assertIn(ref_id, viz_ids, f"panel {p['panelRefName']} -> unknown viz {ref_id}")

    def test_seed_if_empty_idempotent(self):
        import tempfile
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False)
        tmp.close()
        try:
            store = main.savedobjects.SavedObjectStore(tmp.name)
            self.assertTrue(store.seed_if_empty(self.objs))
            # the data view is now searchable
            res = store.search(".kibana", {"query": {"term": {"type": "index-pattern"}}})
            self.assertEqual(res["hits"]["total"]["value"], 1)
            n_dash = store.search(".kibana", {"query": {"term": {"type": "dashboard"}}})["hits"]["total"]["value"]
            self.assertEqual(n_dash, 1)
            # second call is a no-op (user edits never clobbered)
            self.assertFalse(store.seed_if_empty(self.objs))
        finally:
            os.remove(tmp.name)

    def test_every_panel_aggregation_is_serviceable(self):
        # Each dashboard panel's aggregation must be one the connector can plan
        # and turn into injection-safe SQL - otherwise the panel would be blank.
        for name, aggdsl in main.default_objects.panel_aggregations().items():
            plan = main.agg_translate.plan_aggregations(aggdsl, main.es_field_to_ch, main.ch_quote)
            self.assertIsNotNone(plan, f"panel {name}: connector cannot plan {aggdsl}")
            sql = main.agg_translate.build_agg_sql("events", "1=1", plan)
            self.assertIn("FROM events", sql)
            assert_no_structural_injection(sql)


if __name__ == "__main__":
    unittest.main(verbosity=2)
