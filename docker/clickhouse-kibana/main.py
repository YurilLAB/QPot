#!/usr/bin/env python3
"""
QPot ClickHouse-Kibana Connector
Translates Elasticsearch API calls to ClickHouse queries for Kibana compatibility
"""

import json
import re
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse, parse_qs

import geo
import aggs as agg_translate
import savedobjects
import default_objects

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
import uvicorn
import clickhouse_driver
from clickhouse_driver import Client as ClickHouseClient

# Configuration
CH_HOST = os.getenv("CLICKHOUSE_HOST", "clickhouse")
CH_PORT = int(os.getenv("CLICKHOUSE_PORT", "9000"))
CH_DATABASE = os.getenv("CLICKHOUSE_DATABASE", "qpot")
CH_USER = os.getenv("CLICKHOUSE_USER", "default")
CH_PASSWORD = os.getenv("CLICKHOUSE_PASSWORD", "")

# QPot Configuration
QPOT_ID = os.getenv("QPOT_ID", "")
QPOT_INSTANCE = os.getenv("QPOT_INSTANCE", "")

# The Elasticsearch version reported to Kibana. Kibana refuses to start against
# an ES whose major version differs from its own, so this must match the bundled
# Kibana (override with ES_VERSION to track the image).
ES_VERSION = os.getenv("ES_VERSION", "8.11.0")
CLUSTER_UUID = os.getenv("QPOT_CLUSTER_UUID", "qpot-clickhouse-0000000000")

app = FastAPI(title="QPot ClickHouse-Kibana Connector")

# File-backed store for Kibana's own system indices (.kibana*). Kibana reads and
# writes its saved objects there; those documents are Kibana's, not honeypot
# data, so they are kept out of ClickHouse.
SO = savedobjects.SavedObjectStore(os.getenv("QPOT_SO_PATH", "/data/kibana-objects.json"))

# ClickHouse client
ch_client: Optional[ClickHouseClient] = None

# The single ClickHouse table QPot writes events to (see
# internal/database/clickhouse.go: CREATE TABLE events). Every ES index pattern
# resolves to it.
EVENTS_TABLE = "events"

# Index pattern mappings. Kibana/the attack map query "logstash-*"; QPot stores
# everything in the `events` table.
INDEX_PATTERNS = {
    "logstash-*": EVENTS_TABLE,
    "*:logstash-*": EVENTS_TABLE,
    "events": EVENTS_TABLE,
}

# Field mappings from Elasticsearch field names to QPot's ClickHouse columns.
# These MUST match the real `events` schema in internal/database/clickhouse.go
# (timestamp, honeypot, source_ip, source_port, dest_port, protocol,
# event_type, username, password, command, payload, country, city, asn,
# technique_*). The previous mapping targeted a non-existent T-Pot/logstash
# schema (honeypot_logs / src_ip / geoip_*), so no query returned data.
FIELD_MAPPINGS = {
    "@timestamp": "timestamp",
    "timestamp": "timestamp",
    # In T-Pot's Elasticsearch the logstash `type` field holds the honeypot
    # name (Cowrie, Dionaea, ...), which the attack map filters on. QPot stores
    # that in the `honeypot` column; `event_type` is the kind of event.
    "type": "honeypot",
    "event_type": "event_type",
    "honeypot": "honeypot",
    # Source IP: accept the common ES spellings and the geoip.* fields the
    # attack map uses, all backed by QPot's single source_ip column.
    "src_ip": "source_ip",
    "source_ip": "source_ip",
    "geoip.ip": "source_ip",
    "src_port": "source_port",
    "source_port": "source_port",
    "dest_port": "dest_port",
    "protocol": "protocol",
    "username": "username",
    "password": "password",
    "command": "command",
    "payload": "payload",
    # Geo: QPot resolves country/city/asn directly on the event row. Map the
    # geoip.* ES field names the attack map and Kibana dashboards expect onto
    # those real columns.
    "country": "country",
    "geoip.country_name": "country",
    "geoip.country_code2": "country",
    "city": "city",
    "geoip.city_name": "city",
    "asn": "asn",
    # ATT&CK enrichment QPot adds on the same row.
    "technique_id": "technique_id",
    "technique_name": "technique_name",
    "tactic_id": "tactic_id",
    "tactic_name": "tactic_name",
    "kill_chain_stage": "kill_chain_stage",
}


# --- SQL-safety helpers -----------------------------------------------------
# Kibana / the attack map send Elasticsearch DSL whose values (search terms,
# filter values, sizes) and field names are ultimately attacker-influenced
# (an attacker controls usernames, source IPs, commands that end up indexed and
# later queried). Interpolating those straight into a ClickHouse SQL string is a
# SQL-injection sink and also breaks on any legitimate value containing a quote
# (e.g. a username like O'Brien). Every value that reaches the SQL string must
# go through ch_quote, every identifier through safe_ident, and LIMIT through
# safe_limit.

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def ch_quote(value) -> str:
    """Return a ClickHouse string literal for an arbitrary value, safely
    escaped. Booleans/ints are rendered without quotes; everything else is
    stringified, backslash/quote-escaped and single-quoted."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    s = str(value)
    # ClickHouse string-literal escaping: backslash first, then single quote.
    s = s.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{s}'"


def safe_ident(name: str) -> str:
    """Sanitize an identifier (column/field name) to a bare SQL identifier.
    Non-identifier characters are stripped so a crafted field name like
    "evil) OR 1=1 --" cannot break out of its position. Falls back to
    "timestamp" if nothing usable remains."""
    if not name:
        return "timestamp"
    cleaned = name.replace(".", "_")
    m = _IDENT_RE.match(cleaned)
    if not m:
        # Drop any leading junk and retry (e.g. "1abc" -> "abc").
        stripped = re.sub(r"^[^A-Za-z_]+", "", cleaned)
        m = _IDENT_RE.match(stripped) if stripped else None
    return m.group(0) if m else "timestamp"


def safe_limit(size, default: int = 10, maximum: int = 10000) -> int:
    """Coerce an ES "size" (which arrives untyped from a JSON body) to a
    bounded non-negative integer suitable for LIMIT."""
    try:
        n = int(size)
    except (TypeError, ValueError):
        return default
    if n < 0:
        return default
    return min(n, maximum)


def get_ch_client():
    """Get or create ClickHouse client."""
    global ch_client
    if ch_client is None:
        ch_client = ClickHouseClient(
            host=CH_HOST,
            port=CH_PORT,
            database=CH_DATABASE,
            user=CH_USER,
            password=CH_PASSWORD
        )
    return ch_client


def es_field_to_ch(field: str) -> str:
    """Convert Elasticsearch field name to ClickHouse column name. Unknown
    fields are sanitized to a bare identifier so they can never inject SQL."""
    if field in FIELD_MAPPINGS:
        return FIELD_MAPPINGS[field]
    return safe_ident(field)


# Columns matched case-insensitively. T-Pot/Kibana send capitalized honeypot
# names (the attack map queries `type:(Cowrie OR Dionaea ...)`) while QPot
# stores them lower-case (`cowrie`), so equality must fold case.
_CI_COLUMNS = {"honeypot"}


def _eq_condition(ch_field: str, value: str) -> str:
    if ch_field in _CI_COLUMNS:
        return f"lower({ch_field}) = lower({ch_quote(value)})"
    return f"{ch_field} = {ch_quote(value)}"


def _in_condition(ch_field: str, values: list) -> str:
    if ch_field in _CI_COLUMNS:
        vlist = ", ".join(ch_quote(str(v).lower()) for v in values)
        return f"lower({ch_field}) IN ({vlist})"
    vlist = ", ".join(ch_quote(v) for v in values)
    return f"{ch_field} IN ({vlist})"


def query_string_to_condition(qs: str) -> str:
    """Translate the subset of Elasticsearch query_string syntax QPot's
    consumers actually emit into a ClickHouse boolean condition:

        field:value                -> field = 'value'
        field:(v1 OR v2 OR v3)     -> field IN ('v1','v2','v3')   (attack map)
        f1:v1 OR f2:v2             -> (f1 = 'v1' OR f2 = 'v2')

    All values are escaped via ch_quote and the honeypot column is matched
    case-insensitively. Returns "" when nothing usable is present.
    """
    qs = (qs or "").strip()
    if not qs:
        return ""

    # field:(v1 OR v2 OR ...)  - the attack map's main honeypot selector.
    m = re.match(r'^([\w.@+-]+)\s*:\s*\((.+)\)\s*$', qs, re.DOTALL)
    if m:
        field = es_field_to_ch(m.group(1).strip())
        values = [v.strip().strip('"').strip("'")
                  for v in re.split(r'\s+OR\s+', m.group(2), flags=re.IGNORECASE)]
        values = [v for v in values if v]
        return _in_condition(field, values) if values else ""

    # f1:v1 OR f2:v2  (top-level OR of field:value terms)
    if re.search(r'\s+OR\s+', qs, flags=re.IGNORECASE):
        parts = []
        for term in re.split(r'\s+OR\s+', qs, flags=re.IGNORECASE):
            term = term.strip()
            if ":" in term:
                f, v = term.split(":", 1)
                parts.append(_eq_condition(es_field_to_ch(f.strip()), v.strip().strip('"')))
        return "(" + " OR ".join(parts) + ")" if parts else ""

    # field:value
    if ":" in qs:
        f, v = qs.split(":", 1)
        return _eq_condition(es_field_to_ch(f.strip()), v.strip().strip('"'))
    return ""


def parse_time_range(range_dict: Dict) -> tuple:
    """Parse ES time range to ClickHouse time range."""
    time_field = "timestamp"
    gte = None
    lte = None
    
    for field, conditions in range_dict.items():
        time_field = es_field_to_ch(field)
        if isinstance(conditions, dict):
            gte = conditions.get("gte")
            lte = conditions.get("lte")
            if "gte" in conditions and conditions["gte"].startswith("now-"):
                # Handle relative time like "now-1h"
                delta_str = conditions["gte"][4:]  # Remove "now-"
                gte = relative_time_to_datetime(delta_str)
    
    return time_field, gte, lte


def relative_time_to_datetime(delta_str: str) -> datetime:
    """Convert relative time string to datetime."""
    now = datetime.utcnow()
    
    # Parse duration like "1h", "24h", "1m"
    match = re.match(r'(\d+)([smhdwMy])', delta_str)
    if match:
        value, unit = int(match.group(1)), match.group(2)
        deltas = {
            's': timedelta(seconds=value),
            'm': timedelta(minutes=value),
            'h': timedelta(hours=value),
            'd': timedelta(days=value),
            'w': timedelta(weeks=value),
        }
        if unit in deltas:
            return now - deltas[unit]
    
    return now - timedelta(hours=24)


def resolve_time_value(val) -> str:
    """Resolve an Elasticsearch range bound to a 'YYYY-MM-DD HH:MM:SS' string
    ClickHouse can compare against a DateTime column. Handles the forms QPot's
    consumers send:
        "now"            -> current UTC time   (the attack map sends lte:"now")
        "now-1h"/"now-5m"-> relative past
        ISO "2026-..T..Z"-> normalized (drop the T separator / timezone)
        epoch millis/secs-> converted
    A previous version only special-cased gte:"now-..", so the attack map's
    lte:"now" became the literal SQL `<= 'now'` and ClickHouse rejected it.
    """
    if isinstance(val, bool):
        val = int(val)
    if isinstance(val, (int, float)):
        secs = val / 1000.0 if val > 1e11 else float(val)
        return datetime.utcfromtimestamp(secs).strftime("%Y-%m-%d %H:%M:%S")
    s = str(val).strip()
    if s == "now":
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if s.startswith("now-"):
        return relative_time_to_datetime(s[4:]).strftime("%Y-%m-%d %H:%M:%S")
    if s.startswith("now+"):
        m = re.match(r'(\d+)([smhdw])', s[4:])
        if m:
            unit = {"s": "seconds", "m": "minutes", "h": "hours",
                    "d": "days", "w": "weeks"}[m.group(2)]
            return (datetime.utcnow() + timedelta(**{unit: int(m.group(1))})).strftime("%Y-%m-%d %H:%M:%S")
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    # ISO timestamp: normalize the 'T' separator and strip fractional/timezone.
    s = s.replace("T", " ")
    s = re.sub(r'(\.\d+)?(Z|[+-]\d{2}:?\d{2})?$', '', s).strip()
    return s


def es_query_to_ch_where(query: Dict) -> str:
    """Convert Elasticsearch query to ClickHouse WHERE clause."""
    conditions = []
    
    if not query:
        return "1=1"

    # Top-level query_string (some clients send it directly, not under bool).
    if "query_string" in query:
        cond = query_string_to_condition(query["query_string"].get("query", ""))
        if cond:
            conditions.append(cond)

    if "bool" in query:
        bool_query = query["bool"]

        # MUST (AND)
        if "must" in bool_query:
            for must_item in bool_query["must"]:
                if "query_string" in must_item:
                    cond = query_string_to_condition(must_item["query_string"].get("query", ""))
                    if cond:
                        conditions.append(cond)

        # FILTER
        if "filter" in bool_query:
            for filter_item in bool_query["filter"]:
                if "range" in filter_item:
                    for field, range_cond in filter_item["range"].items():
                        ch_field = es_field_to_ch(field)
                        for op, sql_op in (("gte", ">="), ("gt", ">"),
                                           ("lte", "<="), ("lt", "<")):
                            if op in range_cond:
                                conditions.append(
                                    f"{ch_field} {sql_op} {ch_quote(resolve_time_value(range_cond[op]))}")

                if "terms" in filter_item:
                    for field, values in filter_item["terms"].items():
                        ch_field = es_field_to_ch(field.replace(".keyword", ""))
                        if isinstance(values, list):
                            value_list = ", ".join([ch_quote(v) for v in values])
                            conditions.append(f"{ch_field} IN ({value_list})")
                
                if "exists" in filter_item:
                    field = filter_item["exists"].get("field", "")
                    ch_field = es_field_to_ch(field)
                    conditions.append(f"{ch_field} IS NOT NULL")
    
    return " AND ".join(conditions) if conditions else "1=1"


def build_ch_query(index: str, es_query: Dict, size: int = 10, aggs: Dict = None) -> str:
    """Build ClickHouse query from Elasticsearch query."""
    table = INDEX_PATTERNS.get(index, EVENTS_TABLE)
    
    # Build SELECT
    select_fields = "*"
    if "_source" in es_query:
        fields = es_query.get("_source", [])
        if fields:
            mapped_fields = [es_field_to_ch(f) for f in fields]
            select_fields = ", ".join(mapped_fields)
    
    # Build WHERE
    query = es_query.get("query", {})
    where_clause = es_query_to_ch_where(query)
    
    # Build ORDER BY
    order_by = "timestamp DESC"
    if "sort" in es_query:
        sorts = []
        for sort_item in es_query["sort"]:
            if isinstance(sort_item, dict):
                for field, order in sort_item.items():
                    ch_field = es_field_to_ch(field)
                    order_str = "DESC" if order.get("order") == "desc" else "ASC"
                    sorts.append(f"{ch_field} {order_str}")
        if sorts:
            order_by = ", ".join(sorts)
    
    # Build the query. size arrives untyped from the JSON body, so it must be
    # coerced to a bounded integer before it reaches the SQL string.
    ch_query = f"""
    SELECT {select_fields}
    FROM {table}
    WHERE {where_clause}
    ORDER BY {order_by}
    LIMIT {safe_limit(size)}
    """

    return ch_query.strip()


def ch_row_to_es_hit(row: tuple, columns: List[str]) -> Dict:
    """Convert a ClickHouse `events` row into an Elasticsearch hit shaped the
    way QPot's consumers (the T-Pot attack map, Kibana dashboards) expect.

    The attack map reads `type` (honeypot name), `@timestamp`, `src_ip`,
    `src_port`, `dest_port`, and a nested `geoip` object with
    `country_name`/`country_code2`/`latitude`/`longitude`. QPot stores only a
    country ISO code, so latitude/longitude are derived from a country centroid
    (see geo.py) - approximate, country-level coordinates good enough to plot.
    """
    col = {columns[i]: row[i] for i in range(min(len(columns), len(row)))}
    source: Dict[str, Any] = {}

    ts = col.get("timestamp")
    if ts is not None:
        source["@timestamp"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)

    honeypot = col.get("honeypot")
    if honeypot:
        # T-Pot's `type` is the (capitalized) honeypot name.
        source["type"] = str(honeypot).capitalize()
        source["honeypot"] = honeypot

    # Flat fields the dashboards/attack map consume, under both QPot and the
    # common ES spellings.
    if "source_ip" in col:
        source["src_ip"] = col["source_ip"]
        source["source_ip"] = col["source_ip"]
    if "source_port" in col:
        source["src_port"] = col["source_port"]
    if "dest_port" in col:
        source["dest_port"] = col["dest_port"]
    for c in ("protocol", "event_type", "username", "password", "command",
              "city", "asn", "technique_id", "technique_name", "tactic_id",
              "tactic_name"):
        if c in col and col[c] not in (None, ""):
            source[c] = col[c]

    # Geo: QPot stores country as an ISO-3166-1 alpha-2 code; build the nested
    # geoip object the attack map plots from it.
    cc = (col.get("country") or "")
    geoip: Dict[str, Any] = {}
    if cc and cc.upper() not in ("UNKNOWN", "--"):
        geoip["country_code2"] = cc.upper()
        rec = geo.lookup(cc)
        if rec:
            name, lat, lon = rec
            geoip["country_name"] = name
            geoip["latitude"] = lat
            geoip["longitude"] = lon
            geoip["location"] = {"lat": lat, "lon": lon}
        else:
            geoip["country_name"] = cc.upper()
    if col.get("city") and col["city"] != "unknown":
        geoip["city_name"] = col["city"]
    if geoip:
        source["geoip"] = geoip

    return {
        "_index": "logstash-clickhouse",
        "_type": "_doc",
        "_id": f"ch_{hash(str(row))}",
        "_score": 1.0,
        "_source": source,
    }


@app.get("/")
async def root():
    """ES root. Kibana reads version.number here and refuses to start if its
    major version differs, so report a real, configurable ES version."""
    return {
        "name": "qpot-clickhouse",
        "cluster_name": "qpot-clickhouse",
        "cluster_uuid": CLUSTER_UUID,
        "version": {
            "number": ES_VERSION,
            "build_flavor": "default",
            "build_type": "docker",
            "build_hash": "qpot",
            "build_date": "2024-01-01T00:00:00.000Z",
            "build_snapshot": False,
            "lucene_version": "9.7.0",
            "minimum_wire_compatibility_version": "7.17.0",
            "minimum_index_compatibility_version": "7.0.0",
        },
        "tagline": "You Know, for Search",
    }


@app.get("/_cluster/health")
async def cluster_health():
    """ES-compatible cluster health endpoint."""
    return {
        "cluster_name": "qpot-clickhouse",
        "status": "green",
        "timed_out": False,
        "number_of_nodes": 1,
        "number_of_data_nodes": 1,
        "active_primary_shards": 1,
        "active_shards": 1,
        "relocating_shards": 0,
        "initializing_shards": 0,
        "unassigned_shards": 0,
        "delayed_unassigned_shards": 0,
        "number_of_pending_tasks": 0,
        "number_of_in_flight_fetch": 0,
        "task_max_waiting_in_queue_millis": 0,
        "active_shards_percent_as_number": 100.0
    }


@app.get("/_cluster/state")
async def cluster_state():
    """ES-compatible cluster state endpoint."""
    return {
        "cluster_name": "qpot-clickhouse",
        "master_node": "qpot-node-1",
        "blocks": {},
        "nodes": {
            "qpot-node-1": {
                "name": "qpot-clickhouse",
                "ephemeral_id": "qpot-connector",
                "transport_address": "127.0.0.1:9300",
                "attributes": {}
            }
        },
        "metadata": {
            "cluster_uuid": "qpot-cluster",
            "templates": {},
            "indices": {
                "logstash-clickhouse": {
                    "state": "open",
                    "settings": {
                        "index": {
                            "number_of_shards": "1",
                            "number_of_replicas": "0"
                        }
                    },
                    "mappings": {},
                    "aliases": []
                }
            }
        }
    }


@app.get("/_cat/indices")
async def cat_indices():
    """ES-compatible cat indices endpoint."""
    return PlainTextResponse("""green open logstash-clickhouse 1 0 1000 0 1mb 1mb""")


# ES field types for QPot's event fields, as the attack map / Kibana index
# pattern see them. Flat dotted names; nested for _mapping is derived from this.
EVENTS_FIELD_TYPES = {
    "@timestamp": "date",
    "type": "keyword",
    "honeypot": "keyword",
    "src_ip": "ip",
    "source_ip": "ip",
    "src_port": "integer",
    "source_port": "integer",
    "dest_port": "integer",
    "protocol": "keyword",
    "event_type": "keyword",
    "username": "keyword",
    "password": "keyword",
    "command": "text",
    "city": "keyword",
    "asn": "keyword",
    "technique_id": "keyword",
    "technique_name": "keyword",
    "tactic_id": "keyword",
    "tactic_name": "keyword",
    "geoip.country_code2": "keyword",
    "geoip.country_name": "keyword",
    "geoip.city_name": "keyword",
    "geoip.latitude": "float",
    "geoip.longitude": "float",
    "geoip.location": "geo_point",
}


def events_mapping_properties() -> dict:
    """Build the nested ES mapping `properties` from the flat field-type table."""
    props: dict = {}
    for field, typ in EVENTS_FIELD_TYPES.items():
        parts = field.split(".")
        cur = props
        for p in parts[:-1]:
            cur = cur.setdefault(p, {}).setdefault("properties", {})
        cur[parts[-1]] = {"type": typ}
    return props


@app.get("/{index}/_mapping")
async def get_mapping(index: str):
    """ES-compatible mapping endpoint."""
    if savedobjects.is_system_index(index):
        # Kibana manages its own system-index mappings; return an empty dynamic
        # mapping so it proceeds.
        return {index: {"mappings": {"dynamic": "true", "properties": {}}}}
    return {index: {"mappings": {"properties": events_mapping_properties()}}}


def _field_caps_payload(indices_label: str) -> dict:
    es_to_ch_caps = {}
    for field, typ in EVENTS_FIELD_TYPES.items():
        es_to_ch_caps[field] = {
            typ: {
                "type": typ,
                "metadata_field": False,
                "searchable": True,
                "aggregatable": typ in ("keyword", "ip", "integer", "float", "date", "geo_point"),
            }
        }
    # Always-present meta fields Kibana expects.
    for meta, mtype in (("_id", "_id"), ("_index", "_index"), ("_source", "_source")):
        es_to_ch_caps[meta] = {mtype: {"type": mtype, "metadata_field": True,
                                       "searchable": meta != "_source",
                                       "aggregatable": False}}
    return {"indices": [indices_label], "fields": es_to_ch_caps}


@app.get("/{index}/_field_caps")
@app.post("/{index}/_field_caps")
async def field_caps(index: str, request: Request = None):
    """Field capabilities - how Kibana discovers an index pattern's fields."""
    if savedobjects.is_system_index(index):
        return {"indices": [index], "fields": {}}
    return _field_caps_payload(index)


@app.get("/_field_caps")
@app.post("/_field_caps")
async def field_caps_all(request: Request = None):
    return _field_caps_payload("logstash-*")


@app.post("/{index}/_search")
async def search(index: str, request: Request):
    """ES-compatible search endpoint over ClickHouse, with aggregation
    support. Kibana's system indices are served from the saved-object store."""
    try:
        es_query = await request.json()
    except Exception:
        es_query = {}

    # Kibana's own saved objects live in .kibana*; never touch ClickHouse.
    if savedobjects.is_system_index(index):
        return SO.search(index, es_query)

    size = es_query.get("size", 10)
    track_total_hits = es_query.get("track_total_hits", False)
    aggs = es_query.get("aggs") or es_query.get("aggregations") or {}

    try:
        client = get_ch_client()
        table = INDEX_PATTERNS.get(index, EVENTS_TABLE)
        where = es_query_to_ch_where(es_query.get("query", {}))

        # Hits (Kibana viz send size:0 to fetch only aggregations).
        hits = []
        if safe_limit(size, default=10) > 0:
            ch_query = build_ch_query(index, es_query, size, aggs)
            result = client.execute(ch_query, with_column_types=True)
            rows, columns = result[0], [c[0] for c in result[1]]
            hits = [ch_row_to_es_hit(row, columns) for row in rows]

        # Total. With track_total_hits or any aggregation, compute the real
        # matching count; otherwise the hit count is enough.
        total_value = len(hits)
        if track_total_hits or aggs:
            cres = client.execute(f"SELECT count() FROM {table} WHERE {where}")
            total_value = cres[0][0] if cres else len(hits)

        response = {
            "took": 1, "timed_out": False,
            "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
            "hits": {"total": {"value": total_value, "relation": "eq"},
                     "max_score": 1.0 if hits else None, "hits": hits},
        }

        # Aggregations -> ClickHouse GROUP BY.
        if aggs:
            plan = agg_translate.plan_aggregations(aggs, es_field_to_ch, ch_quote)
            if plan is not None:
                asql = agg_translate.build_agg_sql(table, where, plan)
                ares = client.execute(asql, with_column_types=True)
                arows, acols = ares[0], [c[0] for c in ares[1]]
                response["aggregations"] = agg_translate.shape_agg_response(plan, arows, acols)

        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/{index}/_search")
async def search_get(index: str, q: str = None, size: int = 10):
    """ES-compatible GET search endpoint."""
    es_query = {"size": size}
    
    if q:
        es_query["query"] = {
            "query_string": {
                "query": q
            }
        }
    
    # Create a mock request
    class MockRequest:
        async def json(self):
            return es_query
    
    return await search(index, MockRequest())


@app.get("/_xpack")
async def xpack_info():
    """ES-compatible xpack info endpoint."""
    return {
        "build": {
            "hash": "qpot",
            "date": datetime.utcnow().isoformat()
        },
        "license": {
            "status": "active",
            "type": "basic",
            "expiry_date_in_millis": 4102444800000
        },
        "features": {
            "ml": {"available": False, "enabled": False},
            "monitoring": {"available": True, "enabled": True},
            "security": {"available": False, "enabled": False},
            "sql": {"available": True, "enabled": True}
        }
    }


@app.get("/_aliases")
async def get_aliases():
    """ES-compatible aliases endpoint."""
    return {
        "logstash-clickhouse": {
            "aliases": {
                "logstash": {}
            }
        }
    }


@app.get("/_template/logstash")
async def get_template():
    """ES-compatible template endpoint."""
    return {
        "logstash": {
            "order": 0,
            "index_patterns": ["logstash-*"],
            "settings": {
                "index": {
                    "number_of_shards": "1",
                    "number_of_replicas": "0"
                }
            },
            "mappings": {},
            "aliases": {}
        }
    }


def _process_bulk(body_bytes: bytes, default_index: Optional[str]) -> dict:
    """Apply an ND-JSON _bulk body. Operations on Kibana system indices are
    applied to the saved-object store; operations on data indices are accepted
    as no-ops (QPot ingests via Vector, not the ES write path)."""
    items = []
    errors = False
    lines = body_bytes.decode("utf-8", "replace").split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line:
            continue
        try:
            action = json.loads(line)
        except Exception:
            continue
        if not isinstance(action, dict) or not action:
            continue
        op, meta = next(iter(action.items()))
        index = (meta or {}).get("_index", default_index)
        doc_id = (meta or {}).get("_id")
        src = None
        if op in ("index", "create", "update"):
            if i < len(lines):
                try:
                    src = json.loads(lines[i])
                except Exception:
                    src = {}
                i += 1
        system = savedobjects.is_system_index(index or "")
        try:
            if op == "delete":
                res = SO.delete_doc(index, doc_id) if system else {
                    "_index": index, "_id": doc_id, "result": "deleted"}
                status = 200
            elif op == "update":
                res = SO.update_doc(index, doc_id, src or {}) if system else {
                    "_index": index, "_id": doc_id, "result": "updated"}
                status = 200
            else:  # index | create
                if system:
                    res = SO.index_doc(index, doc_id, src or {}, create=(op == "create"))
                else:
                    res = {"_index": index, "_id": doc_id or "auto", "result": "created"}
                status = 201 if res.get("result") == "created" else 200
            res["status"] = status
            items.append({op: res})
        except KeyError:
            errors = True
            items.append({op: {"_index": index, "_id": doc_id, "status": 409,
                               "error": {"type": "version_conflict_engine_exception"}}})
    return {"took": 1, "errors": errors, "items": items}


@app.post("/_bulk")
async def bulk(request: Request):
    return _process_bulk(await request.body(), None)


@app.post("/{index}/_bulk")
async def bulk_index(index: str, request: Request):
    return _process_bulk(await request.body(), index)


@app.get("/_nodes")
async def nodes_info():
    """ES-compatible nodes info endpoint."""
    return {
        "_nodes": {
            "total": 1,
            "successful": 1,
            "failed": 0
        },
        "cluster_name": "qpot-clickhouse",
        "nodes": {
            "qpot-node-1": {
                "name": "qpot-clickhouse",
                "transport_address": "127.0.0.1:9300",
                "host": "127.0.0.1",
                "ip": "127.0.0.1",
                "version": ES_VERSION,
                "build_flavor": "default",
                "build_type": "docker",
                "build_hash": "qpot",
                "total_indexing_buffer": 536870912,
                "roles": ["master", "data", "ingest"],
                "os": {
                    "name": "Linux",
                    "arch": "amd64",
                    "version": "5.0"
                },
                "process": {
                    "refresh_interval_in_millis": 1000,
                    "id": 1,
                    "mlockall": False
                },
                "jvm": {
                    "version": "11.0.1",
                    "vm_name": "OpenJDK 64-Bit Server VM"
                }
            }
        }
    }


@app.head("/")
async def head_root():
    """ES-compatible HEAD request."""
    return Response(status_code=200)


@app.get("/_license")
async def license_info():
    """ES-compatible license endpoint."""
    return {
        "license": {
            "status": "active",
            "uid": "qpot-license",
            "type": "basic",
            "issue_date": "2024-01-01T00:00:00.000Z",
            "issue_date_in_millis": 1704067200000,
            "expiry_date": "2099-12-31T23:59:59.999Z",
            "expiry_date_in_millis": 4102444799999,
            "max_nodes": 1000,
            "issued_to": "QPot User",
            "issuer": "QPot",
            "signature": "QPot License"
        }
    }


# ---------------------------------------------------------------------------
# Document API for Kibana's system indices (.kibana*). These are how Kibana
# bootstraps and persists its saved objects. Non-system indices are read-only
# (QPot ingests via Vector), so writes there are accepted as no-ops.
# ---------------------------------------------------------------------------

@app.put("/{index}/_doc/{doc_id}")
@app.post("/{index}/_doc/{doc_id}")
@app.put("/{index}/_create/{doc_id}")
@app.post("/{index}/_create/{doc_id}")
async def put_doc(index: str, doc_id: str, request: Request):
    create = "/_create/" in str(request.url.path)
    try:
        source = await request.json()
    except Exception:
        source = {}
    if savedobjects.is_system_index(index):
        try:
            res = SO.index_doc(index, doc_id, source, create=create)
        except KeyError:
            raise HTTPException(status_code=409, detail="version_conflict_engine_exception")
        return JSONResponse(res, status_code=201 if res["result"] == "created" else 200)
    return {"_index": index, "_id": doc_id, "result": "created", "_version": 1,
            "_shards": {"total": 1, "successful": 1, "failed": 0}}


@app.post("/{index}/_doc")
async def post_doc_autoid(index: str, request: Request):
    try:
        source = await request.json()
    except Exception:
        source = {}
    if savedobjects.is_system_index(index):
        res = SO.index_doc(index, None, source)
        return JSONResponse(res, status_code=201)
    return {"_index": index, "_id": "auto", "result": "created"}


@app.post("/{index}/_update/{doc_id}")
async def update_doc(index: str, doc_id: str, request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if savedobjects.is_system_index(index):
        return SO.update_doc(index, doc_id, body)
    return {"_index": index, "_id": doc_id, "result": "updated"}


@app.get("/{index}/_doc/{doc_id}")
@app.get("/{index}/_source/{doc_id}")
async def get_doc(index: str, doc_id: str, request: Request):
    if savedobjects.is_system_index(index):
        res = SO.get_doc(index, doc_id)
        if not res.get("found"):
            return JSONResponse(res, status_code=404)
        if str(request.url.path).endswith(f"/_source/{doc_id}"):
            return res["_source"]
        return res
    return JSONResponse({"_index": index, "_id": doc_id, "found": False},
                        status_code=404)


@app.delete("/{index}/_doc/{doc_id}")
async def delete_doc(index: str, doc_id: str):
    if savedobjects.is_system_index(index):
        res = SO.delete_doc(index, doc_id)
        return JSONResponse(res, status_code=200 if res["result"] == "deleted" else 404)
    return {"_index": index, "_id": doc_id, "result": "not_found"}


@app.post("/_mget")
@app.post("/{index}/_mget")
async def mget(request: Request, index: str = None):
    try:
        body = await request.json()
    except Exception:
        body = {}
    return SO.mget(body.get("docs", []), index)


@app.post("/{index}/_count")
@app.get("/{index}/_count")
async def count(index: str, request: Request):
    body = {}
    try:
        if request.method == "POST":
            body = await request.json()
    except Exception:
        body = {}
    if savedobjects.is_system_index(index):
        return SO.count(index, body)
    try:
        client = get_ch_client()
        table = INDEX_PATTERNS.get(index, EVENTS_TABLE)
        where = es_query_to_ch_where(body.get("query", {}))
        res = client.execute(f"SELECT count() FROM {table} WHERE {where}")
        return {"count": res[0][0] if res else 0,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/{index}/_refresh")
@app.get("/{index}/_refresh")
@app.post("/_refresh")
async def refresh(index: str = None):
    return {"_shards": {"total": 1, "successful": 1, "failed": 0}}


@app.put("/{index}")
async def create_index(index: str, request: Request):
    # Kibana creates its system indices; acknowledge so it proceeds.
    return {"acknowledged": True, "shards_acknowledged": True, "index": index}


@app.get("/{index}")
async def get_index(index: str):
    return {index: {"aliases": {}, "mappings": {"properties": (
        {} if savedobjects.is_system_index(index) else events_mapping_properties())},
        "settings": {"index": {"number_of_shards": "1", "number_of_replicas": "0",
                               "uuid": "qpot-" + index.strip(".").replace("*", "x")[:16] or "idx",
                               "version": {"created": "8110000"}}}}}


@app.head("/{index}")
async def head_index(index: str):
    if savedobjects.is_system_index(index) and not SO.exists(index):
        return Response(status_code=404)
    return Response(status_code=200)


@app.get("/_resolve/index/{expr:path}")
async def resolve_index(expr: str):
    name = expr.split(",")[0]
    return {"indices": [{"name": name, "attributes": ["open"]}],
            "aliases": [], "data_streams": []}


@app.get("/{index}/_settings")
async def get_settings(index: str):
    return {index: {"settings": {"index": {"number_of_shards": "1",
                                           "number_of_replicas": "0",
                                           "version": {"created": "8110000"}}}}}


@app.on_event("startup")
async def startup():
    """Startup event."""
    print("[*] QPot ClickHouse-Kibana Connector starting...")
    print(f"[*] QPot ID: {QPOT_ID if QPOT_ID else 'Not configured'}")
    print(f"[*] ClickHouse: {CH_HOST}:{CH_PORT}")
    
    # Seed Kibana's data view + the QPot Overview dashboard on first boot, so
    # Kibana opens straight into working attack dashboards with no setup (the
    # T-Pot experience). Idempotent: once Kibana has written any saved object,
    # this is a no-op and never clobbers user edits.
    try:
        seeded = SO.seed_if_empty(default_objects.build_saved_objects(EVENTS_FIELD_TYPES, ES_VERSION))
        print(f"[*] Kibana saved objects: {'seeded defaults' if seeded else 'already present'}")
    except Exception as e:
        print(f"[!] Warning: could not seed Kibana objects: {e}")

    # Test connection
    try:
        client = get_ch_client()
        client.execute("SELECT 1")
        print("[*] ClickHouse connection established")
    except Exception as e:
        print(f"[!] Warning: Could not connect to ClickHouse: {e}")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9200)
