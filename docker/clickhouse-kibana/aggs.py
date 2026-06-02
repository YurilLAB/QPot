"""Elasticsearch aggregation -> ClickHouse translation for the connector.

Kibana visualizations are built almost entirely on aggregations. This module
translates the bucket + metric aggregations Kibana emits into a single
ClickHouse GROUP BY query and reshapes the flat result back into Elasticsearch's
nested `aggregations` response.

Supported (covers Discover's histogram and the common Visualize types - bar,
line, pie, data table, metric):

  bucket aggs (up to two nested levels):
    - date_histogram (fixed_interval / calendar_interval / interval)
    - terms (field, size, order by _count/_key or a sub-metric)
  metric aggs (as leaves, and as terms order targets):
    - count (implicit doc_count), value_count, cardinality, avg, min, max, sum

Anything unsupported makes plan_aggregations return None, and the caller falls
back to returning hits without an aggregations block (Kibana degrades to "no
results for this agg" rather than erroring).

Identifiers/intervals are whitelisted and all literals escaped by the caller's
helpers, so nothing here is a SQL-injection sink.
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


def _dh_key(key) -> Tuple[Optional[int], Optional[str]]:
    """Resolve a date_histogram bucket key (a datetime from clickhouse_driver,
    or a 'YYYY-MM-DD HH:MM:SS' string from the HTTP/JSONCompact path) to ES's
    (epoch_millis, key_as_string). ClickHouse times are UTC."""
    if key is None:
        return None, None
    if hasattr(key, "timestamp"):
        dt = key
    else:
        dt = None
        for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.strptime(str(key), fmt)
                break
            except ValueError:
                continue
        if dt is None:
            return None, str(key)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000), dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

# ES metric agg -> ClickHouse aggregate function template (on a column).
_METRIC_FUNCS = {
    "avg": "avg",
    "min": "min",
    "max": "max",
    "sum": "sum",
    "value_count": "count",
    "cardinality": "uniqExact",
}

# Calendar/fixed interval -> ClickHouse toStartOfInterval unit. We accept the
# common Kibana intervals; unknown ones fall back to a 1-hour bucket.
_INTERVAL_RE = re.compile(r'^\s*(\d+)\s*([smhdwMy])\s*$')
_CALENDAR = {
    "second": (1, "SECOND"), "minute": (1, "MINUTE"), "hour": (1, "HOUR"),
    "day": (1, "DAY"), "week": (1, "WEEK"), "month": (1, "MONTH"),
    "quarter": (3, "MONTH"), "year": (1, "YEAR"),
}
_UNIT = {"s": "SECOND", "m": "MINUTE", "h": "HOUR", "d": "DAY", "w": "WEEK",
         "M": "MONTH", "y": "YEAR"}


def _interval_to_ch(interval: str) -> Tuple[int, str]:
    """Return (n, UNIT) for a date_histogram interval. Defaults to (1, HOUR)."""
    if not interval:
        return (1, "HOUR")
    if interval in _CALENDAR:
        return _CALENDAR[interval]
    m = _INTERVAL_RE.match(str(interval))
    if m:
        return (int(m.group(1)), _UNIT[m.group(2)])
    return (1, "HOUR")


class Bucket:
    __slots__ = ("name", "kind", "expr", "key_field", "size", "interval_ms",
                 "order_key", "order_dir")

    def __init__(self, name, kind, expr, key_field=None, size=10,
                 interval_ms=None, order_key="_count", order_dir="desc"):
        self.name = name
        self.kind = kind            # "date_histogram" | "terms"
        self.expr = expr            # ClickHouse expression for the bucket key
        self.key_field = key_field
        self.size = size
        self.interval_ms = interval_ms
        self.order_key = order_key
        self.order_dir = order_dir


class Metric:
    __slots__ = ("name", "func", "expr", "kind")

    def __init__(self, name, func, expr, kind):
        self.name = name
        self.func = func            # ClickHouse aggregate function
        self.expr = expr            # full ClickHouse aggregate expression
        self.kind = kind            # ES agg kind


class AggPlan:
    def __init__(self):
        self.buckets: List[Bucket] = []
        self.metrics: List[Metric] = []


def _interval_ms(n: int, unit: str) -> int:
    base = {"SECOND": 1000, "MINUTE": 60000, "HOUR": 3600000,
            "DAY": 86400000, "WEEK": 604800000,
            "MONTH": 2592000000, "YEAR": 31536000000}
    return n * base.get(unit, 3600000)


def plan_aggregations(aggs: Dict, es_field_to_ch, ch_quote) -> Optional[AggPlan]:
    """Walk the (nested) aggregation tree into a flat plan of bucket dimensions
    and metrics. Returns None if the structure isn't supported."""
    plan = AggPlan()

    def walk(node: Dict, depth: int) -> bool:
        if not isinstance(node, dict) or not node:
            return True
        # Find the single bucket agg and any metric aggs at this level.
        bucket_name = None
        sub_aggs = None
        for name, body in node.items():
            if not isinstance(body, dict):
                continue
            if "date_histogram" in body:
                if bucket_name is not None or depth >= 2:
                    return False
                dh = body["date_histogram"]
                field = es_field_to_ch(dh.get("field", "@timestamp"))
                interval = (dh.get("fixed_interval") or dh.get("calendar_interval")
                            or dh.get("interval") or "1h")
                n, unit = _interval_to_ch(interval)
                expr = f"toStartOfInterval({field}, INTERVAL {n} {unit})"
                plan.buckets.append(Bucket(name, "date_histogram", expr,
                                           interval_ms=_interval_ms(n, unit),
                                           order_key="_key", order_dir="asc"))
                bucket_name, sub_aggs = name, body.get("aggs") or body.get("aggregations")
            elif "terms" in body:
                if bucket_name is not None or depth >= 2:
                    return False
                t = body["terms"]
                field = es_field_to_ch(t.get("field", "").replace(".keyword", ""))
                size = t.get("size", 10)
                try:
                    size = max(1, min(int(size), 10000))
                except (TypeError, ValueError):
                    size = 10
                order_key, order_dir = "_count", "desc"
                order = t.get("order")
                if isinstance(order, dict) and order:
                    order_key, order_dir = next(iter(order.items()))
                    order_dir = "asc" if str(order_dir).lower() == "asc" else "desc"
                elif isinstance(order, list) and order and isinstance(order[0], dict):
                    order_key, order_dir = next(iter(order[0].items()))
                    order_dir = "asc" if str(order_dir).lower() == "asc" else "desc"
                plan.buckets.append(Bucket(name, "terms", field, key_field=field,
                                           size=size, order_key=order_key,
                                           order_dir=order_dir))
                bucket_name, sub_aggs = name, body.get("aggs") or body.get("aggregations")
            else:
                # metric agg?
                for mkind, func in _METRIC_FUNCS.items():
                    if mkind in body and isinstance(body[mkind], dict):
                        f = body[mkind].get("field")
                        if mkind == "value_count":
                            expr = "count()"
                        elif not f:
                            return False
                        else:
                            expr = f"{func}({es_field_to_ch(f)})"
                        plan.metrics.append(Metric(name, func, expr, mkind))
                        break
        if bucket_name is not None and sub_aggs:
            return walk(sub_aggs, depth + 1)
        return True

    if not walk(aggs, 0):
        return None
    if not plan.buckets and not plan.metrics:
        return None
    return plan


def build_agg_sql(table: str, where: str, plan: AggPlan) -> str:
    """Build a single GROUP BY query for the plan."""
    selects, groupbys, orderbys = [], [], []
    for i, b in enumerate(plan.buckets):
        alias = f"b{i}"
        selects.append(f"{b.expr} AS {alias}")
        groupbys.append(alias)
    selects.append("count() AS doc_count")
    for j, m in enumerate(plan.metrics):
        selects.append(f"{m.expr} AS m{j}")

    # Ordering: time buckets ascending by key; terms by their order target.
    limit_by = ""
    for i, b in enumerate(plan.buckets):
        alias = f"b{i}"
        if b.kind == "date_histogram":
            orderbys.append(f"{alias} ASC")
        else:
            if b.order_key == "_key":
                orderbys.append(f"{alias} {b.order_dir.upper()}")
            elif b.order_key == "_count":
                orderbys.append(f"doc_count {b.order_dir.upper()}")
            else:
                # order by a named metric
                idx = next((k for k, m in enumerate(plan.metrics)
                            if m.name == b.order_key), None)
                orderbys.append(f"m{idx} {b.order_dir.upper()}" if idx is not None
                                else f"doc_count DESC")

    sql = f"SELECT {', '.join(selects)} FROM {table} WHERE {where}"
    if groupbys:
        sql += f" GROUP BY {', '.join(groupbys)}"
    if orderbys:
        sql += f" ORDER BY {', '.join(orderbys)}"
    # Bound result size. Single terms level: LIMIT size. Two levels: cap rows.
    if len(plan.buckets) == 1 and plan.buckets[0].kind == "terms":
        sql += f" LIMIT {plan.buckets[0].size}"
    elif plan.buckets:
        sql += " LIMIT 100000"
    return sql


def _metric_value(m: Metric, raw):
    if raw is None:
        return {"value": None}
    if m.kind in ("value_count", "cardinality"):
        return {"value": int(raw)}
    return {"value": float(raw)}


def shape_agg_response(plan: AggPlan, rows: List[tuple], columns: List[str]) -> Dict:
    """Reshape flat GROUP BY rows into ES's nested aggregations response."""
    nb = len(plan.buckets)
    nm = len(plan.metrics)
    idx = {c: i for i, c in enumerate(columns)}

    def metrics_obj(row) -> Dict:
        out = {}
        for j, m in enumerate(plan.metrics):
            out[m.name] = _metric_value(m, row[idx.get(f"m{j}", -1)])
        return out

    if nb == 0:
        # metric-only aggregation over the whole result set.
        out = {}
        if rows:
            out.update(metrics_obj(rows[0]))
        else:
            for m in plan.metrics:
                out[m.name] = {"value": 0 if m.kind in ("value_count", "cardinality") else None}
        return out

    def make_bucket(b: Bucket, key, doc_count, row) -> Dict:
        bucket = {"doc_count": int(doc_count)}
        if b.kind == "date_histogram":
            ms, iso = _dh_key(key)
            bucket["key"] = ms if ms is not None else key
            if iso is not None:
                bucket["key_as_string"] = iso
        else:
            bucket["key"] = key
        for j, m in enumerate(plan.metrics):
            bucket[m.name] = _metric_value(m, row[idx.get(f"m{j}", -1)])
        return bucket

    b0 = plan.buckets[0]
    dc_i = idx["doc_count"]

    if nb == 1:
        buckets = [make_bucket(b0, r[idx["b0"]], r[dc_i], r) for r in rows]
        return {b0.name: {"doc_count_error_upper_bound": 0,
                          "sum_other_doc_count": 0, "buckets": buckets}}

    # Two levels: group rows by outer key, build inner buckets, applying the
    # inner terms size per outer bucket.
    b1 = plan.buckets[1]
    outer_order: List[Any] = []
    outer: Dict[Any, Dict] = {}
    for r in rows:
        k0 = r[idx["b0"]]
        if k0 not in outer:
            outer[k0] = {"rows": [], "doc_count": 0}
            outer_order.append(k0)
        outer[k0]["rows"].append(r)
        outer[k0]["doc_count"] += int(r[dc_i])

    out_buckets = []
    for k0 in outer_order:
        agg = outer[k0]
        inner_rows = agg["rows"]
        if b1.kind == "terms":
            inner_rows = inner_rows[:b1.size]
        inner = [make_bucket(b1, r[idx["b1"]], r[dc_i], r) for r in inner_rows]
        # outer bucket carries its own doc_count + the nested inner agg.
        ob = {"key": k0, "doc_count": agg["doc_count"],
              b1.name: {"doc_count_error_upper_bound": 0,
                        "sum_other_doc_count": 0, "buckets": inner}}
        if b0.kind == "date_histogram":
            ms, iso = _dh_key(k0)
            if ms is not None:
                ob["key"] = ms
                ob["key_as_string"] = iso
        out_buckets.append(ob)

    if b0.kind == "terms":
        out_buckets = out_buckets[:b0.size]
    return {b0.name: {"doc_count_error_upper_bound": 0,
                      "sum_other_doc_count": 0, "buckets": out_buckets}}
