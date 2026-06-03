"""Default Kibana saved objects QPot seeds on first boot.

T-Pot's headline feature is that Kibana opens straight into ready-made attack
dashboards. To keep that experience on QPot, the connector seeds Kibana's
`.kibana` store (when empty) with a data view over QPot's data and a "QPot
Overview" dashboard of classic aggregation visualizations. The visualizations
use only fields QPot actually has and aggregations the connector serves, so they
work with no setup - the user doesn't have to create an index pattern or build
dashboards.

`build_saved_objects` produces the documents to seed; `panel_aggregations`
exposes the Elasticsearch aggregation each panel will issue, which the test
suite verifies the connector can answer (against a live ClickHouse).
"""

import json
from typing import Dict, List

INDEX_PATTERN_ID = "qpot-logstash-star"
DASHBOARD_ID = "qpot-overview"

# ES field type -> Kibana data-view field type.
_KIBANA_FIELD_TYPE = {
    "date": "date", "keyword": "string", "text": "string", "ip": "ip",
    "integer": "number", "float": "number", "geo_point": "geo_point",
}


def _kibana_fields(field_types: Dict[str, str]) -> str:
    """Build the index-pattern `fields` attribute (a JSON string of field
    definitions) from the connector's ES field-type table."""
    fields = []
    for name, es_type in field_types.items():
        ktype = _KIBANA_FIELD_TYPE.get(es_type, "string")
        aggregatable = es_type not in ("text",)
        fields.append({
            "name": name,
            "type": ktype,
            "esTypes": [es_type],
            "count": 0,
            "scripted": False,
            "searchable": True,
            "aggregatable": aggregatable,
            "readFromDocValues": aggregatable,
        })
    # Meta fields Kibana always shows.
    for name in ("_id", "_index", "_score", "_source"):
        fields.append({"name": name, "type": "string" if name != "_score" else "number",
                       "count": 0, "scripted": False, "searchable": name not in ("_source", "_score"),
                       "aggregatable": False, "readFromDocValues": False})
    return json.dumps(fields)


def _search_source(query: str = "") -> str:
    return json.dumps({
        "query": {"query": query, "language": "kuery"},
        "filter": [],
        "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
    })


def _ip_reference():
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index",
             "type": "index-pattern", "id": INDEX_PATTERN_ID}]


def _viz(vid, title, vis_type, aggs, params=None, query=""):
    """A classic aggregation-based visualization saved object."""
    vis_state = {"title": title, "type": vis_type, "aggs": aggs,
                 "params": params or {}}
    return {
        "_id": f"visualization:{vid}",
        "_source": {
            "type": "visualization",
            "visualization": {
                "title": title,
                "visState": json.dumps(vis_state),
                "uiStateJSON": "{}",
                "description": "",
                "version": 1,
                "kibanaSavedObjectMeta": {"searchSourceJSON": _search_source(query)},
            },
            "references": _ip_reference(),
            "managed": False,
        },
    }


def _count_metric():
    return {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}


def _terms_bucket(field, size=10, schema="segment"):
    return {"id": "2", "enabled": True, "type": "terms", "schema": schema,
            "params": {"field": field, "orderBy": "1", "order": "desc", "size": size,
                       "otherBucket": False, "missingBucket": False}}


def build_saved_objects(field_types: Dict[str, str], es_version: str) -> List[Dict]:
    """Return the list of {_id, _source} docs to seed into `.kibana`."""
    objs: List[Dict] = []

    # 1) Data view (index pattern) over QPot's data.
    objs.append({
        "_id": f"index-pattern:{INDEX_PATTERN_ID}",
        "_source": {
            "type": "index-pattern",
            "index-pattern": {
                "title": "logstash-*",
                "timeFieldName": "@timestamp",
                "fields": _kibana_fields(field_types),
            },
            "references": [],
            "managed": False,
        },
    })

    # 2) Kibana config: make the data view the default so Discover opens on it.
    objs.append({
        "_id": f"config:{es_version}",
        "_source": {
            "type": "config",
            "config": {"defaultIndex": INDEX_PATTERN_ID,
                       "defaultRoute": "/app/dashboards"},
            "references": [],
            "managed": False,
        },
    })

    # 3) Visualizations (classic, aggregation-based - served by the connector).
    vizzes = [
        _viz("qpot-total-attacks", "QPot - Total Attacks", "metric",
             [_count_metric()],
             {"metric": {"percentageMode": False, "metricColorMode": "None",
                         "labels": {"show": True}}}),
        _viz("qpot-attacks-over-time", "QPot - Attacks Over Time", "histogram",
             [_count_metric(),
              {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
               "params": {"field": "@timestamp", "interval": "auto",
                          "useNormalizedEsInterval": True, "min_doc_count": 1}}],
             {"type": "histogram", "addLegend": True, "addTimeMarker": True}),
        _viz("qpot-top-honeypots", "QPot - Top Honeypots", "pie",
             [_count_metric(), _terms_bucket("type")],
             {"type": "pie", "isDonut": True, "addLegend": True, "addTooltip": True}),
        _viz("qpot-top-countries", "QPot - Top Source Countries", "pie",
             [_count_metric(), _terms_bucket("geoip.country_name")],
             {"type": "pie", "isDonut": True, "addLegend": True}),
        _viz("qpot-top-src-ips", "QPot - Top Source IPs", "table",
             [_count_metric(), _terms_bucket("src_ip", size=20, schema="bucket")],
             {"perPage": 10, "showPartialRows": False, "showTotal": True}),
        _viz("qpot-top-usernames", "QPot - Top Usernames", "table",
             [_count_metric(), _terms_bucket("username", size=20, schema="bucket")],
             {"perPage": 10}),
        _viz("qpot-top-passwords", "QPot - Top Passwords", "table",
             [_count_metric(), _terms_bucket("password", size=20, schema="bucket")],
             {"perPage": 10}),
        _viz("qpot-top-dest-ports", "QPot - Top Targeted Ports", "table",
             [_count_metric(), _terms_bucket("dest_port", size=20, schema="bucket")],
             {"perPage": 10}),
        # Showcases T-Pot's Suricata network IDS, now ingested into QPot: top
        # alert signatures, scoped to Suricata events (type -> honeypot).
        _viz("qpot-suricata-signatures", "QPot - Top Network Alerts (Suricata)", "table",
             [_count_metric(), _terms_bucket("command", size=20, schema="bucket")],
             {"perPage": 10}, query="type:suricata"),
        # p0f passive OS fingerprinting: top attacker operating systems.
        _viz("qpot-p0f-os", "QPot - Attacker OS (p0f)", "pie",
             [_count_metric(), _terms_bucket("command", size=15)],
             {"type": "pie", "isDonut": True, "addLegend": True}, query="type:p0f"),
        # fatt network fingerprints: top JA3/HASSH client fingerprints.
        _viz("qpot-fatt-fingerprints", "QPot - Top Client Fingerprints (fatt)", "table",
             [_count_metric(), _terms_bucket("command", size=20, schema="bucket")],
             {"perPage": 10}, query="type:fatt"),
    ]
    objs.extend(vizzes)

    # 4) Dashboard tying the panels together.
    panels, refs = [], []
    # 2-column grid, 24 units wide.
    layout = [
        ("qpot-total-attacks", 0, 0, 8, 8),
        ("qpot-attacks-over-time", 8, 0, 40, 8),
        ("qpot-top-honeypots", 0, 8, 24, 12),
        ("qpot-top-countries", 24, 8, 24, 12),
        ("qpot-top-src-ips", 0, 20, 16, 14),
        ("qpot-top-usernames", 16, 20, 16, 14),
        ("qpot-top-passwords", 32, 20, 16, 14),
        ("qpot-top-dest-ports", 0, 34, 24, 14),
        ("qpot-suricata-signatures", 24, 34, 24, 14),
        ("qpot-p0f-os", 0, 48, 24, 14),
        ("qpot-fatt-fingerprints", 24, 48, 24, 14),
    ]
    for i, (vid, x, y, w, h) in enumerate(layout):
        ref = f"panel_{i}"
        panels.append({
            "version": es_version,
            "type": "visualization",
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i)},
            "panelIndex": str(i),
            "embeddableConfig": {"enhancements": {}},
            "panelRefName": ref,
        })
        refs.append({"name": ref, "type": "visualization", "id": vid})

    objs.append({
        "_id": f"dashboard:{DASHBOARD_ID}",
        "_source": {
            "type": "dashboard",
            "dashboard": {
                "title": "QPot Overview",
                "description": "Attacks against QPot honeypots (auto-provisioned).",
                "panelsJSON": json.dumps(panels),
                "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
                "version": 1,
                "timeRestore": True,
                "timeFrom": "now-24h",
                "timeTo": "now",
                "refreshInterval": {"pause": False, "value": 60000},
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"},
                                                    "filter": []})
                },
            },
            "references": refs,
            "managed": False,
        },
    })

    return objs


def panel_aggregations() -> Dict[str, Dict]:
    """The Elasticsearch aggregation each dashboard panel issues, used to verify
    the connector can serve every shipped visualization. Metric-only panels
    (Total Attacks) use track_total_hits and need no agg, so are omitted."""
    return {
        "attacks_over_time": {"2": {"date_histogram": {"field": "@timestamp", "fixed_interval": "1h"}}},
        "top_honeypots": {"2": {"terms": {"field": "type", "size": 10}}},
        "top_countries": {"2": {"terms": {"field": "geoip.country_name", "size": 10}}},
        "top_src_ips": {"2": {"terms": {"field": "src_ip", "size": 20}}},
        "top_usernames": {"2": {"terms": {"field": "username", "size": 20}}},
        "top_passwords": {"2": {"terms": {"field": "password", "size": 20}}},
        "top_dest_ports": {"2": {"terms": {"field": "dest_port", "size": 20}}},
        "suricata_signatures": {"2": {"terms": {"field": "command", "size": 20}}},
        "p0f_os": {"2": {"terms": {"field": "command", "size": 15}}},
        "fatt_fingerprints": {"2": {"terms": {"field": "command", "size": 20}}},
    }
