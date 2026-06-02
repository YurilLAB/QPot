# QPot ClickHouse-Kibana Connector

This service provides an Elasticsearch-compatible API layer on top of ClickHouse, allowing Kibana to connect to and visualize QPot data stored in ClickHouse.

## Features

- **Elasticsearch API Compatibility**: Translates ES queries to ClickHouse SQL
- **Kibana Support**: Use Kibana with ClickHouse as the backend
- **Index Pattern Support**: Handles `logstash-*` patterns
- **Query Translation**: Converts ES DSL to ClickHouse queries
- **Read-Optimized**: Designed for analytics workloads
- **Attack map support**: Translates the T-Pot attack map's `type:(...)`
  honeypot selector and time ranges, and synthesizes `geoip.latitude/longitude`
  from each event's country code so the map can plot QPot's ClickHouse data
- **Kibana support**: reports an ES version for Kibana's compatibility check,
  serves `_field_caps`/`_mapping` for index patterns, translates Kibana's
  **aggregations** (`date_histogram`, `terms`, and `avg/min/max/sum/
  value_count/cardinality` metrics, up to two nested bucket levels) into
  ClickHouse `GROUP BY`, and persists Kibana's own saved objects (index
  patterns, visualizations, dashboards) in a writable `.kibana*` document store

## Kibana over ClickHouse

`docker-compose.kibana.yml` runs Kibana against QPot data with no Elasticsearch
(connector aliased as `elasticsearch`; `ES_VERSION` must match the bundled
Kibana's major version):

```
CLICKHOUSE_HOST=<qpot-db-host> ES_VERSION=8.11.0 docker compose \
  -f docker/clickhouse-kibana/docker-compose.kibana.yml up
```

This covers Discover, index patterns and the common Visualize aggregations over
QPot data. It is not a full Elasticsearch, so ES|QL, ML and other advanced
features are out of scope; honeypot data is read-only (QPot ingests via Vector),
while Kibana's saved objects are read/write in the `.kibana*` store.

## Attack map over ClickHouse

`docker-compose.attack-map.yml` runs the T-Pot attack map against QPot data with
no Elasticsearch. The connector joins the network under the alias
`elasticsearch`, so the attack map's DataServer (which hardcodes
`http://elasticsearch:9200`) reaches it unmodified:

```
CLICKHOUSE_HOST=<qpot-db-host> docker compose \
  -f docker/clickhouse-kibana/docker-compose.attack-map.yml up
```

QPot stores only a country ISO code per event, so the connector derives
country-centroid coordinates (see `geo.py`) for plotting; events with an unknown
country carry no coordinates and are skipped rather than placed at (0,0).

## Schema

Queries resolve to QPot's single ClickHouse `events` table (see
`internal/database/clickhouse.go`). Elasticsearch field names are mapped to that
table's real columns - e.g. `src_ip` and `geoip.ip` -> `source_ip`,
`geoip.country_name` -> `country`, `type` -> `event_type`. SQL safety: all
values are escaped and all identifiers/limits are sanitized before they reach
ClickHouse (see `test_main.py`).

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `CLICKHOUSE_HOST` | `clickhouse` | ClickHouse server hostname |
| `CLICKHOUSE_PORT` | `9000` | ClickHouse native protocol port |
| `CLICKHOUSE_DATABASE` | `qpot` | Database name |
| `CLICKHOUSE_USER` | `default` | Username |
| `CLICKHOUSE_PASSWORD` | `` | Password |
| `QPOT_ID` | `` | QPot instance ID |
| `QPOT_INSTANCE` | `` | QPot instance name |

## API Endpoints

### Elasticsearch-compatible

- `GET /` - Root info
- `GET /_cluster/health` - Cluster health
- `GET /_cluster/state` - Cluster state
- `GET /_cat/indices` - List indices
- `GET /{index}/_mapping` - Index mapping
- `POST /{index}/_search` - Search
- `GET /_xpack` - X-Pack info
- `GET /_aliases` - Aliases
- `GET /_nodes` - Nodes info
- `GET /_license` - License info

## Usage with Kibana

1. Configure Kibana to use this service as the Elasticsearch host:
   ```yaml
   elasticsearch.hosts: ["http://clickhouse-kibana:9200"]
   ```

2. Create index patterns in Kibana:
   - Pattern: `logstash-*`
   - Time field: `@timestamp`

3. Use Kibana Discover, Visualize, and Dashboard as normal

## Query Translation Examples

### Time Range Query
**Elasticsearch:**
```json
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h",
        "lte": "now"
      }
    }
  }
}
```

**ClickHouse:**
```sql
SELECT * FROM events 
WHERE timestamp >= now() - INTERVAL 24 HOUR 
  AND timestamp <= now()
```

### Type Filter
**Elasticsearch:**
```json
{
  "query": {
    "terms": {
      "type.keyword": ["Cowrie", "Dionaea"]
    }
  }
}
```

**ClickHouse:**
```sql
SELECT * FROM events 
WHERE type IN ('Cowrie', 'Dionaea')
```

## Limitations

- Write operations (indexing) are not supported (read-only)
- Some complex aggregations may not be fully supported
- Script queries are not supported
- Percolator queries are not supported

## Architecture

```
Kibana → ClickHouse-Kibana Connector → ClickHouse
   ↓
ES API Translation Layer
   ↓
SQL Query Builder
   ↓
ClickHouse Driver
```
