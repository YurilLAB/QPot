# QPot ClickHouse-Kibana Connector

This service provides an Elasticsearch-compatible API layer on top of ClickHouse, allowing Kibana to connect to and visualize QPot data stored in ClickHouse.

## Features

- **Elasticsearch API Compatibility**: Translates ES queries to ClickHouse SQL
- **Kibana Support**: Use Kibana with ClickHouse as the backend
- **Index Pattern Support**: Handles `logstash-*` patterns
- **Query Translation**: Converts ES DSL to ClickHouse queries
- **Read-Optimized**: Designed for analytics workloads

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
SELECT * FROM honeypot_logs 
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
SELECT * FROM honeypot_logs 
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
