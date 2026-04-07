#!/usr/bin/env python3
"""
QPot Attack Map Data Server
Modified from T-Pot Attack Map to support QPot ID and multiple database backends
"""

import datetime
import json
import time
import os
import sys
import pytz
import redis
from tzlocal import get_localzone

# Database backends - will try to import, fallback to stubs if not available
try:
    from elasticsearch import Elasticsearch
    ES_AVAILABLE = True
except ImportError:
    ES_AVAILABLE = False
    class Elasticsearch:
        def __init__(self, *args, **kwargs):
            raise Exception("Elasticsearch not installed")

try:
    import clickhouse_driver
    from clickhouse_driver import Client as ClickHouseClient
    CH_AVAILABLE = True
except ImportError:
    CH_AVAILABLE = False
    class ClickHouseClient:
        def __init__(self, *args, **kwargs):
            raise Exception("ClickHouse driver not installed")

# Configuration from environment
DB_BACKEND = os.getenv("QPOT_DB_BACKEND", "elasticsearch").lower()  # elasticsearch, clickhouse, timescaledb
ES_HOST = os.getenv("QPOT_ES_HOST", "elasticsearch")
ES_PORT = os.getenv("QPOT_ES_PORT", "9200")
CH_HOST = os.getenv("QPOT_CH_HOST", "clickhouse")
CH_PORT = int(os.getenv("QPOT_CH_PORT", "9000"))
CH_DATABASE = os.getenv("QPOT_CH_DATABASE", "qpot")
REDIS_HOST = os.getenv("QPOT_REDIS_HOST", "map_redis")
REDIS_PORT = int(os.getenv("QPOT_REDIS_PORT", "6379"))
REDIS_CHANNEL = os.getenv("QPOT_REDIS_CHANNEL", "attack-map-production")

# QPot Configuration
QPOT_ID = os.getenv("QPOT_ID", "")
QPOT_INSTANCE = os.getenv("QPOT_INSTANCE", "")
OUTPUT_TEXT = os.getenv("QPOT_ATTACKMAP_TEXT", "ENABLED").upper()

version = 'QPot Attack Map Data Server 3.0.0'
local_tz = get_localzone()

# Track disconnection state for reconnection messages
was_disconnected_db = False
was_disconnected_redis = False

# Global clients
db_client = None
redis_client = None
event_count = 1

# Color Codes for Attack Map
service_rgb = {
    'CHARGEN': '#4CAF50',
    'FTP-DATA': '#F44336',
    'FTP': '#FF5722',
    'SSH': '#FF9800',
    'TELNET': '#FFC107',
    'SMTP': '#8BC34A',
    'WINS': '#009688',
    'DNS': '#00BCD4',
    'DHCP': '#03A9F4',
    'TFTP': '#2196F3',
    'HTTP': '#3F51B5',
    'DICOM': '#9C27B0',
    'POP3': '#E91E63',
    'NTP': '#795548',
    'RPC': '#607D8B',
    'IMAP': '#9E9E9E',
    'SNMP': '#FF6B35',
    'LDAP': '#FF8E53',
    'HTTPS': '#0080FF',
    'SMB': '#BF00FF',
    'SMTPS': '#80FF00',
    'EMAIL': '#00FF80',
    'IPMI': '#00FFFF',
    'IPP': '#8000FF',
    'IMAPS': '#FF0080',
    'POP3S': '#80FF80',
    'NFS': '#FF8080',
    'SOCKS': '#8080FF',
    'SQL': '#00FF00',
    'ORACLE': '#FFFF00',
    'PPTP': '#FF00FF',
    'MQTT': '#00FF40',
    'SSDP': '#40FF00',
    'IEC104': '#FF4000',
    'HL7': '#4000FF',
    'MYSQL': '#00FF00',
    'RDP': '#FF0060',
    'IPSEC': '#60FF00',
    'SIP': '#FFCCFF',
    'POSTGRESQL': '#00CCFF',
    'ADB': '#FFCCCC',
    'VNC': '#0000FF',
    'REDIS': '#CC00FF',
    'IRC': '#FFCC00',
    'JETDIRECT': '#8000FF',
    'ELASTICSEARCH': '#FF8000',
    'INDUSTRIAL': '#80FF40',
    'MEMCACHED': '#40FF80',
    'MONGODB': '#FF4080',
    'SCADA': '#8040FF',
    'OTHER': '#78909C'
}

# Port to Protocol Mapping
PORT_MAP = {
    19: "CHARGEN",
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    2222: "SSH",
    23: "TELNET",
    2223: "TELNET",
    25: "SMTP",
    42: "WINS",
    53: "DNS",
    67: "DHCP",
    69: "TFTP",
    80: "HTTP",
    81: "HTTP",
    104: "DICOM",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "EMAIL",
    623: "IPMI",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1025: "NFS",
    1080: "SOCKS",
    1433: "SQL",
    1521: "ORACLE",
    1723: "PPTP",
    1883: "MQTT",
    1900: "SSDP",
    2404: "IEC104",
    2575: "HL7",
    3306: "MYSQL",
    3389: "RDP",
    5000: "IPSEC",
    5060: "SIP",
    5061: "SIP",
    5432: "POSTGRESQL",
    5555: "ADB",
    5900: "VNC",
    6379: "REDIS",
    6667: "IRC",
    8080: "HTTP",
    8888: "HTTP",
    8443: "HTTPS",
    9100: "JETDIRECT",
    9200: "ELASTICSEARCH",
    10001: "INDUSTRIAL",
    11112: "DICOM",
    11211: "MEMCACHED",
    27017: "MONGODB",
    50100: "SCADA"
}

# Honeypot types for querying
HONEYPOT_TYPES = [
    "Adbhoney", "Beelzebub", "Ciscoasa", "CitrixHoneypot", "ConPot",
    "Cowrie", "Ddospot", "Dicompot", "Dionaea", "ElasticPot", 
    "Endlessh", "Galah", "Glutton", "Go-pot", "H0neytr4p", "Hellpot", 
    "Heralding", "Honeyaml", "Honeytrap", "Honeypots", "Log4pot", 
    "Ipphoney", "Mailoney", "Medpot", "Miniprint", "Redishoneypot", 
    "Sentrypeer", "Tanner", "Wordpot"
]


def connect_redis():
    """Connect to Redis with persistence."""
    global redis_client
    try:
        if redis_client:
            redis_client.ping()
            return redis_client
    except Exception:
        pass
    
    redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0)
    return redis_client


def connect_database():
    """Connect to the configured database backend."""
    global db_client
    
    if DB_BACKEND == "elasticsearch":
        if not ES_AVAILABLE:
            raise Exception("Elasticsearch Python client not installed")
        es_url = f"http://{ES_HOST}:{ES_PORT}"
        db_client = Elasticsearch(es_url)
        return db_client
        
    elif DB_BACKEND == "clickhouse":
        if not CH_AVAILABLE:
            raise Exception("ClickHouse Python driver not installed")
        db_client = ClickHouseClient(host=CH_HOST, port=CH_PORT, database=CH_DATABASE)
        return db_client
        
    elif DB_BACKEND == "timescaledb":
        # TODO: Implement TimescaleDB support
        raise Exception("TimescaleDB support not yet implemented")
        
    else:
        raise Exception(f"Unknown database backend: {DB_BACKEND}")


def push_honeypot_stats(honeypot_stats):
    """Push stats to Redis."""
    redis_instance = connect_redis()
    # Add QPot metadata
    stats_with_meta = {
        **honeypot_stats,
        "qpot_id": QPOT_ID,
        "qpot_instance": QPOT_INSTANCE
    }
    tmp = json.dumps(stats_with_meta)
    redis_instance.publish(REDIS_CHANNEL, tmp)


def get_es_query_stats(timedelta):
    """Get Elasticsearch query for honeypot stats."""
    return {
        "bool": {
            "must": [],
            "filter": [
                {
                    "terms": {
                        "type.keyword": HONEYPOT_TYPES
                    }
                },
                {
                    "range": {
                        "@timestamp": {
                            "format": "strict_date_optional_time",
                            "gte": "now-" + timedelta,
                            "lte": "now"
                        }
                    }
                },
                {
                    "exists": {
                        "field": "geoip.ip"
                    }
                }
            ]
        }
    }


def get_ch_query_stats(timedelta):
    """Get ClickHouse query for honeypot stats."""
    # Map time delta to ClickHouse interval
    interval_map = {
        "1m": "1 MINUTE",
        "1h": "1 HOUR",
        "24h": "24 HOUR"
    }
    ch_interval = interval_map.get(timedelta, "24 HOUR")
    
    query = f"""
    SELECT count() as total
    FROM honeypot_logs
    WHERE type IN ({', '.join(["'" + t + "'" for t in HONEYPOT_TYPES])})
      AND timestamp >= now() - INTERVAL {ch_interval}
      AND geoip_ip IS NOT NULL
    """
    return query


def get_es_query_events(time_last, time_now):
    """Get Elasticsearch query for recent events."""
    return {
        "bool": {
            "must": [
                {
                    "query_string": {
                        "query": (
                            "type:(" + " OR ".join(HONEYPOT_TYPES) + ")"
                        )
                    }
                }
            ],
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gte": time_last,
                            "lte": time_now
                        }
                    }
                }
            ]
        }
    }


def get_ch_query_events(time_last, time_now):
    """Get ClickHouse query for recent events."""
    query = f"""
    SELECT *
    FROM honeypot_logs
    WHERE type IN ({', '.join(["'" + t + "'" for t in HONEYPOT_TYPES])})
      AND timestamp BETWEEN '{time_last}' AND '{time_now}'
    ORDER BY timestamp DESC
    LIMIT 100
    """
    return query


def query_database_stats(timedelta):
    """Query database for stats."""
    if DB_BACKEND == "elasticsearch":
        result = db_client.search(
            index="logstash-*",
            aggs={},
            size=0,
            track_total_hits=True,
            query=get_es_query_stats(timedelta)
        )
        return result['hits']['total']['value']
        
    elif DB_BACKEND == "clickhouse":
        result = db_client.execute(get_ch_query_stats(timedelta))
        return result[0][0] if result else 0
        
    return 0


def query_database_events(time_last, time_now):
    """Query database for recent events."""
    if DB_BACKEND == "elasticsearch":
        result = db_client.search(
            index="logstash-*",
            size=100,
            query=get_es_query_events(time_last, time_now)
        )
        return result['hits']['hits']
        
    elif DB_BACKEND == "clickhouse":
        # For ClickHouse, we need to transform the results to match ES format
        rows = db_client.execute(get_ch_query_events(time_last, time_now))
        hits = []
        for row in rows:
            # Map ClickHouse columns to ES-like structure
            # This assumes the table has columns matching the ES fields
            hit = {
                "_source": {
                    "type": row[0] if len(row) > 0 else "Unknown",
                    "geoip": {
                        "country_name": row[1] if len(row) > 1 else "",
                        "country_code2": row[2] if len(row) > 2 else "",
                        "continent_code": row[3] if len(row) > 3 else "",
                        "latitude": row[4] if len(row) > 4 else 0,
                        "longitude": row[5] if len(row) > 5 else 0,
                        "ip": row[6] if len(row) > 6 else ""
                    },
                    "geoip_ext": {
                        "latitude": row[7] if len(row) > 7 else 0,
                        "longitude": row[8] if len(row) > 8 else 0,
                        "ip": row[9] if len(row) > 9 else "",
                        "country_code2": row[10] if len(row) > 10 else "",
                        "country_name": row[11] if len(row) > 11 else ""
                    },
                    "t-pot_hostname": row[12] if len(row) > 12 else "",
                    "@timestamp": row[13].isoformat() if len(row) > 13 and row[13] else datetime.datetime.now(datetime.UTC).isoformat(),
                    "dest_port": row[14] if len(row) > 14 else 0,
                    "src_ip": row[15] if len(row) > 15 else "",
                    "src_port": row[16] if len(row) > 16 else 0,
                    "ip_rep": row[17] if len(row) > 17 else "reputation unknown"
                }
            }
            hits.append(hit)
        return hits
        
    return []


def update_honeypot_data():
    """Main loop for updating honeypot data."""
    global was_disconnected_db, was_disconnected_redis, event_count
    
    processed_data = []
    last = {"1m", "1h", "24h"}
    mydelta = 10
    time_last_request = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)
    last_stats_time = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=10)
    
    while True:
        now = datetime.datetime.now(datetime.UTC)
        
        # Get stats every 10 seconds
        if (now - last_stats_time).total_seconds() >= 10:
            last_stats_time = now
            honeypot_stats = {}
            
            for i in last:
                try:
                    count = query_database_stats(i)
                    honeypot_stats.update({"last_"+i: count})
                except Exception as e:
                    pass
                    
            honeypot_stats.update({"type": "Stats"})
            push_honeypot_stats(honeypot_stats)

        # Get recent events
        mylast_dt = time_last_request.replace(tzinfo=None)
        mynow_dt = (datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)).replace(tzinfo=None)
        
        mylast = str(mylast_dt).split(" ")
        mynow = str(mynow_dt).split(" ")
        
        time_last = mylast[0] + "T" + mylast[1] if len(mylast) > 1 else mylast[0]
        time_now = mynow[0] + "T" + mynow[1] if len(mynow) > 1 else mynow[0]
        
        try:
            hits = query_database_events(time_last, time_now)
            
            if len(hits) != 0:
                time_last_request = datetime.datetime.now(datetime.UTC) - datetime.timedelta(seconds=mydelta)
                for hit in hits:
                    try:
                        process_datas = process_data(hit)
                        if process_datas:
                            processed_data.append(process_datas)
                    except Exception:
                        pass
                        
            if len(processed_data) != 0:
                push(processed_data)
                processed_data = []
                
        except Exception as e:
            if not was_disconnected_db:
                print(f"[ ] Connection lost to database ({type(e).__name__}), retrying...")
                was_disconnected_db = True
            time.sleep(5)
            continue
            
        if was_disconnected_db:
            print("[*] Database connection re-established")
            was_disconnected_db = False
            
        time.sleep(0.5)


def process_data(hit):
    """Process a single hit into alert format."""
    alert = {}
    source = hit.get("_source", {})
    
    alert["honeypot"] = source.get("type", "Unknown")
    
    geoip = source.get("geoip", {})
    alert["country"] = geoip.get("country_name", "")
    alert["country_code"] = geoip.get("country_code2", "")
    alert["continent_code"] = geoip.get("continent_code", "")
    alert["latitude"] = geoip.get("latitude", 0)
    alert["longitude"] = geoip.get("longitude", 0)
    
    geoip_ext = source.get("geoip_ext", {})
    alert["dst_lat"] = geoip_ext.get("latitude", 0)
    alert["dst_long"] = geoip_ext.get("longitude", 0)
    alert["dst_ip"] = geoip_ext.get("ip", "")
    alert["dst_iso_code"] = geoip_ext.get("country_code2", "")
    alert["dst_country_name"] = geoip_ext.get("country_name", "")
    
    # Support both T-Pot and QPot hostname fields
    alert["tpot_hostname"] = source.get("t-pot_hostname", source.get("qpot_hostname", ""))
    alert["qpot_id"] = QPOT_ID
    alert["qpot_instance"] = QPOT_INSTANCE
    
    try:
        dt = datetime.datetime.fromisoformat(source.get("@timestamp", "").replace('Z', '+00:00'))
        alert["event_time"] = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        ts = source.get("@timestamp", "")
        alert["event_time"] = str(ts[0:10]) + " " + str(ts[11:19]) if len(ts) >= 19 else ts
        
    alert["iso_code"] = geoip.get("country_code2", "")
    alert["dst_port"] = source.get("dest_port", 0)
    alert["protocol"] = port_to_type(source.get("dest_port", 0))
    alert["src_ip"] = source.get("src_ip", "")
    alert["src_port"] = source.get("src_port", 0)
    alert["ip_rep"] = source.get("ip_rep", "reputation unknown")
    
    if alert["src_ip"]:
        try:
            alert["color"] = service_rgb[alert["protocol"].upper()]
        except Exception:
            alert["color"] = service_rgb["OTHER"]
        return alert
    else:
        print("SRC IP EMPTY")
        return None


def port_to_type(port):
    """Convert port number to protocol name."""
    try:
        return PORT_MAP.get(int(port), "OTHER")
    except Exception:
        return "OTHER"


def push(alerts):
    """Push alerts to Redis."""
    global event_count
    
    redis_instance = connect_redis()
    
    for alert in alerts:
        if OUTPUT_TEXT == "ENABLED":
            my_time = datetime.datetime.strptime(alert["event_time"], "%Y-%m-%d %H:%M:%S")
            my_time = my_time.replace(tzinfo=pytz.UTC)
            local_event_time = my_time.astimezone(local_tz)
            local_event_time = local_event_time.strftime("%Y-%m-%d %H:%M:%S")

            table_data = [
                [local_event_time, alert["country"], alert["src_ip"], alert["ip_rep"].title(),
                 alert["protocol"], alert["honeypot"], alert["tpot_hostname"]]
            ]

            min_widths = [19, 20, 15, 18, 10, 14, 14]

            for row in table_data:
                formatted_line = " | ".join(
                    "{:<{width}}".format(str(value), width=min_widths[i]) for i, value in enumerate(row))
                print(formatted_line)

        json_data = {
            "protocol": alert["protocol"],
            "color": alert["color"],
            "iso_code": alert["iso_code"],
            "honeypot": alert["honeypot"],
            "src_port": alert["src_port"],
            "event_time": alert["event_time"],
            "src_lat": alert["latitude"],
            "src_ip": alert["src_ip"],
            "ip_rep": alert["ip_rep"].title(),
            "type": "Traffic",
            "dst_long": alert["dst_long"],
            "continent_code": alert["continent_code"],
            "dst_lat": alert["dst_lat"],
            "event_count": event_count,
            "country": alert["country"],
            "src_long": alert["longitude"],
            "dst_port": alert["dst_port"],
            "dst_ip": alert["dst_ip"],
            "dst_iso_code": alert["dst_iso_code"],
            "dst_country_name": alert["dst_country_name"],
            "tpot_hostname": alert["tpot_hostname"],
            "qpot_id": alert.get("qpot_id", QPOT_ID),
            "qpot_instance": alert.get("qpot_instance", QPOT_INSTANCE)
        }
        event_count += 1
        tmp = json.dumps(json_data)
        redis_instance.publish(REDIS_CHANNEL, tmp)


def check_connections():
    """Check database and Redis connections on startup."""
    print("[*] Checking connections...")
    print(f"[*] Database backend: {DB_BACKEND}")
    print(f"[*] QPot ID: {QPOT_ID if QPOT_ID else 'Not configured'}")
    
    db_ready = False
    redis_ready = False
    db_waiting_printed = False
    redis_waiting_printed = False
    
    while not (db_ready and redis_ready):
        # Check Database
        if not db_ready:
            try:
                if DB_BACKEND == "elasticsearch":
                    db_client.info()
                elif DB_BACKEND == "clickhouse":
                    db_client.execute("SELECT 1")
                print(f"[*] {DB_BACKEND.title()} connection established")
                db_ready = True
            except Exception as e:
                if not db_waiting_printed:
                    print(f"[...] Waiting for {DB_BACKEND}... (Error: {type(e).__name__})")
                    db_waiting_printed = True
        
        # Check Redis
        if not redis_ready:
            try:
                r = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=0)
                r.ping()
                print("[*] Redis connection established")
                redis_ready = True
            except Exception as e:
                if not redis_waiting_printed:
                    print(f"[...] Waiting for Redis... (Error: {type(e).__name__})")
                    redis_waiting_printed = True
        
        if not (db_ready and redis_ready):
            time.sleep(5)
    
    return True


if __name__ == '__main__':
    print(version)
    print(f"[*] QPot Attack Map Data Server")
    print(f"[*] QPot ID: {QPOT_ID if QPOT_ID else 'Not configured'}")
    
    # Connect to database
    try:
        connect_database()
    except Exception as e:
        print(f"[!] Failed to connect to database: {e}")
        sys.exit(1)
    
    # Check connections
    check_connections()
    print("[*] Starting data server...\n")
    
    try:
        while True:
            try:
                update_honeypot_data()
            except Exception as e:
                error_type = type(e).__name__
                error_msg = str(e)
                
                if "6379" in error_msg or "Redis" in error_msg or "redis" in error_msg.lower():
                    if not was_disconnected_redis:
                        print(f"[ ] Connection lost to Redis ({error_type}), retrying...")
                        was_disconnected_redis = True
                else:
                    if not was_disconnected_db:
                        print(f"[ ] Connection lost to database ({error_type}), retrying...")
                        was_disconnected_db = True
                
                time.sleep(5)
                
                if was_disconnected_redis:
                    try:
                        r = connect_redis()
                        r.ping()
                        print("[*] Redis connection re-established")
                        was_disconnected_redis = False
                    except:
                        pass
                        
                if was_disconnected_db:
                    try:
                        if DB_BACKEND == "elasticsearch":
                            db_client.info()
                        elif DB_BACKEND == "clickhouse":
                            db_client.execute("SELECT 1")
                        print(f"[*] {DB_BACKEND.title()} connection re-established")
                        was_disconnected_db = False
                    except:
                        pass

    except KeyboardInterrupt:
        print('\nSHUTTING DOWN')
        exit()
