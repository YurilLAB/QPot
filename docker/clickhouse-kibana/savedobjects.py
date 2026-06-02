"""A small, file-backed Elasticsearch-document store for Kibana's system
indices (`.kibana*`, `.tasks`, etc.).

Kibana keeps its own state - index patterns, saved searches, visualizations,
dashboards, the config doc - in `.kibana*` indices that it both reads and
writes. Those documents are Kibana's, not honeypot data, so they cannot live in
ClickHouse. This store handles them separately with enough of the ES document
API (index/create/update/get/delete/mget/bulk/count/search) for Kibana to boot
and persist saved objects, persisted to a JSON file so they survive restarts.

It is deliberately simple: documents are keyed by (index, id); search supports
match_all and term/terms/ids/bool filters on document fields. It is not a
general ES engine - just enough that Kibana's system-index round-trips work.
"""

import json
import os
import threading
import time
from typing import Any, Dict, List, Optional


def is_system_index(index: str) -> bool:
    """Kibana/ES system indices the connector serves from this store rather
    than ClickHouse."""
    if not index:
        return False
    first = index.split(",")[0].strip().lstrip("/")
    return first.startswith(".")


class SavedObjectStore:
    def __init__(self, path: Optional[str] = None):
        self.path = path
        self._lock = threading.RLock()
        # index -> { id -> {"_seq_no":int, "_primary_term":1, "_version":int,
        #                    "_source": {...}} }
        self._data: Dict[str, Dict[str, Dict]] = {}
        self._seq = 0
        self._load()

    # ---- persistence -----------------------------------------------------
    def _load(self):
        if self.path and os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    blob = json.load(f)
                self._data = blob.get("data", {})
                self._seq = blob.get("seq", 0)
            except Exception:
                self._data, self._seq = {}, 0

    def _persist(self):
        if not self.path:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump({"data": self._data, "seq": self._seq}, f)
            os.replace(tmp, self.path)
        except Exception:
            pass

    def _next_seq(self) -> int:
        self._seq += 1
        return self._seq

    @staticmethod
    def _canon(index: str) -> str:
        # Collapse versioned/aliased Kibana indices (.kibana_8.1.0_001,
        # .kibana_task_manager) to a stable bucket per family.
        idx = index.strip().lstrip("/")
        for fam in (".kibana_task_manager", ".kibana_security", ".kibana_alerting",
                    ".kibana_ingest", ".kibana_analytics", ".kibana"):
            if idx.startswith(fam):
                return fam
        return idx

    # ---- document API ----------------------------------------------------
    def index_doc(self, index: str, doc_id: Optional[str], source: Dict,
                  create: bool = False) -> Dict:
        with self._lock:
            idx = self._canon(index)
            bucket = self._data.setdefault(idx, {})
            if doc_id is None:
                doc_id = f"auto-{self._next_seq()}"
            existed = doc_id in bucket
            if create and existed:
                raise KeyError("version_conflict_engine_exception")
            version = (bucket[doc_id]["_version"] + 1) if existed else 1
            bucket[doc_id] = {
                "_seq_no": self._next_seq(),
                "_primary_term": 1,
                "_version": version,
                "_source": source,
            }
            self._persist()
            return {
                "_index": index, "_id": doc_id, "_version": version,
                "result": "updated" if existed else "created",
                "_seq_no": bucket[doc_id]["_seq_no"], "_primary_term": 1,
                "_shards": {"total": 1, "successful": 1, "failed": 0},
            }

    def update_doc(self, index: str, doc_id: str, body: Dict) -> Dict:
        with self._lock:
            idx = self._canon(index)
            bucket = self._data.setdefault(idx, {})
            cur = bucket.get(doc_id)
            doc = dict(cur["_source"]) if cur else {}
            if "doc" in body and isinstance(body["doc"], dict):
                doc.update(body["doc"])
            elif "doc_as_upsert" in body:
                doc.update(body.get("doc", {}))
            res = self.index_doc(index, doc_id, doc)
            res["result"] = "updated"
            return res

    def get_doc(self, index: str, doc_id: str) -> Dict:
        with self._lock:
            bucket = self._data.get(self._canon(index), {})
            d = bucket.get(doc_id)
            if not d:
                return {"_index": index, "_id": doc_id, "found": False}
            return {"_index": index, "_id": doc_id, "_version": d["_version"],
                    "_seq_no": d["_seq_no"], "_primary_term": 1,
                    "found": True, "_source": d["_source"]}

    def delete_doc(self, index: str, doc_id: str) -> Dict:
        with self._lock:
            bucket = self._data.get(self._canon(index), {})
            existed = doc_id in bucket
            if existed:
                del bucket[doc_id]
                self._persist()
            return {"_index": index, "_id": doc_id,
                    "result": "deleted" if existed else "not_found",
                    "_shards": {"total": 1, "successful": 1, "failed": 0}}

    def mget(self, docs: List[Dict], default_index: Optional[str]) -> Dict:
        out = []
        for d in docs:
            index = d.get("_index", default_index)
            out.append(self.get_doc(index, d.get("_id")))
        return {"docs": out}

    # ---- query matching --------------------------------------------------
    def _matches(self, source: Dict, query: Optional[Dict]) -> bool:
        if not query:
            return True
        if "match_all" in query:
            return True
        if "match_none" in query:
            return False
        if "ids" in query:
            return False  # handled by caller via _id, treat here as no field match
        if "term" in query:
            for f, v in query["term"].items():
                val = v.get("value") if isinstance(v, dict) else v
                if _field(source, f) != val:
                    return False
            return True
        if "terms" in query:
            for f, vals in query["terms"].items():
                if _field(source, f) not in (vals or []):
                    return False
            return True
        if "match" in query:
            for f, v in query["match"].items():
                val = v.get("query") if isinstance(v, dict) else v
                if str(_field(source, f)) != str(val):
                    return False
            return True
        if "bool" in query:
            b = query["bool"]
            for clause in b.get("must", []) + b.get("filter", []):
                if not self._matches(source, clause):
                    return False
            if "should" in b and b["should"]:
                if not any(self._matches(source, c) for c in b["should"]):
                    # minimum_should_match defaults to 1 when there's no must/filter
                    if not (b.get("must") or b.get("filter")):
                        return False
            for clause in b.get("must_not", []):
                if self._matches(source, clause):
                    return False
            return True
        # Unknown query shape: don't exclude (Kibana filters client-side).
        return True

    def search(self, index: str, body: Dict) -> Dict:
        with self._lock:
            bucket = self._data.get(self._canon(index), {})
            query = (body or {}).get("query", {})
            size = (body or {}).get("size", 100)
            try:
                size = max(0, min(int(size), 10000))
            except (TypeError, ValueError):
                size = 100

            # ids query handled specially against the doc id
            id_filter = _collect_ids(query)
            hits = []
            for doc_id, d in bucket.items():
                if id_filter is not None and doc_id not in id_filter:
                    continue
                if id_filter is None and not self._matches(d["_source"], query):
                    continue
                hits.append({
                    "_index": index, "_id": doc_id, "_version": d["_version"],
                    "_seq_no": d["_seq_no"], "_primary_term": 1, "_score": 1.0,
                    "_source": d["_source"],
                })
            total = len(hits)
            return {
                "took": 1, "timed_out": False,
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0},
                "hits": {"total": {"value": total, "relation": "eq"},
                         "max_score": 1.0, "hits": hits[:size]},
            }

    def count(self, index: str, body: Dict) -> Dict:
        res = self.search(index, {**(body or {}), "size": 10000})
        return {"count": res["hits"]["total"]["value"],
                "_shards": {"total": 1, "successful": 1, "skipped": 0, "failed": 0}}

    def exists(self, index: str) -> bool:
        return self._canon(index) in self._data


def _field(source: Dict, path: str):
    cur: Any = source
    for part in path.replace(".keyword", "").split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _collect_ids(query: Optional[Dict]) -> Optional[set]:
    """Return the set of ids if the query is (or contains) an ids query, else
    None."""
    if not query:
        return None
    if "ids" in query:
        return set(query["ids"].get("values", []))
    if "bool" in query:
        for clause in (query["bool"].get("must", []) +
                       query["bool"].get("filter", [])):
            got = _collect_ids(clause)
            if got is not None:
                return got
    return None
