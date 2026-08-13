# graphql_parser.py
# Stateless parser: a read-only GraphQL introspection response -> api_schema node recording type/field NAMES only (never values). Discovery/mapping, never an attack.
"""Parse a GraphQL introspection response into a schema map (§28.22).

DISCOVERY ONLY. The introspection query (issued by ``WebPlanner``) is a
read-only schema READ, never a mutation. This parser records only the schema's
STRUCTURE — type names and field names (bounded) — into a single ``api_schema``
node linked to the GraphQL ``endpoint``. It never records a value, executes a
query, or emits any follow-up request; it is a stateless
``RawObservation`` → ``ParsedObservation`` transform like every other parser.

A response that is not a valid introspection result (no ``data.__schema``)
produces an empty ``ParsedObservation`` — a probed-but-non-GraphQL endpoint
records nothing new.
"""
from __future__ import annotations

import json

from memfabric.ids import now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.graph_ids import (
    api_schema_id as _api_schema_id,
    contains_edge_id as _contains_edge_id,
    endpoint_id as _endpoint_id,
    exposes_edge_id as _exposes_edge_id,
    host_id as _host_id_fn,
)
from apex_host.parsers.command_parser import _host_from_target, _normalize_url

#: Bounds on the recorded schema map — keeps the api_schema node bounded on a
#: large schema. Names only; never values.
_MAX_TYPE_NAMES = 100
_MAX_FIELD_NAMES = 200


class GraphQLParser:
    """Stateless parser: GraphQL introspection JSON -> ParsedObservation."""

    def parse_introspection(
        self, output: str, *, target: str, host_ip: str = ""
    ) -> ParsedObservation:
        text = (output or "").strip()
        if not text:
            return ParsedObservation()
        try:
            data = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return ParsedObservation()
        if not isinstance(data, dict):
            return ParsedObservation()
        schema = (data.get("data") or {}).get("__schema") if isinstance(data.get("data"), dict) else None
        if not isinstance(schema, dict):
            return ParsedObservation()

        timestamp = now()
        url = _normalize_url(target)
        host = _host_from_target(host_ip) if host_ip.strip() else _host_from_target(target)
        h_id = _host_id_fn(host)
        ep_id = _endpoint_id(url)
        sc_id = _api_schema_id(url)

        # Collect type and field NAMES (skip GraphQL introspection meta types
        # like __Schema/__Type). Bounded. Never any value.
        type_names: list[str] = []
        field_names: list[str] = []
        for t in schema.get("types") or []:
            if not isinstance(t, dict):
                continue
            name = str(t.get("name", ""))
            if not name or name.startswith("__"):
                continue
            if len(type_names) < _MAX_TYPE_NAMES:
                type_names.append(name)
            for f in t.get("fields") or []:
                if isinstance(f, dict) and f.get("name") and len(field_names) < _MAX_FIELD_NAMES:
                    field_names.append(str(f["name"]))

        query_type = ""
        if isinstance(schema.get("queryType"), dict):
            query_type = str(schema["queryType"].get("name", ""))
        mutation_type = ""
        if isinstance(schema.get("mutationType"), dict):
            mutation_type = str(schema["mutationType"].get("name", ""))

        # The GraphQL endpoint (confirmed by a valid introspection response).
        endpoint = Node(
            id=ep_id, type="endpoint",
            props={"url": url, "fetched": True, "graphql": True, "content_kind": "graphql"},
            confidence=0.85, source="graphql", first_seen=timestamp, last_seen=timestamp,
        )
        schema_node = Node(
            id=sc_id, type="api_schema",
            props={
                "endpoint_url": url,
                "query_type": query_type,
                "mutation_type": mutation_type,
                "type_names": sorted(set(type_names)),
                "type_count": len(type_names),
                "field_names": sorted(set(field_names)),
                "field_count": len(field_names),
            },
            confidence=0.85, source="graphql", first_seen=timestamp, last_seen=timestamp,
        )
        edges = [
            Edge(
                id=_exposes_edge_id(h_id, ep_id), from_id=h_id, to_id=ep_id, type="exposes",
                props={}, confidence=0.85, source="graphql",
                first_seen=timestamp, last_seen=timestamp,
            ),
            Edge(
                id=_contains_edge_id(ep_id, sc_id), from_id=ep_id, to_id=sc_id, type="contains",
                props={}, confidence=0.85, source="graphql",
                first_seen=timestamp, last_seen=timestamp,
            ),
        ]
        return ParsedObservation(node_deltas=[endpoint, schema_node], edge_deltas=edges)
