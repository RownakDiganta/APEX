# browser_parser.py
# Stateless parser that converts a BrowserObservation into Endpoint, Form, AuthFlow, and Token EKG node/edge deltas.
"""Parses a BrowserObservation (real or synthetic, dry_run-aware) into
memfabric Node/Edge deltas — Endpoint, Form, AuthFlow, Token nodes.
"""
from __future__ import annotations

from memfabric.ids import new_id, now
from memfabric.types import Edge, Node, ParsedObservation

from apex_host.types import BrowserObservation

_PASSWORD_FIELD_HINTS = ("pass", "pwd", "secret")


class BrowserParser:
    """Stateless parser: BrowserObservation -> ParsedObservation."""

    def parse_observation(
        self, obs: BrowserObservation, *, target: str, source: str = "browser"
    ) -> ParsedObservation:
        nodes: list[Node] = []
        edges: list[Edge] = []
        timestamp = now()

        endpoint_id = f"endpoint:{obs.url}"
        nodes.append(
            Node(
                id=endpoint_id,
                type="endpoint",
                props={"url": obs.url, "title": obs.title, "target": target},
                confidence=0.8,
                source=source,
                first_seen=timestamp,
                last_seen=timestamp,
            )
        )

        for i, form in enumerate(obs.forms):
            form_id = f"form:{obs.url}:{i}"
            fields = [str(f) for f in form.get("fields", [])]
            nodes.append(
                Node(
                    id=form_id,
                    type="form",
                    props={
                        "action": form.get("action", ""),
                        "method": form.get("method", "GET"),
                        "fields": fields,
                    },
                    confidence=0.75,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=endpoint_id,
                    to_id=form_id,
                    type="contains",
                    props={},
                    confidence=0.75,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

            is_auth_form = any(
                hint in f.lower() for f in fields for hint in _PASSWORD_FIELD_HINTS
            )
            if is_auth_form:
                auth_id = f"auth_flow:{obs.url}:{i}"
                nodes.append(
                    Node(
                        id=auth_id,
                        type="auth_flow",
                        props={"url": obs.url, "form_action": form.get("action", "")},
                        confidence=0.75,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )
                edges.append(
                    Edge(
                        id=new_id(),
                        from_id=endpoint_id,
                        to_id=auth_id,
                        type="requires",
                        props={},
                        confidence=0.75,
                        source=source,
                        first_seen=timestamp,
                        last_seen=timestamp,
                    )
                )

        for hint in obs.auth_hints:
            auth_hint_id = f"auth_flow:{obs.url}:hint:{hint}"
            nodes.append(
                Node(
                    id=auth_hint_id,
                    type="auth_flow",
                    props={"url": obs.url, "hint": hint},
                    confidence=0.5,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=endpoint_id,
                    to_id=auth_hint_id,
                    type="requires",
                    props={},
                    confidence=0.5,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        for token in obs.tokens:
            token_id = f"token:{obs.url}:{token[:24]}"
            nodes.append(
                Node(
                    id=token_id,
                    type="token",
                    props={"name": token},
                    confidence=0.6,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )
            edges.append(
                Edge(
                    id=new_id(),
                    from_id=endpoint_id,
                    to_id=token_id,
                    type="contains",
                    props={},
                    confidence=0.6,
                    source=source,
                    first_seen=timestamp,
                    last_seen=timestamp,
                )
            )

        return ParsedObservation(node_deltas=nodes, edge_deltas=edges)
