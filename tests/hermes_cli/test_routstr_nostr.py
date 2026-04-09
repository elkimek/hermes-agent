"""Tests for Nostr node discovery."""

import pytest
from hermes_cli.routstr.nostr_discovery import (
    _parse_node_event, _deduplicate_nodes, clear_cache,
)


class TestParseNodeEvent:
    def test_basic_event(self):
        event = {
            "pubkey": "abc123",
            "created_at": 1700000000,
            "content": '{"name": "TestNode", "about": "A test node"}',
            "tags": [
                ["d", "test-node-1"],
                ["u", "https://node1.routstr.com"],
                ["u", "http://abc123.onion"],
                ["mint", "https://mint.minibits.cash/Bitcoin"],
                ["version", "0.3.0"],
            ],
        }
        node = _parse_node_event(event)
        assert node["id"] == "test-node-1"
        assert node["name"] == "TestNode"
        assert node["about"] == "A test node"
        assert node["urls"] == ["https://node1.routstr.com", "http://abc123.onion"]
        assert node["onion"] == "http://abc123.onion"
        assert node["mints"] == ["https://mint.minibits.cash/Bitcoin"]
        assert node["version"] == "0.3.0"
        assert node["pubkey"] == "abc123"

    def test_missing_content(self):
        event = {
            "pubkey": "def456",
            "created_at": 1700000000,
            "tags": [["d", "node-2"], ["u", "https://example.com"]],
        }
        node = _parse_node_event(event)
        assert node["id"] == "node-2"
        assert node["name"] == "node-2"  # falls back to d-tag
        assert node["about"] == ""

    def test_no_d_tag_uses_pubkey(self):
        event = {
            "pubkey": "pubkey123",
            "created_at": 1700000000,
            "tags": [["u", "https://example.com"]],
        }
        node = _parse_node_event(event)
        assert node["id"] == "pubkey123"


class TestDeduplicateNodes:
    def test_keeps_most_recent(self):
        events = [
            {"pubkey": "a", "created_at": 100, "tags": [["d", "node1"], ["u", "https://old.com"]], "content": "{}"},
            {"pubkey": "a", "created_at": 200, "tags": [["d", "node1"], ["u", "https://new.com"]], "content": "{}"},
        ]
        nodes = _deduplicate_nodes(events)
        assert len(nodes) == 1
        assert nodes[0]["urls"] == ["https://new.com"]

    def test_different_ids_kept(self):
        events = [
            {"pubkey": "a", "created_at": 100, "tags": [["d", "node1"], ["u", "https://a.com"]], "content": "{}"},
            {"pubkey": "b", "created_at": 100, "tags": [["d", "node2"], ["u", "https://b.com"]], "content": "{}"},
        ]
        nodes = _deduplicate_nodes(events)
        assert len(nodes) == 2

    def test_empty(self):
        assert _deduplicate_nodes([]) == []


class TestClearCache:
    def test_clears(self):
        clear_cache()
        from hermes_cli.routstr.nostr_discovery import _cached_nodes
        assert _cached_nodes is None
