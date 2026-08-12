from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import main as app_module
from main import app, apply_guardrails


@pytest.fixture(autouse=True)
def clean_db_and_log(tmp_path, monkeypatch):
    """Give every test a fresh, isolated demo DB and audit log."""
    monkeypatch.setattr(app_module, "DB_PATH", tmp_path / "demo.db")
    monkeypatch.setattr(app_module, "AUDIT_LOG_PATH", tmp_path / "audit_log.jsonl")
    app_module.init_db()
    yield


client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_schema_lists_allowlisted_tables():
    resp = client.get("/schema")
    assert resp.status_code == 200
    body = resp.json()
    assert set(body.keys()) == {"customers", "products", "orders"}
    assert "price" in body["products"]


def test_simple_count_query():
    resp = client.post("/query", json={"question": "how many customers are there"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["rows"][0]["customer_count"] == 5


def test_products_under_price_filter():
    resp = client.post("/query", json={"question": "products under $50"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["row_count"] > 0
    assert all(row["price"] < 50 for row in body["rows"])


def test_top_n_customers_by_spend():
    resp = client.post("/query", json={"question": "top 2 customers by spend"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["row_count"] == 2
    spends = [row["total_spend"] for row in body["rows"]]
    assert spends == sorted(spends, reverse=True)


def test_orders_for_named_customer():
    resp = client.post("/query", json={"question": "orders for Alice Chen"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["row_count"] > 0
    assert all(row["customer"] == "Alice Chen" for row in body["rows"])


def test_unsupported_question_returns_422():
    resp = client.post("/query", json={"question": "what is the meaning of life"})
    assert resp.status_code == 422


def test_query_is_audited():
    client.post("/query", json={"question": "how many orders"})
    resp = client.get("/audit-log")
    assert resp.status_code == 200
    entries = resp.json()
    assert entries[0]["question"] == "how many orders"
    assert entries[0]["status"] == "accepted"


# --- Guardrail unit tests: exercise the validator directly with SQL that a
# malicious or buggy translator could in principle produce. -----------------

def test_guardrail_rejects_non_select():
    result = apply_guardrails("DROP TABLE customers")
    assert not result.allowed
    assert "SELECT" in result.reason


def test_guardrail_rejects_multiple_statements():
    result = apply_guardrails("SELECT * FROM customers; DROP TABLE customers;")
    assert not result.allowed
    assert "multiple statements" in result.reason


def test_guardrail_rejects_comment_injection():
    result = apply_guardrails("SELECT * FROM customers -- WHERE id = 1")
    assert not result.allowed
    assert "comment" in result.reason


def test_guardrail_rejects_unknown_table():
    result = apply_guardrails("SELECT * FROM secret_admin_table")
    assert not result.allowed
    assert "unknown table" in result.reason


def test_guardrail_rejects_blocked_keyword_disguised_in_select():
    result = apply_guardrails("SELECT * FROM customers WHERE id = (INSERT INTO x VALUES (1))")
    assert not result.allowed


def test_guardrail_adds_default_limit():
    result = apply_guardrails("SELECT * FROM customers")
    assert result.allowed
    assert "LIMIT" in result.sql.upper()


def test_guardrail_respects_existing_limit():
    result = apply_guardrails("SELECT * FROM customers LIMIT 5")
    assert result.allowed
    assert result.sql.upper().count("LIMIT") == 1
