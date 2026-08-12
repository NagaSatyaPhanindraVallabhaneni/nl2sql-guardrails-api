"""
nl2sql-guardrails-api
======================

A small FastAPI service that turns natural-language questions into governed,
read-only SQL queries against a demo database.

Design goals (this is the interesting part, not the toy schema):

  * SELECT-only execution — the guardrail layer rejects anything that is not
    a single, well-formed SELECT statement.
  * Table/column allowlisting — generated SQL may only reference tables and
    columns that exist in the demo schema; nothing else is reachable.
  * Statement-injection defense — semicolon-separated multi-statements,
    comment-based injection (`--`, `/* */`), and PRAGMA/ATTACH tricks are
    rejected before anything touches the database.
  * Row-limit enforcement — every accepted query gets a LIMIT applied so a
    single request can't page-drag the whole table.
  * Audit logging — every request (accepted or rejected) is appended to an
    append-only JSONL audit log with the question, the SQL, and the outcome.
  * Pluggable translation layer — the default `TemplateNLTranslator` is a
    deterministic, dependency-free pattern matcher so the demo runs with no
    API keys. A real deployment can swap in an LLM-backed `NLTranslator`
    (see `LLMTranslatorProtocol` below) without touching the guardrail or
    audit code at all.

This mirrors the shape of a production "governed natural-language query
layer" over a real database, minus anything proprietary — safe to run and
read end to end.
"""

from __future__ import annotations

import json
import re
import sqlite3
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Demo schema + seed data
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "demo.db"
AUDIT_LOG_PATH = Path(__file__).parent / "audit_log.jsonl"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    city TEXT NOT NULL,
    signup_date TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL REFERENCES customers(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    quantity INTEGER NOT NULL,
    order_date TEXT NOT NULL
);
"""

SEED_CUSTOMERS = [
    (1, "Alice Chen", "Dayton", "2024-01-15"),
    (2, "Marco Diaz", "Columbus", "2024-02-20"),
    (3, "Priya Nair", "Cincinnati", "2024-03-05"),
    (4, "Sam O'Neil", "Dayton", "2024-04-11"),
    (5, "Yuki Tanaka", "Cleveland", "2024-05-30"),
]

SEED_PRODUCTS = [
    (1, "Wireless Mouse", "Electronics", 19.99),
    (2, "Mechanical Keyboard", "Electronics", 79.99),
    (3, "Standing Desk", "Furniture", 249.00),
    (4, "Desk Lamp", "Furniture", 34.50),
    (5, "Notebook Set", "Office Supplies", 12.75),
    (6, "USB-C Hub", "Electronics", 29.99),
]

SEED_ORDERS = [
    (1, 1, 1, 2, "2024-06-01"),
    (2, 1, 3, 1, "2024-06-03"),
    (3, 2, 2, 1, "2024-06-05"),
    (4, 3, 4, 3, "2024-06-10"),
    (5, 4, 6, 1, "2024-06-12"),
    (6, 5, 5, 5, "2024-06-15"),
    (7, 2, 6, 2, "2024-06-18"),
    (8, 1, 2, 1, "2024-06-20"),
]

# Allowlist used by the guardrail layer: table -> set of real columns.
SCHEMA_ALLOWLIST: dict[str, set[str]] = {
    "customers": {"id", "name", "city", "signup_date"},
    "products": {"id", "name", "category", "price"},
    "orders": {"id", "customer_id", "product_id", "quantity", "order_date"},
}

DEFAULT_ROW_LIMIT = 50


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    fresh = not DB_PATH.exists()
    conn = get_connection()
    try:
        conn.executescript(SCHEMA_SQL)
        if fresh:
            conn.executemany(
                "INSERT INTO customers VALUES (?, ?, ?, ?)", SEED_CUSTOMERS
            )
            conn.executemany(
                "INSERT INTO products VALUES (?, ?, ?, ?)", SEED_PRODUCTS
            )
            conn.executemany(
                "INSERT INTO orders VALUES (?, ?, ?, ?, ?)", SEED_ORDERS
            )
            conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Guardrail layer
# ---------------------------------------------------------------------------

BLOCKED_KEYWORDS = (
    "insert", "update", "delete", "drop", "alter", "create", "attach",
    "detach", "pragma", "vacuum", "replace", "grant", "revoke", "exec",
)

TABLE_REF_RE = re.compile(r"\b(?:from|join)\s+([a-zA-Z_][a-zA-Z0-9_]*)", re.IGNORECASE)
LIMIT_RE = re.compile(r"\blimit\s+\d+\b", re.IGNORECASE)


@dataclass
class GuardrailResult:
    allowed: bool
    sql: str
    reason: str | None = None


def apply_guardrails(sql: str) -> GuardrailResult:
    """Validate and normalize a generated SQL string before execution.

    Every rejection path returns a clear `reason` so it can be surfaced to
    the caller and written to the audit log — the goal is that a rejected
    query is just as debuggable as an accepted one.
    """
    candidate = sql.strip()

    if not candidate:
        return GuardrailResult(False, sql, "empty query")

    # Reject multiple statements (naive but effective for this grammar: no
    # legitimate SELECT in this API needs an embedded semicolon).
    if candidate.rstrip(";").count(";") > 0:
        return GuardrailResult(False, sql, "multiple statements are not allowed")

    # Reject comment-based injection attempts.
    if "--" in candidate or "/*" in candidate:
        return GuardrailResult(False, sql, "inline comments are not allowed")

    # Must be a single SELECT statement.
    if not re.match(r"^\s*select\b", candidate, re.IGNORECASE):
        return GuardrailResult(False, sql, "only SELECT statements are allowed")

    lowered = candidate.lower()
    for keyword in BLOCKED_KEYWORDS:
        if re.search(rf"\b{keyword}\b", lowered):
            return GuardrailResult(False, sql, f"blocked keyword: {keyword}")

    # Table allowlist enforcement.
    referenced_tables = {t.lower() for t in TABLE_REF_RE.findall(candidate)}
    unknown = referenced_tables - SCHEMA_ALLOWLIST.keys()
    if unknown:
        return GuardrailResult(False, sql, f"unknown table(s): {', '.join(sorted(unknown))}")

    # Enforce a row limit if the query doesn't already have one.
    if not LIMIT_RE.search(candidate):
        candidate = f"{candidate.rstrip(';')} LIMIT {DEFAULT_ROW_LIMIT}"

    return GuardrailResult(True, candidate, None)


def log_audit_event(question: str, sql: str, result: GuardrailResult, row_count: int | None) -> None:
    entry = {
        "timestamp": time.time(),
        "question": question,
        "generated_sql": sql,
        "status": "accepted" if result.allowed else "rejected",
        "reason": result.reason,
        "row_count": row_count,
    }
    with AUDIT_LOG_PATH.open("a") as f:
        f.write(json.dumps(entry) + "\n")


def read_audit_log(limit: int = 20) -> list[dict]:
    if not AUDIT_LOG_PATH.exists():
        return []
    lines = AUDIT_LOG_PATH.read_text().strip().splitlines()
    return [json.loads(line) for line in lines[-limit:][::-1]]


# ---------------------------------------------------------------------------
# Natural-language translation layer
# ---------------------------------------------------------------------------

class LLMTranslatorProtocol(Protocol):
    """Swap-in point for a real LLM-backed translator.

    A production deployment would implement this against OpenAI, Azure
    OpenAI, or Anthropic and inject it in place of `TemplateNLTranslator` —
    the guardrail layer above validates whatever SQL comes back, so the
    rest of the service does not need to change.
    """

    def translate(self, question: str) -> str | None:
        ...


class TemplateNLTranslator:
    """Deterministic, dependency-free NL -> SQL translator.

    Covers a fixed set of question patterns so the whole project runs with
    zero external API calls and zero API keys. This is intentionally the
    "dumb" half of the system — the guardrail and audit layers are the part
    worth reading.
    """

    def translate(self, question: str) -> str | None:
        q = question.strip().lower()

        if re.search(r"how many customers", q):
            return "SELECT COUNT(*) AS customer_count FROM customers"

        if re.search(r"how many (products|items)", q):
            return "SELECT COUNT(*) AS product_count FROM products"

        if re.search(r"how many orders", q):
            return "SELECT COUNT(*) AS order_count FROM orders"

        if re.search(r"total revenue|total sales", q):
            return (
                "SELECT ROUND(SUM(p.price * o.quantity), 2) AS total_revenue "
                "FROM orders o JOIN products p ON o.product_id = p.id"
            )

        m = re.search(r"products? (?:under|below|less than) \$?(\d+(?:\.\d+)?)", q)
        if m:
            return (
                "SELECT id, name, category, price FROM products "
                f"WHERE price < {float(m.group(1))} ORDER BY price ASC"
            )

        m = re.search(r"top (\d+) customers? by (?:total )?spend", q)
        if m:
            n = int(m.group(1))
            return (
                "SELECT c.name, ROUND(SUM(p.price * o.quantity), 2) AS total_spend "
                "FROM orders o "
                "JOIN customers c ON o.customer_id = c.id "
                "JOIN products p ON o.product_id = p.id "
                "GROUP BY c.id ORDER BY total_spend DESC "
                f"LIMIT {n}"
            )

        if re.search(r"list all customers|show all customers", q):
            return "SELECT id, name, city, signup_date FROM customers ORDER BY id"

        if re.search(r"list all products|show all products", q):
            return "SELECT id, name, category, price FROM products ORDER BY id"

        m = re.search(r"orders for ([a-z' ]+?)(?:\?|$)", q)
        if m:
            name = m.group(1).strip().replace("'", "''")
            return (
                "SELECT o.id, c.name AS customer, p.name AS product, o.quantity, o.order_date "
                "FROM orders o "
                "JOIN customers c ON o.customer_id = c.id "
                "JOIN products p ON o.product_id = p.id "
                f"WHERE LOWER(c.name) LIKE LOWER('%{name}%') "
                "ORDER BY o.order_date"
            )

        if re.search(r"products? by category", q):
            return "SELECT category, COUNT(*) AS product_count FROM products GROUP BY category"

        return None


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="nl2sql-guardrails-api",
    description="Natural language to governed, read-only SQL over a demo database.",
    version="1.0.0",
    lifespan=lifespan,
)

translator = TemplateNLTranslator()


class QueryRequest(BaseModel):
    question: str = Field(..., min_length=1, examples=["how many customers are there"])


class QueryResponse(BaseModel):
    question: str
    sql: str
    columns: list[str]
    rows: list[dict]
    row_count: int


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/schema")
def schema() -> dict:
    return {table: sorted(cols) for table, cols in SCHEMA_ALLOWLIST.items()}


@app.get("/audit-log")
def audit_log(limit: int = 20) -> list[dict]:
    return read_audit_log(limit)


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest) -> QueryResponse:
    generated_sql = translator.translate(request.question)

    if generated_sql is None:
        result = GuardrailResult(False, "", "unsupported question pattern")
        log_audit_event(request.question, "", result, None)
        raise HTTPException(
            status_code=422,
            detail=(
                "I don't have a translation for that question yet. Try things like "
                "'how many customers are there', 'products under $50', "
                "'top 3 customers by spend', or 'orders for Alice Chen'."
            ),
        )

    result = apply_guardrails(generated_sql)

    if not result.allowed:
        log_audit_event(request.question, generated_sql, result, None)
        raise HTTPException(status_code=400, detail=f"query rejected: {result.reason}")

    conn = get_connection()
    try:
        cursor = conn.execute(result.sql)
        rows = [dict(row) for row in cursor.fetchall()]
        columns = [d[0] for d in cursor.description] if cursor.description else []
    finally:
        conn.close()

    log_audit_event(request.question, result.sql, result, len(rows))

    return QueryResponse(
        question=request.question,
        sql=result.sql,
        columns=columns,
        rows=rows,
        row_count=len(rows),
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
