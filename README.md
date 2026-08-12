# nl2sql-guardrails-api

A small FastAPI service that turns natural-language questions into **governed, read-only SQL** against a database — with a schema allowlist, statement-injection defenses, automatic row limits, and an append-only audit log.

It's a safe, self-contained demonstration of the same "natural-language query layer over a real database" pattern used in production institutional data systems: the interesting part isn't the demo schema, it's the guardrail and audit layer around it.

## Why this exists

Letting an LLM (or any translator) turn user text into SQL is easy. Letting it do that *safely* against a real database is the actual engineering problem: you need to guarantee the generated query can't mutate data, can't reach tables it shouldn't, can't smuggle a second statement in behind a comment, and leaves a trail you can audit after the fact. This project implements that guardrail layer end to end, with tests that specifically try to break it.

## How it works

```
question
   │
   ▼
NL Translator  ──────►  generated SQL
(pattern-based by            │
 default; swap in an         ▼
 LLM via the same       Guardrail Layer
 interface)             ├─ SELECT-only
                         ├─ no multiple statements
                         ├─ no inline comments
                         ├─ table/column allowlist
                         └─ auto row LIMIT
                                │
                                ▼
                          SQLite execution
                                │
                                ▼
                          Audit log (JSONL)
```

The NL → SQL step is deliberately the "dumb" half of the system: `TemplateNLTranslator` is a deterministic, dependency-free pattern matcher, so the whole project runs with **zero API keys**. A production deployment would implement `LLMTranslatorProtocol` against OpenAI/Azure OpenAI/Anthropic and drop it in — the guardrail and audit code doesn't change at all, because it validates whatever SQL comes back regardless of who generated it.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

uvicorn main:app --reload
```

```bash
curl -X POST localhost:8000/query \
  -H "Content-Type: application/json" \
  -d '{"question": "top 3 customers by spend"}'
```

```json
{
  "question": "top 3 customers by spend",
  "sql": "SELECT c.name, ROUND(SUM(p.price * o.quantity), 2) AS total_spend FROM orders o JOIN customers c ON o.customer_id = c.id JOIN products p ON o.product_id = p.id GROUP BY c.id ORDER BY total_spend DESC LIMIT 3",
  "columns": ["name", "total_spend"],
  "rows": [
    {"name": "Alice Chen", "total_spend": 368.97},
    {"name": "Marco Diaz", "total_spend": 139.97},
    {"name": "Priya Nair", "total_spend": 103.5}
  ],
  "row_count": 3
}
```

Try also: `"how many customers are there"`, `"products under $50"`, `"orders for Alice Chen"`, `"products by category"`.

## Endpoints

| Method | Path          | Description                                   |
|--------|---------------|------------------------------------------------|
| POST   | `/query`      | Translate a question, guard it, execute it     |
| GET    | `/schema`     | List the allowlisted tables/columns            |
| GET    | `/audit-log`  | Recent accepted/rejected queries, most recent first |
| GET    | `/health`     | Liveness check                                  |

## Testing the guardrails, not just the happy path

`tests/test_main.py` includes unit tests that call `apply_guardrails()` directly with SQL a buggy or adversarial translator could in principle produce — a `DROP TABLE`, a semicolon-chained second statement, a comment-based injection, and an unknown table — and asserts each one is rejected with a specific reason.

```bash
pytest -q
```

## Tech stack

Python · FastAPI · Pydantic · SQLite · Pytest · GitHub Actions

## Possible extensions

- Real LLM-backed translator behind `LLMTranslatorProtocol`
- Per-caller rate limiting and API-key auth
- Row-level access control (RBAC) on top of the table allowlist
- Structured query cost/complexity scoring before execution
