"""HTTP API for the Acme support agent (INTENTIONALLY VULNERABLE - scan target only)."""

import logging
import sqlite3

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from app.agent import DB_PATH, build_agent, llm

logger = logging.getLogger(__name__)
app = FastAPI(title="Acme Support")
support_agent = build_agent()


class ChatRequest(BaseModel):
    customer_email: str
    message: str


@app.post("/chat", response_class=HTMLResponse)  # AITM-AUTH-001: no authentication
def chat(body: ChatRequest) -> HTMLResponse:
    logger.info("Chat from %s: %s", body.customer_email, body.message)  # AITM-DATA-003: PII in logs
    # AITM-PI-001 (user text spliced into the prompt) and AITM-DATA-002 (email sent to the model)
    result = support_agent.invoke({"messages": [("user", f"Customer {body.customer_email} says: {body.message}")]})
    answer = result["messages"][-1].content
    return HTMLResponse(f"<div class='answer'>{answer}</div>")  # AITM-OUT-002: model output rendered as HTML


@app.get("/reports")  # AITM-AUTH-001
def run_report(question: str) -> dict:
    sql = llm.invoke(f"Write one SQLite query that answers: {question}").content  # AITM-PI-001
    with sqlite3.connect(DB_PATH) as connection:
        rows = connection.execute(sql).fetchall()  # AITM-OUT-001: model-written SQL executed
    return {"sql": sql, "rows": rows}
