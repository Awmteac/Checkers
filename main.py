#!/usr/bin/env python3
"""
ASAS Debitando Checker — Web Edition
Wraps AuthNetAcceptJsAdapter from checkers.py in a FastAPI service.
Streams per-card results over WebSocket. Railway-ready.
"""

import asyncio
import logging
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional, Set

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from checkers import (
    GatewayConfig,
    GatewayType,
    GatewayFactory,
    BaseGatewayAdapter,
    ProxyConfig,
    ProxyRotator,
    LRUCache,
    CardInput,
    CheckResult,
    ResultStatus,
    IdentityGenerator,
    parse_card_line,
)

CONCURRENCY_LIMIT = int(os.environ.get("CONCURRENCY_LIMIT", "10"))
PER_CARD_TIMEOUT = float(os.environ.get("PER_CARD_TIMEOUT", "30.0"))
JOB_TTL_SECONDS = int(os.environ.get("JOB_TTL_SECONDS", "3600"))
MAX_CARDS_PER_JOB = int(os.environ.get("MAX_CARDS_PER_JOB", "5000"))

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("asas-web")


class Job:
    def __init__(self, job_id: str, total: int):
        self.id = job_id
        self.total = total
        self.processed = 0
        self.approved = 0
        self.declined = 0
        self.errors = 0
        self.results: List[CheckResult] = []
        self.subscribers: Set[WebSocket] = set()
        self.finished = False
        self.created_at = time.time()
        self.task: Optional[asyncio.Task] = None
        self.lock = asyncio.Lock()


JOBS: Dict[str, Job] = {}
JOBS_LOCK = asyncio.Lock()

GATEWAY: Optional[BaseGatewayAdapter] = None
PROXY: Optional[ProxyRotator] = None
CACHE: Optional[LRUCache] = None


def build_gateway() -> BaseGatewayAdapter:
    gateway_config = GatewayConfig(
        name="AuthNet Accept.js",
        gateway_type=GatewayType.AUTHNET_ACCEPTJS,
        endpoint_ref="AUTHNET_ENDPOINT",
        merchant_ref="AUTHNET_MERCHANT_ID",
        client_ref="AUTHNET_CLIENT_KEY",
        timeout_ms=30000,
        retry_limit=3,
        backoff_factor=1.5,
        backoff_max_ms=30000,
        circuit_breaker_threshold=10,
        circuit_breaker_timeout=30,
        rate_limit_requests=1000,
        rate_limit_window=60,
    )
    proxy_config = ProxyConfig(pool_ref="PROXY_POOL")
    proxy = ProxyRotator(proxy_config)
    cache = LRUCache(max_size=1000, ttl_seconds=300)
    return GatewayFactory.create(
        GatewayType.AUTHNET_ACCEPTJS,
        gateway_config,
        proxy,
        cache,
    )


async def process_one_card(card: CardInput) -> CheckResult:
    identity = IdentityGenerator.generate()
    return await GATEWAY.check(card, identity)


async def run_job(job: Job, cards: List[CardInput]) -> None:
    sem = asyncio.Semaphore(CONCURRENCY_LIMIT)

    async def worker(idx: int, card: CardInput) -> None:
        async with sem:
            try:
                result = await asyncio.wait_for(
                    process_one_card(card),
                    timeout=PER_CARD_TIMEOUT,
                )
            except asyncio.TimeoutError:
                result = CheckResult(
                    card=card,
                    status=ResultStatus.TIMEOUT,
                    message=f"Timeout após {PER_CARD_TIMEOUT}s",
                    latency_ms=int(PER_CARD_TIMEOUT * 1000),
                )
            except Exception as e:
                log.exception(f"Card {idx} failed")
                result = CheckResult(
                    card=card,
                    status=ResultStatus.ERROR,
                    message=f"Erro interno: {type(e).__name__}",
                    latency_ms=0,
                )

        async with job.lock:
            job.processed += 1
            if result.status == ResultStatus.APPROVED:
                job.approved += 1
            elif result.status == ResultStatus.DECLINED:
                job.declined += 1
            else:
                job.errors += 1
            job.results.append(result)

            payload = {
                "type": "result",
                "data": _serialize_result(idx, result),
                "progress": {
                    "processed": job.processed,
                    "total": job.total,
                    "approved": job.approved,
                    "declined": job.declined,
                    "errors": job.errors,
                },
            }

            dead: List[WebSocket] = []
            for ws in job.subscribers:
                try:
                    await ws.send_json(payload)
                except Exception:
                    dead.append(ws)
            for ws in dead:
                job.subscribers.discard(ws)

    try:
        await asyncio.gather(*(worker(i, c) for i, c in enumerate(cards)))
    finally:
        async with job.lock:
            job.finished = True
            done_payload = {
                "type": "done",
                "data": {
                    "job_id": job.id,
                    "total": job.total,
                    "processed": job.processed,
                    "approved": job.approved,
                    "declined": job.declined,
                    "errors": job.errors,
                    "elapsed": round(time.time() - job.created_at, 2),
                },
            }
            dead: List[WebSocket] = []
            for ws in job.subscribers:
                try:
                    await ws.send_json(done_payload)
                    await ws.close()
                except Exception:
                    dead.append(ws)
            for ws in dead:
                job.subscribers.discard(ws)


def _serialize_result(index: int, result: CheckResult) -> Dict:
    card = result.card
    status_map = {
        ResultStatus.APPROVED: "APROVADA",
        ResultStatus.DECLINED: "REPROVADA",
        ResultStatus.ERROR: "ERRO",
        ResultStatus.TIMEOUT: "ERRO",
    }
    return {
        "index": index,
        "card": f"{card.bin}xxxx{card.last4}",
        "raw": card.raw_line or f"{card.number}|{card.month}|{card.year}|{card.cvv}",
        "expiry": card.expiry,
        "status": status_map.get(result.status, "REPROVADA"),
        "message": result.message,
        "latency_ms": result.latency_ms or 0,
        "proxy_node": result.proxy_node,
        "session_id": result.session_id,
        "request_id": result.request_id,
        "timestamp": result.timestamp.isoformat(),
    }


async def cleanup_loop() -> None:
    while True:
        await asyncio.sleep(300)
        now = time.time()
        async with JOBS_LOCK:
            stale = [
                jid for jid, j in JOBS.items()
                if now - j.created_at > JOB_TTL_SECONDS and j.finished
            ]
            for jid in stale:
                del JOBS[jid]
                log.info(f"Cleaned up job {jid}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    global GATEWAY, PROXY, CACHE
    GATEWAY = build_gateway()
    PROXY = GATEWAY.proxy
    CACHE = GATEWAY.cache
    log.info(
        f"ASAS Checker started | gateway={GATEWAY.config.name} | "
        f"concurrency={CONCURRENCY_LIMIT} | timeout={PER_CARD_TIMEOUT}s"
    )
    cleanup_task = asyncio.create_task(cleanup_loop())
    yield
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        pass
    log.info("ASAS Checker shut down cleanly")


app = FastAPI(title="ASAS Debitando Checker", lifespan=lifespan)


class JobRequest(BaseModel):
    cards: str = Field(..., description="Newline-separated cc|mm|yy|cvv entries")


@app.post("/api/jobs")
async def create_job(req: JobRequest):
    if GATEWAY is None:
        raise HTTPException(503, "Gateway não inicializado")

    lines = [l for l in req.cards.splitlines() if l.strip()]
    if not lines:
        raise HTTPException(400, "Nenhum cartão fornecido")
    if len(lines) > MAX_CARDS_PER_JOB:
        raise HTTPException(400, f"Máximo de {MAX_CARDS_PER_JOB} cartões por job")

    parsed: List[CardInput] = []
    invalid: List[str] = []
    for line in lines:
        c = parse_card_line(line)
        if c:
            parsed.append(c)
        else:
            invalid.append(line)

    if not parsed:
        raise HTTPException(400, "Nenhum cartão válido. Use o formato cc|mm|yy|cvv")

    job = Job(job_id=uuid.uuid4().hex[:12], total=len(parsed))
    async with JOBS_LOCK:
        JOBS[job.id] = job

    job.task = asyncio.create_task(run_job(job, parsed))
    log.info(f"Job {job.id} created | valid={len(parsed)} invalid={len(invalid)}")

    return {
        "job_id": job.id,
        "total": job.total,
        "invalid": invalid,
        "invalid_count": len(invalid),
    }


@app.get("/api/jobs/{job_id}")
async def get_job(job_id: str):
    job = JOBS.get(job_id)
    if not job:
        raise HTTPException(404, "Job não encontrado")
    return {
        "job_id": job.id,
        "total": job.total,
        "processed": job.processed,
        "approved": job.approved,
        "declined": job.declined,
        "errors": job.errors,
        "finished": job.finished,
        "results": [_serialize_result(i, r) for i, r in enumerate(job.results)],
    }


@app.websocket("/ws/{job_id}")
async def ws_endpoint(ws: WebSocket, job_id: str):
    await ws.accept()
    job = JOBS.get(job_id)
    if not job:
        await ws.send_json({"type": "error", "data": "Job não encontrado"})
        await ws.close()
        return

    async with job.lock:
        for i, r in enumerate(job.results):
            await ws.send_json({
                "type": "result",
                "data": _serialize_result(i, r),
                "progress": {
                    "processed": job.processed,
                    "total": job.total,
                    "approved": job.approved,
                    "declined": job.declined,
                    "errors": job.errors,
                },
            })
        if job.finished:
            await ws.send_json({
                "type": "done",
                "data": {
                    "job_id": job.id,
                    "total": job.total,
                    "processed": job.processed,
                    "approved": job.approved,
                    "declined": job.declined,
                    "errors": job.errors,
                    "elapsed": round(time.time() - job.created_at, 2),
                },
            })
            await ws.close()
            return
        job.subscribers.add(ws)

    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        job.subscribers.discard(ws)


@app.get("/health")
async def health():
    return {
        "ok": True,
        "jobs": len(JOBS),
        "gateway": GATEWAY.config.name if GATEWAY else None,
        "proxy_nodes": len(PROXY._pool) if PROXY else 0,
        "ts": time.time(),
    }


STATIC_DIR = Path(__file__).parent / "static"
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def index():
    idx = STATIC_DIR / "index.html"
    if idx.exists():
        html = idx.read_text(encoding="utf-8")
        return HTMLResponse(
            html,
            headers={
                "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
                "Pragma": "no-cache",
                "Expires": "0",
            },
        )
    return HTMLResponse("<h1>ASAS Checker</h1><p>static/index.html missing</p>", status_code=500)
