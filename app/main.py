"""FastAPI 入口：中间件、异常映射、生命周期恢复与静态页面。"""
from __future__ import annotations

import logging
import mimetypes
import uuid
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.datastructures import MutableHeaders
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.api import auth, projects, streams
from app.config import settings
from app.core.errors import AppError
from app.database import create_all, healthcheck
from app.isolation import docker as iso
from app.services import config_service, stage_service

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Windows 注册表可能把 .js 映射为 text/plain，显式注册以保证浏览器可执行静态脚本。
for _ext, _mime in {
    ".js": "application/javascript",
    ".css": "text/css",
    ".html": "text/html",
    ".json": "application/json",
    ".svg": "image/svg+xml",
}.items():
    mimetypes.add_type(_mime, _ext)
PAGES = {
    "index.html",
    "projects.html",
    "project.html",
    "monitor.html",
    "vulnerabilities.html",
    "attack-paths.html",
    "report.html",
    "config.html",
}
PUBLIC_PAGES = {"index.html"}
MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_EXEMPT = {"/api/system/init", "/api/system/login"}


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.ensure_dirs()
    try:
        create_all()
        from app.database import SessionLocal

        db = SessionLocal()
        try:
            recovered = stage_service.recover_running(db)
            if recovered:
                logger.warning("已将 %s 个中断的评估任务标记为失败", recovered)
        finally:
            db.close()
        logger.info("数据库表已就绪")
    except Exception as exc:  # noqa: BLE001
        logger.warning("自动建库/恢复失败（请检查 MySQL 是否可用）：%s", exc)
    yield


class RequestContextMiddleware:
    """CSRF 校验、请求编号与安全响应头。"""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET").upper()
        headers = {
            key.decode("latin-1").lower(): value.decode("latin-1")
            for key, value in scope.get("headers", [])
        }
        if (
            method in MUTATING_METHODS
            and path.startswith("/api/")
            and path not in CSRF_EXEMPT
            and headers.get("x-requested-with", "").lower() != "xmlhttprequest"
        ):
            response = JSONResponse(
                {"code": "CSRF_REQUIRED", "message": "缺少 X-Requested-With 请求头"},
                status_code=403,
            )
            await response(scope, receive, send)
            return

        request_id = headers.get("x-request-id") or uuid.uuid4().hex[:16]
        scope.setdefault("state", {})
        scope["state"]["request_id"] = request_id

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                response_headers = MutableHeaders(scope=message)
                response_headers["X-Request-ID"] = request_id
                response_headers["X-Content-Type-Options"] = "nosniff"
                response_headers["X-Frame-Options"] = "SAMEORIGIN"
                response_headers["Referrer-Policy"] = "same-origin"
                if path.startswith("/api/"):
                    response_headers["Cache-Control"] = "no-store"
            await send(message)

        await self.app(scope, receive, send_with_headers)


app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)
app.add_middleware(RequestContextMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.secret_key,
    session_cookie="sas_session",
    max_age=86400,
    same_site="lax",
)

app.include_router(auth.router)
app.include_router(projects.router)
app.include_router(streams.router)


@app.exception_handler(AppError)
async def app_error_handler(request: Request, exc: AppError):
    return JSONResponse(
        status_code=exc.http_status,
        content={
            "code": exc.code,
            "message": exc.message,
            "detail": exc.detail if exc.detail is not None else exc.message,
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={
            "code": "VALIDATION_ERROR",
            "message": "请求参数校验失败",
            "detail": jsonable_encoder(exc.errors()),
        },
    )


@app.exception_handler(StarletteHTTPException)
async def http_error_handler(request: Request, exc: StarletteHTTPException):
    detail = exc.detail
    message = detail if isinstance(detail, str) else "请求失败"
    return JSONResponse(
        status_code=exc.status_code,
        content={"code": f"HTTP_{exc.status_code}", "message": message, "detail": detail},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def unhandled_error_handler(request: Request, exc: Exception):
    logger.exception("未处理异常：%s %s", request.method, request.url.path)
    return JSONResponse(
        status_code=500,
        content={"code": "INTERNAL_ERROR", "message": "服务器内部错误", "detail": None},
    )


def _logged_in(request: Request) -> bool:
    return bool(request.session.get("user_id"))


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/")
def index(request: Request):
    if _logged_in(request):
        return RedirectResponse("/projects.html")
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/projects")
def projects_alias():
    return RedirectResponse("/projects.html")


@app.get("/{page}.html")
def page(page: str, request: Request):
    filename = f"{page}.html"
    if filename not in PAGES:
        return RedirectResponse("/projects.html" if _logged_in(request) else "/index.html")
    if filename not in PUBLIC_PAGES and not _logged_in(request):
        return RedirectResponse("/index.html")
    return FileResponse(STATIC_DIR / filename)


@app.get("/api/health")
def api_health() -> dict:
    try:
        from app.database import SessionLocal

        db = SessionLocal()
        try:
            llm_configured = bool(config_service.get_effective_config(db).get("llm_api_key"))
        finally:
            db.close()
    except Exception:
        llm_configured = bool(settings.llm_api_key)
    db_ok = healthcheck()
    return {
        "status": "ok" if db_ok else "degraded",
        "db": db_ok,
        "docker": iso.docker_available(),
        "llm_configured": llm_configured,
    }


@app.get("/healthz")
def healthz() -> dict:
    return api_health()


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
