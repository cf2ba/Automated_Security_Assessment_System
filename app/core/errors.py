"""统一业务异常。"""
from __future__ import annotations


class AppError(Exception):
    code = "APP_ERROR"
    http_status = 400

    def __init__(self, message: str, detail=None):
        super().__init__(message)
        self.message = message
        self.detail = detail


class AuthRequired(AppError):
    code = "AUTH_REQUIRED"
    http_status = 401


class AuthForbidden(AppError):
    code = "AUTH_FORBIDDEN"
    http_status = 403


class SystemAlreadyInitialized(AppError):
    code = "SYSTEM_ALREADY_INITIALIZED"
    http_status = 409


class RateLimited(AppError):
    code = "RATE_LIMITED"
    http_status = 429


class ProjectNotFound(AppError):
    code = "PROJECT_NOT_FOUND"
    http_status = 404


class ProjectRunning(AppError):
    code = "PROJECT_RUNNING"
    http_status = 409


class ProjectNotRunning(AppError):
    code = "PROJECT_NOT_RUNNING"
    http_status = 409


class SourcePathInvalid(AppError):
    code = "SOURCE_PATH_INVALID"
    http_status = 400


class SourcePathNotAllowed(AppError):
    code = "SOURCE_PATH_NOT_ALLOWED"
    http_status = 403


class GitCloneFailed(AppError):
    code = "GIT_CLONE_FAILED"
    http_status = 400


class DockerUnavailable(AppError):
    code = "DOCKER_UNAVAILABLE"
    http_status = 503


class LLMUnavailable(AppError):
    code = "LLM_NOT_CONFIGURED"
    http_status = 503


class LLMOutputInvalid(AppError):
    code = "LLM_OUTPUT_INVALID"
    http_status = 502


class ReportNotReady(AppError):
    code = "REPORT_NOT_READY"
    http_status = 409


class ReportNotFound(AppError):
    code = "REPORT_NOT_FOUND"
    http_status = 404


class VulnerabilityNotFound(AppError):
    code = "VULN_NOT_FOUND"
    http_status = 404


class PathNotFound(AppError):
    code = "PATH_NOT_FOUND"
    http_status = 404


class ConfigInvalid(AppError):
    code = "CONFIG_INVALID"
    http_status = 400


class ConfigSecretNotWritable(AppError):
    code = "CONFIG_SECRET_NOT_WRITABLE"
    http_status = 400
