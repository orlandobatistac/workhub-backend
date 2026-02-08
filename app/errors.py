"""Centralized API error helpers and standard error schema.

Provides:
- api_error(...) -> HTTPException with JSON detail: {"error": {"code": str, "message": str, "details": ...}}
- make_validation_error_response(...) -> dict payload used by exception handler
"""
from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException


def api_error(status_code: int, code: str, message: str, details: Optional[Any] = None, headers: Optional[dict] = None) -> HTTPException:
    payload: dict = {"error": {"code": code, "message": message}}
    if details is not None:
        payload["error"]["details"] = details
    return HTTPException(status_code=status_code, detail=payload, headers=headers)


from fastapi.encoders import jsonable_encoder


def make_validation_error_response(errors: Any) -> dict:
    # Use FastAPI's jsonable_encoder to safely convert potential exception objects
    payload = {"error": {"code": "validation_error", "message": "Validation error", "details": errors}}
    return jsonable_encoder(payload)
