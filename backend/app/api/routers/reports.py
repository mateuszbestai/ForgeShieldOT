"""Reports API — generate and retrieve simulated/demo OT security reports."""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import HTMLResponse, PlainTextResponse
from sqlmodel import Session

from app.api.deps import (
    WRITE_OPERATIONS,
    AuthenticatedUser,
    get_current_user,
    require_role,
)
from app.core.db import get_session
from app.core.enums import ReportFormat
from app.schemas.common import PaginationParams, pagination
from app.schemas.report import GenerateReportRequest
from app.services import report_service

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/types")
def report_types(
    _user: AuthenticatedUser = Depends(get_current_user),
) -> dict:
    return {"items": report_service.available_types()}


@router.get("")
def list_reports(
    page: PaginationParams = Depends(pagination),
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    items, total = report_service.list_reports(session, page=page)
    return {
        "items": [_report_dict(r) for r in items],
        "total": total,
        "limit": page.limit,
        "offset": page.offset,
        "is_demo_environment": True,
    }


@router.post("/generate", status_code=201)
def generate_report(
    data: GenerateReportRequest,
    user: AuthenticatedUser = Depends(require_role(*WRITE_OPERATIONS)),
    session: Session = Depends(get_session),
) -> dict:
    report = report_service.generate(session, data, user)
    return _report_dict(report)


@router.get("/{report_id}")
def get_report(
    report_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
) -> dict:
    report = report_service.get_report(session, report_id)
    return _report_dict(report)


@router.get("/{report_id}/download")
def download_report(
    report_id: uuid.UUID,
    _user: AuthenticatedUser = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    report = report_service.get_report(session, report_id)
    if report.fmt == ReportFormat.HTML:
        return HTMLResponse(content=report.content)
    if report.fmt == ReportFormat.PDF:
        return PlainTextResponse(
            content=report.content,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="report-{report.id}.pdf"'
            },
        )
    return PlainTextResponse(content=report.content, media_type="text/markdown")


def _report_dict(report) -> dict:
    return {
        "id": str(report.id),
        "report_type": report.report_type.value,
        "title": report.title,
        "fmt": report.fmt.value,
        "summary": report.summary,
        "content": report.content,
        "params": report.params,
        "is_demo": report.is_demo,
        "generated_by": str(report.generated_by) if report.generated_by else None,
        "created_at": report.created_at.isoformat() if report.created_at else None,
    }
