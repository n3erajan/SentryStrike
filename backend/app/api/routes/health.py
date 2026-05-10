from fastapi import APIRouter

from app.api.dependencies import json_response

router = APIRouter(prefix="/health", tags=["health"])


@router.get("")
async def health_check() -> dict:
    return json_response({"status": "healthy"})


@router.get("/owasp-categories")
async def list_owasp_categories() -> dict:
    categories = [
        "A01-Broken Access Control",
        "A02-Cryptographic Failures",
        "A03-Injection",
        "A04-Insecure Design",
        "A05-Security Misconfiguration",
        "A06-Vulnerable and Outdated Components",
        "A07-Identification and Authentication Failures",
        "A08-Software and Data Integrity Failures",
        "A09-Security Logging and Monitoring Failures",
        "A10-Exception Handling and Information Leakage",
    ]
    return json_response(categories)
