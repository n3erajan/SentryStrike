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
        "A02-Security Misconfiguration",
        "A03-Software Supply Chain Failures",
        "A04-Cryptographic Failures",
        "A05-Injection",
        "A06-Insecure Design",
        "A07-Authentication Failures",
        "A08-Software and Data Integrity Failures",
        "A09-Security Logging and Monitoring Failures",
        "A10-Mishandling of Exceptional Conditions",
    ]
    return json_response(categories)
