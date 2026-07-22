import pytest
from pydantic import ValidationError

from app.schemas.provider_response import FindingAnalysisResponse


def _response(**overrides):
    data = {
        "description": "A database query can be altered by user input.",
        "exploitability": "Easy",
        "exploitability_reasoning": "Database error output confirms parsing.",
        "business_impact": "An attacker may read protected records.",
        "verdict": "confirmed",
        "false_positive_probability": 0.02,
        "false_positive_reasoning": "Direct error output supports the finding.",
        "remediation": "Use parameterized queries.",
        "references": [
            "https://owasp.org/www-community/attacks/SQL_Injection",
            "javascript:alert(1)",
            "file:///etc/passwd",
        ],
    }
    data.update(overrides)
    return data


def test_response_discards_non_http_references() -> None:
    response = FindingAnalysisResponse.model_validate(_response())

    assert response.references == [
        "https://owasp.org/www-community/attacks/SQL_Injection"
    ]


def test_response_rejects_unknown_security_fields() -> None:
    with pytest.raises(ValidationError):
        FindingAnalysisResponse.model_validate(
            _response(cvss_score=1.0, severity="Low")
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("verdict", "suppressed"),
        ("exploitability", "Trivial"),
        ("false_positive_probability", 1.5),
    ],
)
def test_response_rejects_out_of_contract_values(field, value) -> None:
    with pytest.raises(ValidationError):
        FindingAnalysisResponse.model_validate(_response(**{field: value}))

