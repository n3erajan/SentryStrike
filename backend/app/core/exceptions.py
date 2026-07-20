class AppError(Exception):
    """Base application error with a machine-readable code and user-facing message."""

    def __init__(self, message: str, code: str = "APP_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(message)


class ValidationError(AppError):
    """Raised when user-supplied input fails validation."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="VALIDATION_ERROR")


class ScannerError(AppError):
    """Raised when communication with the scanner worker fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="SCANNER_ERROR")


class IntegrationError(AppError):
    """Raised when a third-party integration (NVD, SSLyze, etc.) fails."""

    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="INTEGRATION_ERROR")
