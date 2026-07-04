class AppError(Exception):
    def __init__(self, message: str, code: str = "APP_ERROR") -> None:
        self.message = message
        self.code = code
        super().__init__(message)


class ValidationError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="VALIDATION_ERROR")


class ScannerError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="SCANNER_ERROR")


class IntegrationError(AppError):
    def __init__(self, message: str) -> None:
        super().__init__(message=message, code="INTEGRATION_ERROR")
