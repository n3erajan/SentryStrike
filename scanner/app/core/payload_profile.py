from dataclasses import dataclass

from shared.models.vulnerability import TechnologyComponent


@dataclass(frozen=True)
class PayloadProfile:
    """Technology-derived switches for active payload dictionaries."""

    is_windows: bool = False
    is_unix_like: bool = False
    supports_php_wrappers: bool = False
    supports_remote_include: bool = False
    is_dotnet: bool = False
    is_java: bool = False
    confidence: str = "unknown"


def build_payload_profile(technology_stack: list[TechnologyComponent] | None) -> PayloadProfile:
    names = " ".join(
        f"{getattr(component, 'name', '')} {getattr(component, 'category', '')}"
        for component in (technology_stack or [])
    ).lower()

    if not names.strip():
        return PayloadProfile()

    is_windows = any(token in names for token in ("iis", "asp.net", "microsoft", "windows", ".net"))
    is_dotnet = any(token in names for token in ("asp.net", ".net", "iis"))
    is_java = any(token in names for token in ("java", "jsp", "tomcat", "jetty", "spring", "weblogic", "websphere"))
    supports_php = any(token in names for token in ("php", "apache", "nginx")) and "asp.net" not in names
    explicit_php = "php" in names

    # Apache/nginx are usually Unix-like, but not conclusive by themselves.
    is_unix_like = any(token in names for token in ("linux", "unix", "ubuntu", "debian", "centos", "apache", "nginx", "php"))
    if is_windows and not is_unix_like:
        return PayloadProfile(
            is_windows=True,
            is_unix_like=False,
            supports_php_wrappers=False,
            supports_remote_include=False,
            is_dotnet=is_dotnet,
            is_java=is_java,
            confidence="high",
        )

    return PayloadProfile(
        is_windows=is_windows,
        is_unix_like=is_unix_like,
        supports_php_wrappers=explicit_php,
        supports_remote_include=supports_php or is_java,
        is_dotnet=is_dotnet,
        is_java=is_java,
        confidence="medium",
    )
