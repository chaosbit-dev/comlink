"""SMTP path (design doc §4).

Epic 0 scope: connectivity verification for ``proton_health_check``.
The gated send pipeline lands in Epic 3 (guardrails, audit log) — note that
sending must NOT also APPEND to Sent (§3.6).
"""

from __future__ import annotations

import contextlib

import aiosmtplib

from comlink.config import ComlinkSettings
from comlink.errors import AuthFailed, BridgeUnavailable, ComlinkError, redact


async def verify_smtp_connectivity(settings: ComlinkSettings, password: str) -> None:
    """Connect, STARTTLS, and authenticate against the Bridge SMTP endpoint.

    Raises a taxonomy error on failure; returns ``None`` on success.
    """
    client = aiosmtplib.SMTP(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        timeout=15,
        start_tls=False,
        use_tls=False,
    )
    try:
        await client.connect()
        await client.starttls(tls_context=settings.build_ssl_context())
        await client.login(settings.username, password)
    except aiosmtplib.SMTPAuthenticationError as exc:
        raise AuthFailed.smtp() from exc
    except (aiosmtplib.SMTPConnectError, aiosmtplib.SMTPConnectTimeoutError, OSError) as exc:
        raise BridgeUnavailable.for_endpoint(
            settings.smtp_host, settings.smtp_port, "SMTP"
        ) from exc
    except aiosmtplib.SMTPException as exc:
        raise ComlinkError(f"SMTP check failed: {redact(str(exc), [password])}") from exc
    finally:
        with contextlib.suppress(aiosmtplib.SMTPException, OSError):
            await client.quit()
