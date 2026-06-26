"""SMTP path (design doc §4, §6 Compose).

Connectivity verification for ``proton_health_check`` plus the gated send path
(Epic 3). Sending via Bridge SMTP makes Proton save the Sent copy server-side,
so this module must NEVER touch IMAP and never APPEND to Sent (§3.6) — doing so
would create a duplicate.
"""

from __future__ import annotations

import contextlib
from email.message import EmailMessage

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


async def send_message(
    settings: ComlinkSettings,
    password: str,
    message: EmailMessage,
    *,
    envelope_recipients: list[str],
) -> str:
    """Send *message* via the Bridge SMTP endpoint; return its Message-ID.

    Reuses the exact STARTTLS sequence proven in :func:`verify_smtp_connectivity`.
    The SMTP envelope recipients (``to`` + ``cc`` + ``bcc``) are passed
    explicitly so Bcc recipients receive the message without a Bcc header ever
    being serialized (§6). Never APPENDs to Sent — Proton saves the Sent copy
    server-side (§3.6).
    """
    from_addr = str(message["From"])
    message_id = str(message["Message-ID"])
    client = aiosmtplib.SMTP(
        hostname=settings.smtp_host,
        port=settings.smtp_port,
        timeout=30,
        start_tls=False,
        use_tls=False,
    )
    try:
        await client.connect()
        await client.starttls(tls_context=settings.build_ssl_context())
        await client.login(settings.username, password)
        await client.send_message(message, sender=from_addr, recipients=envelope_recipients)
    except aiosmtplib.SMTPAuthenticationError as exc:
        raise AuthFailed.smtp() from exc
    except (aiosmtplib.SMTPConnectError, aiosmtplib.SMTPConnectTimeoutError, OSError) as exc:
        raise BridgeUnavailable.for_endpoint(
            settings.smtp_host, settings.smtp_port, "SMTP"
        ) from exc
    except aiosmtplib.SMTPException as exc:
        raise ComlinkError(f"SMTP send failed: {redact(str(exc), [password])}") from exc
    finally:
        with contextlib.suppress(aiosmtplib.SMTPException, OSError):
            await client.quit()
    return message_id
