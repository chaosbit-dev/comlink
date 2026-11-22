"""One IMAP connection manager per configured Bridge address (split address mode).

Addresses are an explicit list (``COMLINK_ACCOUNTS``), never discovered. Managers
are built eagerly but connect lazily, so one address failing to log in cannot break
the others. An address is never guessed: with several configured, a missing or
unknown ``address`` is refused.
"""

from __future__ import annotations

from comlink.bridge.imap import ImapConnectionManager
from comlink.config import ComlinkSettings, normalize_address
from comlink.errors import ComlinkError


class AccountPool:
    """Address → :class:`ImapConnectionManager`, in configured order."""

    def __init__(
        self,
        settings: ComlinkSettings,
        managers: dict[str, ImapConnectionManager] | None = None,
    ) -> None:
        # Legacy single-address mode keeps COMLINK_USERNAME's exact spelling for the
        # From header and SMTP login; keys and comparisons are normalized.
        self._spelling: dict[str, str] = {}
        if managers is not None:
            self._managers = dict(managers)
        elif settings.accounts.strip():
            self._managers = {
                address: ImapConnectionManager(settings, address)
                for address in settings.account_addresses()
            }
        else:
            # Legacy single-address deployment: log in exactly as COMLINK_USERNAME says.
            self._managers = {normalize_address(settings.username): ImapConnectionManager(settings)}
            self._spelling[normalize_address(settings.username)] = settings.username
        self._primary = normalize_address(settings.username) if settings.username else ""
        if self._primary not in self._managers:
            self._primary = next(iter(self._managers))

    @property
    def addresses(self) -> list[str]:
        return list(self._managers)

    @property
    def multi(self) -> bool:
        """True when several addresses are configured (results then carry ``address``)."""
        return len(self._managers) > 1

    @property
    def primary(self) -> ImapConnectionManager:
        """The default account's manager (the default when one address is configured)."""
        return self._managers[self._primary]

    def items(self) -> list[tuple[str, ImapConnectionManager]]:
        return list(self._managers.items())

    def resolve(self, address: str | None) -> tuple[str, ImapConnectionManager]:
        """The manager for *address*; refuse (never guess) when it is ambiguous."""
        if address is None or not address.strip():
            if self.multi:
                raise ComlinkError(
                    "address is required: several addresses are configured "
                    f"({', '.join(self._managers)}). Pass one of them."
                )
            return self._primary, self.primary
        key = normalize_address(address)
        manager = self._managers.get(key)
        if manager is None:
            raise ComlinkError(
                f"Unknown address {address!r}. Configured addresses: {', '.join(self._managers)}."
            )
        return key, manager

    def resolve_sender(self, from_address: str | None) -> tuple[str, ImapConnectionManager]:
        """The From address and its manager; refuse (never guess) when ambiguous.

        Same rule as :meth:`resolve`, worded for a sender: with one address configured
        ``from_address`` is optional; with several, a missing or unknown one is refused.
        """
        try:
            key, manager = self.resolve(from_address)
        except ComlinkError as exc:
            message = str(exc).replace("address is required", "from_address is required", 1)
            raise ComlinkError(message) from exc
        return self._spelling.get(key, key), manager

    def resolve_reply_parent(
        self, sender: str, sender_manager: ImapConnectionManager, in_reply_to_address: str | None
    ) -> ImapConnectionManager:
        """The mailbox a reply's parent UID lives in (default: the From address's).

        A UID is only meaningful within one address's mailbox, so a reply to a message
        in another address's mailbox must name that address explicitly; an unconfigured
        one is refused.
        """
        if in_reply_to_address is None or not in_reply_to_address.strip():
            return sender_manager
        return self.resolve(in_reply_to_address)[1]

    async def aclose(self) -> None:
        for manager in self._managers.values():
            await manager.aclose()
