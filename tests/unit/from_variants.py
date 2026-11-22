"""Run the send-gate adversarial suites over a non-default From address (comlink#14).

A module that imports ``send_message_impl`` adds an autouse fixture built by
:func:`from_variant_fixture`. It is parametrized: ``default`` leaves the module's
single-address calls untouched; ``non-default-from`` reroutes each call through a
three-address pool and sends From ``hello@chaosbit.dev`` — not the default sender —
so every allowlist, confirm, Bcc and rate-limit case is proven for it too.
"""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator
from typing import Any

import pytest

from comlink.accounts import AccountPool
from comlink.config import ComlinkSettings

NON_DEFAULT_FROM = "hello@chaosbit.dev"
_ADDRESSES = ["brandon@chaosbit.dev", NON_DEFAULT_FROM, "security@chaosbit.dev"]


def from_variant_fixture() -> Callable[..., Iterator[None]]:
    @pytest.fixture(autouse=True, params=["default", "non-default-from"])
    def _from_variant(
        request: pytest.FixtureRequest, monkeypatch: pytest.MonkeyPatch
    ) -> Iterator[None]:
        if request.param == "non-default-from":
            module = sys.modules[request.module.__name__]
            real = module.send_message_impl

            async def routed(
                settings: ComlinkSettings, imap: Any, limiter: Any, **kwargs: Any
            ) -> dict[str, Any]:
                multi = settings.model_copy(
                    update={"accounts": ",".join(_ADDRESSES), "username": _ADDRESSES[0]}
                )
                pool = AccountPool(multi, managers=dict.fromkeys(_ADDRESSES, imap))
                return await real(  # type: ignore[no-any-return]
                    multi, imap, limiter, pool=pool, from_address=NON_DEFAULT_FROM, **kwargs
                )

            monkeypatch.setattr(module, "send_message_impl", routed)
        yield

    return _from_variant
