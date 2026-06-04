"""Model adapters for the sota_bench SOTA-validation loop.

This module is STDLIB-ONLY. It defines the :class:`ModelAdapter` interface
(the single seam through which the loop talks to a model) and a deterministic,
network-free :class:`StubAdapter` used by tests and reproducible fixtures.

The loop is intentionally model-agnostic: it never imports a vendor SDK. A real
adapter (e.g. one that calls a frontier API) is expected to live downstream and
subclass :class:`ModelAdapter`; a thin, lazily-imported reference is sketched in
:func:`make_openai_adapter` so that importing this module never requires (or
pays for) a third-party dependency.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Mapping
from typing import Any

__all__ = [
    "ModelAdapter",
    "StubAdapter",
    "make_openai_adapter",
]


class ModelAdapter(ABC):
    """Abstract interface for anything that turns a prompt into text.

    The loop depends only on :meth:`run`. Keeping the surface this small is what
    makes the benchmark model-agnostic: a "naive single-call" baseline and a
    full "method" scaffold are *both* just ``ModelAdapter`` implementations, so
    the same scoring code measures the signed delta between them.
    """

    @abstractmethod
    def run(self, prompt: str) -> str:
        """Return the model's text output for ``prompt``.

        Implementations must be side-effect-free with respect to scoring (the
        loop treats the returned string as the entire observable output).
        """
        raise NotImplementedError


class StubAdapter(ModelAdapter):
    """A deterministic, offline :class:`ModelAdapter` for tests and fixtures.

    The canned behavior is supplied either as a mapping from prompt to output,
    or as a callable invoked with the prompt. This lets a test construct a
    *known* naive-misses / method-hits split and assert the exact signed delta
    the loop must report, with no network and no randomness.

    Args:
        responses: Either a ``Mapping[str, str]`` looked up by exact prompt, or
            a ``Callable[[str], str]`` invoked with the prompt.
        default: Output returned when a mapping has no entry for the prompt. If
            ``None`` (the default) a missing key raises :class:`KeyError`, which
            surfaces fixture drift loudly instead of silently mislabeling.

    Raises:
        TypeError: If ``responses`` is neither a mapping nor callable.
    """

    def __init__(
        self,
        responses: Mapping[str, str] | Callable[[str], str],
        *,
        default: str | None = None,
    ) -> None:
        if callable(responses):
            self._fn: Callable[[str], str] = responses
            self._mapping: dict[str, str] | None = None
        elif isinstance(responses, Mapping):
            self._fn = self._lookup
            self._mapping = dict(responses)
        else:
            raise TypeError(
                "responses must be a Mapping[str, str] or Callable[[str], str], "
                f"got {type(responses).__name__}"
            )
        self._default = default

    def _lookup(self, prompt: str) -> str:
        """Resolve ``prompt`` against the canned mapping (with optional default)."""
        assert self._mapping is not None  # narrowed by construction
        if prompt in self._mapping:
            return self._mapping[prompt]
        if self._default is not None:
            return self._default
        raise KeyError(f"StubAdapter has no canned response for prompt: {prompt!r}")

    def run(self, prompt: str) -> str:
        """Return the canned output for ``prompt``."""
        return self._fn(prompt)


def make_openai_adapter(*_args: Any, **_kwargs: Any) -> ModelAdapter:
    """Reference factory for a real, networked adapter (lazily imported).

    This is a thin OPTIONAL convenience and is deliberately NOT used by the
    core or the tests, so that the core stays stdlib-only. The third-party SDK
    is imported *inside* the function body, meaning importing this module (or
    the ``sota_bench.adapters`` package) never requires the dependency.
    Downstream users who want a live model should either install the extra and
    call this, or write their own :class:`ModelAdapter` subclass.

    Raises:
        ImportError: If the optional SDK is not installed.
        NotImplementedError: Always, in this reference skeleton, wire your own
            client here (or subclass :class:`ModelAdapter` directly).
    """
    try:
        import openai  # noqa: F401  (optional, lazily imported by design)
    except ImportError as exc:  # pragma: no cover - exercised only with the extra
        raise ImportError(
            "make_openai_adapter requires the optional 'openai' package; "
            "install it or implement your own ModelAdapter subclass."
        ) from exc

    raise NotImplementedError(
        "make_openai_adapter is a reference skeleton. Subclass ModelAdapter and "
        "implement run(prompt) -> str against your client of choice."
    )
