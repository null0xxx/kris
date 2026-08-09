"""Validated, redirect-bounded HTTP fetch with RAM-only body storage."""

from __future__ import annotations

import asyncio
import ipaddress
import threading
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any, Final

import httpx

from lsassist.memory.fetch_body import FETCH_BODY_LIMIT, FetchBodyStore, FetchBodyStoreError
from lsassist.tools.handlers import (
    BODY_TOO_LARGE,
    CONTENT_TYPE_REFUSED,
    FETCH_FAILED,
    MEMORY_STORE_FAILED,
    REDIRECT_REFUSED,
    TIMED_OUT,
    URL_REFUSED,
    Handler,
    HandlerContext,
    HandlerRefused,
)

__all__ = ["MAX_REDIRECTS", "make_net_fetch_handler", "normalize_domain"]

MAX_REDIRECTS: Final = 5
_REDIRECTS: Final = frozenset({301, 302, 303, 307, 308})
_LOCALHOSTS: Final = frozenset({"localhost", "127.0.0.1", "::1"})


def normalize_domain(value: object) -> str:
    """Return one canonical host spelling; reject userinfo/path/port smuggling."""
    if not isinstance(value, str) or not value or value != value.strip():
        raise HandlerRefused(URL_REFUSED, "domain must be a non-empty unpadded string")
    host = value[:-1] if value.endswith(".") else value
    if not host or any(mark in host for mark in ("@", "/", "\\", "?", "#", "%")):
        raise HandlerRefused(URL_REFUSED, "domain contains userinfo, path, or escape syntax")
    try:
        return ipaddress.ip_address(host.strip("[]")).compressed.lower()
    except ValueError:
        pass
    if ":" in host or any(
        not (label and label.replace("-", "a").isalnum()) for label in host.split(".")
    ):
        raise HandlerRefused(URL_REFUSED, "domain is not a valid DNS name or IP address")
    return host.encode("idna").decode("ascii").lower()


def _normalized_allowlist(domains: frozenset[str]) -> frozenset[str]:
    if not isinstance(domains, frozenset):
        raise TypeError("net.fetch allowlist must be an immutable frozenset")
    return frozenset(normalize_domain(domain) for domain in domains)


def _url(scheme: object, domain: object, port: object, target: object) -> httpx.URL:
    if scheme not in {"http", "https"}:
        raise HandlerRefused(URL_REFUSED, "net.fetch scheme must be http or https")
    host = normalize_domain(domain)
    if scheme == "http" and host not in _LOCALHOSTS:
        raise HandlerRefused(URL_REFUSED, "plain HTTP is permitted only for exact localhost")
    if port is not None and (
        isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535
    ):
        raise HandlerRefused(URL_REFUSED, "net.fetch port must be an integer in 1..65535")
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        raise HandlerRefused(URL_REFUSED, "net.fetch target must be an absolute-path reference")
    if "\x00" in target or "#" in target:
        raise HandlerRefused(URL_REFUSED, "net.fetch target contains NUL or a fragment")
    authority = f"[{host}]" if ":" in host else host
    if port is not None:
        authority = f"{authority}:{port}"
    try:
        url = httpx.URL(f"{scheme}://{authority}{target}")
    except (TypeError, ValueError) as exc:
        raise HandlerRefused(URL_REFUSED, "net.fetch URL could not be constructed") from exc
    if url.userinfo:
        raise HandlerRefused(URL_REFUSED, "net.fetch URL userinfo is forbidden")
    return url


def _validate_hop(url: httpx.URL, permitted: frozenset[str], authority: tuple[str, int]) -> str:
    host = normalize_domain(url.host)
    if url.scheme not in {"http", "https"}:
        raise HandlerRefused(REDIRECT_REFUSED, "redirect scheme is not HTTP(S)")
    if url.scheme == "http" and host not in _LOCALHOSTS:
        raise HandlerRefused(REDIRECT_REFUSED, "redirect downgraded to non-local HTTP")
    if url.userinfo:
        raise HandlerRefused(REDIRECT_REFUSED, "redirect URL contains userinfo")
    port = url.port or (443 if url.scheme == "https" else 80)
    if (url.scheme, port) != authority:
        raise HandlerRefused(REDIRECT_REFUSED, "redirect changed the approved scheme or port")
    if host not in permitted:
        raise HandlerRefused(REDIRECT_REFUSED, f"redirect domain {host!r} is not permitted")
    return host


def _content_type(response: httpx.Response) -> str:
    raw = str(response.headers.get("content-type", ""))
    media_type = raw.split(";", 1)[0].strip().lower()
    if not (
        media_type.startswith("text/") or media_type in {"application/json", "application/xml"}
    ):
        raise HandlerRefused(
            CONTENT_TYPE_REFUSED, f"response content type {media_type or '<missing>'!r} is refused"
        )
    return media_type


def _remaining(context: HandlerContext, operation: str) -> float:
    if context.deadline is None:
        return float(context.manifest.timeout_s)
    remaining = context.deadline - time.monotonic()
    if remaining <= 0:
        raise HandlerRefused(
            TIMED_OUT, f"{operation} exceeded the {context.manifest.timeout_s}s budget"
        )
    return remaining


def _run_async(call: Callable[[], Awaitable[dict[str, Any]]], timeout: float) -> dict[str, Any]:
    result: list[dict[str, Any] | BaseException] = []

    def worker() -> None:
        async def bounded() -> dict[str, Any]:
            async with asyncio.timeout(max(0.0, timeout - min(0.01, timeout / 2))):
                return await call()
        try:
            result.append(asyncio.run(bounded()))
        except BaseException as exc:
            result.append(exc)
    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        raise HandlerRefused(TIMED_OUT, "HTTP transport exhausted the total deadline")
    if isinstance(value := result[0], BaseException):
        raise value
    return value


def make_net_fetch_handler(
    body_store: FetchBodyStore,
    *,
    client_factory: Callable[..., httpx.AsyncClient] = httpx.AsyncClient,
) -> Handler:
    """Inject the RAM store and HTTP client without adding policy authority."""

    async def exchange(context: HandlerContext) -> dict[str, Any]:
        args = context.normalized.args
        method = args.get("method")
        if method not in {"GET", "HEAD"}:
            raise HandlerRefused(URL_REFUSED, "net.fetch method must be GET or HEAD")
        current = _url(args.get("scheme"), args.get("domain"), args.get("port"), args.get("target"))
        initial_host = normalize_domain(current.host)
        permitted = _normalized_allowlist(context.environment.stores.net_allowlist) | {initial_host}
        authority = (current.scheme, current.port or (443 if current.scheme == "https" else 80))
        redirects = 0
        try:
            remaining = _remaining(context, "net.fetch")
            async with client_factory(
                trust_env=False,
                follow_redirects=False,
                timeout=remaining,
            ) as client:
                while True:
                    remaining = _remaining(context, "net.fetch redirect chain")
                    _validate_hop(current, permitted, authority)
                    async with client.stream(method, current, timeout=remaining) as response:
                        if response.status_code in _REDIRECTS:
                            location = response.headers.get("location")
                            if location is None or redirects >= MAX_REDIRECTS:
                                raise HandlerRefused(
                                    REDIRECT_REFUSED, "redirect is missing Location or exceeds cap"
                                )
                            current = current.join(location)
                            _validate_hop(current, permitted, authority)
                            redirects += 1
                            continue
                        if not 200 <= response.status_code < 300:
                            raise HandlerRefused(
                                FETCH_FAILED, f"HTTP response status {response.status_code}"
                            )
                        content_type = _content_type(response)
                        body = bytearray()
                        if method == "GET":
                            async for chunk in response.aiter_bytes():
                                _remaining(context, "net.fetch response stream")
                                if len(body) + len(chunk) > FETCH_BODY_LIMIT:
                                    raise HandlerRefused(
                                        BODY_TOO_LARGE, "response body exceeds the 1 MiB cap"
                                    )
                                body.extend(chunk)
                        break
        except HandlerRefused:
            raise
        except httpx.TimeoutException as exc:
            raise HandlerRefused(TIMED_OUT, "HTTP transport exhausted the total deadline") from exc
        except httpx.HTTPError as exc:
            raise HandlerRefused(
                FETCH_FAILED, f"HTTP transport failed: {type(exc).__name__}"
            ) from exc

        return {"url": str(current), "status_code": response.status_code,
                "content_type": content_type, "body": bytes(body), "redirects": redirects}

    def fetch(context: HandlerContext) -> Mapping[str, Any]:
        try:
            fetched = _run_async(lambda: exchange(context), _remaining(context, "net.fetch"))
        except (TimeoutError, httpx.TimeoutException) as exc:
            raise HandlerRefused(TIMED_OUT, "HTTP transport exhausted the total deadline") from exc
        reference = None
        digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        body = fetched["body"]
        if context.normalized.args["method"] == "GET":
            try:
                _remaining(context, "net.fetch body store")
                stored = body_store.put(body)
            except FetchBodyStoreError as exc:
                raise HandlerRefused(MEMORY_STORE_FAILED, str(exc)) from exc
            reference, digest = stored.ref, stored.digest
        return {
            "url": fetched["url"],
            "method": context.normalized.args["method"],
            "status_code": fetched["status_code"],
            "content_type": fetched["content_type"],
            "body_ref": reference,
            "byte_count": len(body),
            "digest": digest,
            "redirects": fetched["redirects"],
        }

    return fetch
