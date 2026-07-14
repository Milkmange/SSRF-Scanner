"""Out-of-band (OOB) interaction support for confirming blind SSRF.

Blind SSRF cannot be confirmed from the HTTP response alone - the only
reliable signal is the target server actually calling back to infrastructure
we control. This module provides that infrastructure.

Model (industry-standard, same idea as Burp Collaborator / interactsh):

  1. For each callback-style payload we mint a UNIQUE correlation token and
     build an authority of the form ``<token>.<oob-domain>``.
  2. That authority is embedded where payloads previously used the static
     ``--backurl`` value.
  3. A listener we control records every inbound hit (token, source IP, time).
  4. After the scan we match recorded hits against the tokens we sent. A hit
     means the target fetched our URL => confirmed SSRF, attributable to the
     exact payload/vector that carried that token.

Providers:
  - ``NullOOB``       : default no-op (behaviour unchanged, manual --backurl).
  - ``SelfHostedOOB`` : runs an aiohttp HTTP listener and correlates by the
                        leftmost DNS label (subdomain) or first path segment.

SECURITY NOTE: SelfHostedOOB opens an unauthenticated inbound HTTP listener so
that a remote target can reach it. It only records requests and always returns
a benign response; it never executes anything. Bind it deliberately and expose
it only for the duration of a scan.
"""

import logging
import secrets
import time
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class Interaction:
    token: str
    protocol: str        # e.g. "http"
    remote_addr: str
    method: str
    path: str
    host: str
    user_agent: str
    timestamp: float


@dataclass
class CallbackMeta:
    token: str
    attack_type: str
    payload: str
    target_url: str
    created: float


class OOBProvider:
    """Base provider. The default is a no-op (OOB disabled)."""

    enabled = False

    async def start(self) -> bool:
        return False

    def new_callback(self, attack_type: str, payload: str, target_url: str) -> Optional[str]:
        """Return a per-payload callback authority, or None when disabled."""
        return None

    def collect(self) -> List[Interaction]:
        return []

    def meta_for(self, token: str) -> Optional[CallbackMeta]:
        return None

    async def stop(self):
        return None


class NullOOB(OOBProvider):
    """OOB disabled - preserves the original manual --backurl behaviour."""

    enabled = False


class SelfHostedOOB(OOBProvider):
    """Self-hosted HTTP callback listener with token correlation.

    Args:
        listen_host: interface to bind the listener to (e.g. "0.0.0.0").
        listen_port: port to bind (e.g. 8000).
        public_base: the externally reachable authority that resolves to this
            listener, e.g. "oob.example.com" (needs wildcard DNS
            ``*.oob.example.com`` -> listener IP) or an ngrok host. May include
            a port, e.g. "1.2.3.4:8000".
    """

    enabled = True

    def __init__(self, listen_host: str, listen_port: int, public_base: str,
                 logger: Optional[logging.Logger] = None):
        self.listen_host = listen_host
        self.listen_port = int(listen_port)
        self.public_base = public_base.strip().rstrip('/')
        self.logger = logger or logging.getLogger("ssrf_scanner")
        self._interactions: List[Interaction] = []
        self._meta: Dict[str, CallbackMeta] = {}
        self._runner = None

    async def start(self) -> bool:
        try:
            from aiohttp import web
        except Exception as e:  # pragma: no cover
            self.logger.error(f"OOB listener requires aiohttp: {e}")
            self.enabled = False
            return False
        try:
            app = web.Application()
            app.router.add_route('*', '/{tail:.*}', self._handle)
            self._runner = web.AppRunner(app, access_log=None)
            await self._runner.setup()
            site = web.TCPSite(self._runner, self.listen_host, self.listen_port)
            await site.start()
            self.logger.info(
                f"OOB listener bound on {self.listen_host}:{self.listen_port} "
                f"(public base: {self.public_base})"
            )
            return True
        except Exception as e:
            self.logger.error(f"Failed to start OOB listener: {e}")
            self.enabled = False
            return False

    async def _handle(self, request):
        from aiohttp import web
        token = self._extract_token(request)
        self._interactions.append(Interaction(
            token=token,
            protocol="http",
            remote_addr=request.remote or "",
            method=request.method,
            path=request.path_qs,
            host=request.host or "",
            user_agent=request.headers.get("User-Agent", ""),
            timestamp=time.time(),
        ))
        # Always benign; never act on the request.
        return web.Response(text="ok")

    def _extract_token(self, request) -> str:
        # Subdomain correlation: leftmost label of the Host header.
        host = (request.host or "").split(':')[0]
        if host:
            label = host.split('.')[0]
            if label in self._meta:
                return label
        # Path correlation: first path segment.
        path = request.path.strip('/')
        if path:
            seg = path.split('/')[0]
            if seg in self._meta:
                return seg
        # Unknown/unmatched: record the raw label so it is still visible.
        return (host.split('.')[0] if host else path) or "unknown"

    def new_callback(self, attack_type: str, payload: str, target_url: str) -> str:
        token = "t" + secrets.token_hex(6)
        self._meta[token] = CallbackMeta(
            token=token,
            attack_type=attack_type,
            payload=payload,
            target_url=target_url,
            created=time.time(),
        )
        # Bare authority so it is a drop-in for the static backurl (callers wrap
        # it with schemes/ports). Subdomain token => works with wildcard DNS.
        return f"{token}.{self.public_base}"

    def collect(self) -> List[Interaction]:
        return list(self._interactions)

    def meta_for(self, token: str) -> Optional[CallbackMeta]:
        return self._meta.get(token)

    async def stop(self):
        if self._runner is not None:
            try:
                await self._runner.cleanup()
            except Exception:
                pass
            self._runner = None
