"""Blind-SSRF / CVE-probe payload library.

Loads and renders the templated payloads bundled in
``payloads/blind-ssrf-payloads.json`` (sourced from the MIT-licensed
errorfiathck/ssrf-exploit project - see payloads/THIRD_PARTY_NOTICES.md).

Payloads are templates containing placeholder tokens:

    {target_addr}       full target URL (e.g. https://host)
    {target_host}       target hostname (e.g. host)
    {canary_addr}       out-of-band callback URL (the scanner's --backurl)
    {canary_urlencoded} URL-encoded callback URL
    {command}           benign probe command
    {crlf} / {newline}  line separators (rendered URL-encoded so they are
                        transmittable as header/parameter values)

Entries fall into three shapes, exposed via ``RenderedPayload.kind``:

    "url"     - begins with {target_addr}; a complete URL to request directly
                against the target (known-CVE probe).
    "gopher"  - a gopher:// exploitation string (Redis/Memcache).
    "smuggle" - a raw "{crlf}...HTTP/1.1..." request-smuggling template that
                only fires through a CRLF-capable fetch vector + OOB canary.
"""

import json
import logging
import os
from dataclasses import dataclass
from typing import Iterator, List, Optional
from urllib.parse import quote, urlparse


@dataclass
class RenderedPayload:
    category: str      # e.g. "canaries", "http", "gopher"
    name: str          # e.g. "Weblogic/UDDI Explorer (CVE-2014-4210)"
    value: str         # fully rendered payload
    kind: str          # "url" | "gopher" | "smuggle"
    needs_canary: bool  # True if the template referenced a canary token


class BlindPayloadLibrary:
    # A harmless marker command. We never want to run destructive commands;
    # this is only used to fill the {command} slot so templates render.
    DEFAULT_COMMAND = "id"

    def __init__(self, path: str, logger: Optional[logging.Logger] = None):
        self.path = path
        self.logger = logger or logging.getLogger("ssrf_scanner")
        self._raw = {}
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            self.logger.warning(f"Blind payload file not found: {self.path}")
            return
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            self._raw = data.get("categories", {}) if isinstance(data, dict) else {}
            self.logger.info(
                f"Loaded {self.count()} blind-SSRF template payloads from "
                f"{os.path.basename(self.path)}"
            )
        except Exception as e:
            self.logger.error(f"Error loading blind payloads: {e}")
            self._raw = {}

    @staticmethod
    def _walk(node, trail):
        """Yield (name, template_string) leaf pairs from the nested structure."""
        if isinstance(node, str):
            yield ("/".join(trail), node)
        elif isinstance(node, dict):
            for k, v in node.items():
                yield from BlindPayloadLibrary._walk(v, trail + [str(k)])
        elif isinstance(node, list):
            for i, v in enumerate(node):
                yield from BlindPayloadLibrary._walk(v, trail + [str(i)])

    def count(self) -> int:
        return sum(1 for _cat, sub in self._raw.items() for _ in self._walk(sub, []))

    @staticmethod
    def _classify(template: str) -> str:
        t = template.lstrip()
        if t.startswith("{target_addr}"):
            return "url"
        if t.startswith("gopher://"):
            return "gopher"
        return "smuggle"

    def iter_templates(self, include_smuggle: bool = True):
        """Yield ``(category, name, template, kind, needs_canary)`` tuples.

        Exposes the raw (unrendered) templates so callers can substitute a
        different canary per payload - needed for per-payload OOB correlation.
        """
        for category, sub in self._raw.items():
            for name, template in self._walk(sub, []):
                if not isinstance(template, str):
                    continue
                kind = self._classify(template)
                if kind == "smuggle" and not include_smuggle:
                    continue
                needs_canary = ("{canary_addr}" in template
                                or "{canary_urlencoded}" in template)
                yield (category, name, template, kind, needs_canary)

    def _replacements(self, target_url, canary, command):
        parsed = urlparse(target_url)
        target_host = parsed.hostname or target_url
        target_addr = target_url.rstrip("/")
        canary_addr = (canary or "").strip()
        command = command or self.DEFAULT_COMMAND
        return {
            "{target_addr}": target_addr,
            "{target_host}": target_host,
            "{canary_addr}": canary_addr,
            "{canary_urlencoded}": quote(canary_addr, safe=""),
            "{command}": command,
            # URL-encoded separators so the rendered value survives being sent
            # as a header/parameter value (raw CR/LF would be rejected).
            "{crlf}": "%0d%0a",
            "{newline}": "%0a",
        }

    def render_one(self, template: str, target_url: str,
                   canary: Optional[str] = None,
                   command: Optional[str] = None) -> str:
        """Render a single template string with the given substitutions."""
        rendered = template
        for token, val in self._replacements(target_url, canary, command).items():
            rendered = rendered.replace(token, val)
        return rendered

    def render(
        self,
        target_url: str,
        canary: Optional[str] = None,
        command: Optional[str] = None,
        include_smuggle: bool = True,
    ) -> Iterator[RenderedPayload]:
        """Render every template for a given target using a single canary.

        Convenience wrapper over :meth:`iter_templates` + :meth:`render_one`.
        Canary-dependent templates are flagged via ``needs_canary`` so callers
        may skip them when no callback is configured.
        """
        for category, name, template, kind, needs_canary in self.iter_templates(include_smuggle):
            yield RenderedPayload(
                category=category,
                name=name,
                value=self.render_one(template, target_url, canary, command),
                kind=kind,
                needs_canary=needs_canary,
            )
