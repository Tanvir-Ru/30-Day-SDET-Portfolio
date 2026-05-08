"""
Toxiproxy client wrapper.

Toxiproxy is a TCP proxy that can simulate network conditions:
  - Latency injection (adds delay to every packet)
  - Bandwidth throttling (limits bytes per second)
  - Packet loss (randomly drops connections)
  - Slow close (delays connection close, leaving sockets half-open)
  - Timeout (closes connection after N ms)
  - Reset peer (sends TCP RST instead of FIN)
  - Slicer (splits packets into smaller chunks)
  - LimitData (closes connection after N bytes)

This wrapper provides a Python API over the Toxiproxy HTTP REST API,
making it easy to create proxies, inject toxics, and tear them down
programmatically from test code.

Toxiproxy REST API: https://github.com/Shopify/toxiproxy
Docker: docker run -d -p 8474:8474 -p 8000-8100:8000-8100 ghcr.io/shopify/toxiproxy

Architecture note: Toxiproxy sits between the test client and the API.
Tests point at the Toxiproxy port; Toxiproxy forwards to the real API
and injects the configured failures in the middle.

  [Test] → localhost:8001 (Toxiproxy) → localhost:8000 (Real API)
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import httpx


@dataclass
class ToxicConfig:
    """Configuration for a single Toxiproxy toxic."""
    type:       str                   # latency, bandwidth, slow_close, timeout, reset_peer, slicer, limit_data
    stream:     str = "downstream"   # downstream | upstream
    toxicity:   float = 1.0          # 0.0–1.0 — fraction of connections affected
    attributes: dict = field(default_factory=dict)

    @classmethod
    def latency(cls, latency_ms: int, jitter_ms: int = 0) -> "ToxicConfig":
        """Add fixed latency ± jitter to every response."""
        return cls(type="latency", attributes={"latency": latency_ms, "jitter": jitter_ms})

    @classmethod
    def bandwidth(cls, rate_kbps: int) -> "ToxicConfig":
        """Limit throughput to rate_kbps kilobytes per second."""
        return cls(type="bandwidth", attributes={"rate": rate_kbps})

    @classmethod
    def timeout(cls, timeout_ms: int) -> "ToxicConfig":
        """Close connection after timeout_ms without response."""
        return cls(type="timeout", attributes={"timeout": timeout_ms})

    @classmethod
    def reset_peer(cls, timeout_ms: int = 0) -> "ToxicConfig":
        """Send TCP RST after timeout_ms — hard disconnect."""
        return cls(type="reset_peer", attributes={"timeout": timeout_ms})

    @classmethod
    def slow_close(cls, delay_ms: int) -> "ToxicConfig":
        """Delay connection close — leaves sockets half-open."""
        return cls(type="slow_close", attributes={"delay": delay_ms})

    @classmethod
    def packet_loss(cls, toxicity: float = 0.5) -> "ToxicConfig":
        """Randomly close connections (simulates packet loss)."""
        return cls(type="reset_peer", toxicity=toxicity, attributes={"timeout": 0})

    @classmethod
    def slicer(cls, average_size: int = 1, size_variation: int = 0, delay_us: int = 0) -> "ToxicConfig":
        """Slice data into small packets to simulate slow networks."""
        return cls(type="slicer", attributes={
            "average_size": average_size,
            "size_variation": size_variation,
            "delay": delay_us,
        })


class ToxiproxyProxy:
    """Represents a single Toxiproxy proxy with methods to add/remove toxics."""

    def __init__(self, name: str, listen: str, upstream: str, client: "ToxiproxyClient"):
        self.name     = name
        self.listen   = listen
        self.upstream = upstream
        self._client  = client
        self._toxics: list[str] = []

    @property
    def url(self) -> str:
        return f"http://{self.listen}"

    def add_toxic(self, toxic: ToxicConfig, name: str = None) -> str:
        """Add a toxic to this proxy. Returns the toxic name."""
        toxic_name = name or f"{toxic.type}_{int(time.time() * 1000)}"
        payload = {
            "name":     toxic_name,
            "type":     toxic.type,
            "stream":   toxic.stream,
            "toxicity": toxic.toxicity,
            "attributes": toxic.attributes,
        }
        self._client._post(f"/proxies/{self.name}/toxics", payload)
        self._toxics.append(toxic_name)
        return toxic_name

    def remove_toxic(self, toxic_name: str) -> None:
        self._client._delete(f"/proxies/{self.name}/toxics/{toxic_name}")
        self._toxics = [t for t in self._toxics if t != toxic_name]

    def remove_all_toxics(self) -> None:
        for name in list(self._toxics):
            try:
                self.remove_toxic(name)
            except Exception:
                pass

    def disable(self) -> None:
        self._client._post(f"/proxies/{self.name}", {"enabled": False})

    def enable(self) -> None:
        self._client._post(f"/proxies/{self.name}", {"enabled": True})

    def delete(self) -> None:
        self.remove_all_toxics()
        self._client._delete(f"/proxies/{self.name}")

    @contextlib.contextmanager
    def toxic(self, config: ToxicConfig, name: str = None):
        """Context manager: add toxic, yield, remove toxic."""
        toxic_name = self.add_toxic(config, name)
        try:
            yield toxic_name
        finally:
            try:
                self.remove_toxic(toxic_name)
            except Exception:
                pass


class ToxiproxyClient:
    """
    HTTP client for the Toxiproxy management API.
    Default management port: 8474
    """

    def __init__(self, host: str = "localhost", port: int = 8474):
        self.base_url = f"http://{host}:{port}"
        self._session = httpx.Client(timeout=5.0)

    def is_running(self) -> bool:
        try:
            resp = self._session.get(f"{self.base_url}/version")
            return resp.status_code == 200
        except Exception:
            return False

    def create_proxy(
        self,
        name:     str,
        listen:   str,
        upstream: str,
    ) -> ToxiproxyProxy:
        """Create a proxy that forwards traffic from listen → upstream."""
        payload = {"name": name, "listen": listen, "upstream": upstream, "enabled": True}
        self._post("/proxies", payload)
        return ToxiproxyProxy(name=name, listen=listen, upstream=upstream, client=self)

    def get_proxy(self, name: str) -> ToxiproxyProxy:
        resp = self._session.get(f"{self.base_url}/proxies/{name}")
        resp.raise_for_status()
        data = resp.json()
        return ToxiproxyProxy(
            name=data["name"],
            listen=data["listen"],
            upstream=data["upstream"],
            client=self,
        )

    def list_proxies(self) -> list[str]:
        resp = self._session.get(f"{self.base_url}/proxies")
        resp.raise_for_status()
        return list(resp.json().keys())

    def reset(self) -> None:
        """Remove all toxics from all proxies."""
        self._post("/reset", {})

    def delete_all(self) -> None:
        for name in self.list_proxies():
            try:
                self._delete(f"/proxies/{name}")
            except Exception:
                pass

    @contextlib.contextmanager
    def proxy(self, name: str, listen: str, upstream: str):
        """Context manager: create proxy, yield, delete proxy."""
        p = self.create_proxy(name, listen, upstream)
        try:
            yield p
        finally:
            try:
                p.delete()
            except Exception:
                pass

    def _post(self, path: str, data: dict) -> dict:
        resp = self._session.post(f"{self.base_url}{path}", json=data)
        resp.raise_for_status()
        try:
            return resp.json()
        except Exception:
            return {}

    def _delete(self, path: str) -> None:
        resp = self._session.delete(f"{self.base_url}{path}")
        resp.raise_for_status()

    def close(self) -> None:
        self._session.close()
