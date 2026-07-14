"""Data models shared across the scanner."""

from dataclasses import dataclass
from datetime import datetime
from typing import Dict


@dataclass
class ScanResult:
    url: str
    attack_type: str
    payload: str
    response_code: int
    response_size: int
    timestamp: datetime
    headers: Dict[str, str]
    is_vulnerable: bool
    verification_method: str = ""
    notes: str = ""

