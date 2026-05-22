import re
import sys
import argparse

from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass


@dataclass
class LogEntry:
    ip: str
    timestamp: datetime
    method: str
    uri: str
    query_string: str
    status_code: int

    def __str__(self) -> str:
        qs = f"?{self.query_string}" if self.query_string else ""
        return (
            f"[{self.timestamp}] "
            f"{self.ip} "
            f"{self.method} "
            f"{self.uri}{qs} "
            f"-> {self.status_code}"
        )

    def __repr__(self) -> str:
        return (
            f"LogEntry(ip={self.ip!r}, "
            f"timestamp={self.timestamp!r}, "
            f"method={self.method!r}, "
            f"uri={self.uri!r}, "
            f"query_string={self.query_string!r}, "
            f"status_code={self.status_code!r})"
        )