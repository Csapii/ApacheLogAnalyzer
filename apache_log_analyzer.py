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
