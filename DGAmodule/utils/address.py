from dataclasses import dataclass

@dataclass
class IPAddress:
    """IP address class"""
    ip: str
    port: int