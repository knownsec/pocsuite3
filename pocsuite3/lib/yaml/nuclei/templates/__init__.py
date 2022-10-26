from dataclasses import dataclass, field
from enum import Enum

from pocsuite3.lib.yaml.nuclei.model import Info
from pocsuite3.lib.yaml.nuclei.protocols.http import HttpRequest


class ProtocolType(Enum):
    InvalidProtocol = "invalid"
    DNSProtocol = "dns"
    FileProtocol = "file"
    HTTPProtocol = "http"
    HeadlessProtocol = "headless"
    NetworkProtocol = "network"
    WorkflowProtocol = "workflow"
    SSLProtocol = "ssl"
    WebsocketProtocol = "websocket"
    WHOISProtocol = "whois"


# Template is a YAML input file which defines all the requests and other metadata for a template.
@dataclass
class Template:
    id: str = ''
    info: Info = field(default_factory=Info)
    requests: list[HttpRequest] = field(default_factory=list)
    stop_at_first_match: bool = True
    variables: dict = field(default_factory=dict)
