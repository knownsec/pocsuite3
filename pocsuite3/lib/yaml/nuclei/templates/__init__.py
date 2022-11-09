from dataclasses import dataclass, field
from typing import List

from pocsuite3.lib.yaml.nuclei.model import Info, CaseInsensitiveEnum
from pocsuite3.lib.yaml.nuclei.protocols.http import HttpRequest
from pocsuite3.lib.yaml.nuclei.protocols.network import NetworkRequest


class ProtocolType(CaseInsensitiveEnum):
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


@dataclass
class Template:
    """Template is a YAML input file which defines all the requests and other metadata for a template.
    """
    id: str = ''
    info: Info = field(default_factory=Info)
    requests: List[HttpRequest] = field(default_factory=list)
    network: List[NetworkRequest] = field(default_factory=list)
    stop_at_first_match: bool = True
    variables: dict = field(default_factory=dict)
