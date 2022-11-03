from dataclasses import dataclass, field

from pocsuite3.lib.core.log import LOGGER as logger
from pocsuite3.modules.interactsh import Interactsh


@dataclass
class InteractshClient:
    client: Interactsh = field(default_factory=Interactsh)
    interactsh_protocol: list = field(default_factory=list)
    interactsh_request: list = field(default_factory=list)
    interactsh_response: list = field(default_factory=list)

    def poll(self) -> None:
        results = self.client.poll()
        for result in results:
            logger.debug(result)
            self.interactsh_protocol.append(result['protocol'])
            self.interactsh_request.append(result['raw-request'])
            self.interactsh_response.append(result['raw-response'])
