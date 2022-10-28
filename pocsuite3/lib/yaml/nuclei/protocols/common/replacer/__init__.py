import json

from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import Evaluate


class Marker:
    # General marker (open/close)
    General = "§"
    # ParenthesisOpen marker - begin of a placeholder
    ParenthesisOpen = "{{"
    # ParenthesisClose marker - end of a placeholder
    ParenthesisClose = "}}"


def marker_replace(data, dynamic_values):
    """replaces placeholders in template with values
    """
    data = json.dumps(data)
    for k, v in dynamic_values.items():
        if k in data:
            data = data.replace(f'{Marker.General}{k}{Marker.General}', str(v))
            data = data.replace(f'{Marker.ParenthesisOpen}{k}{Marker.ParenthesisClose}', str(v))

    data = Evaluate(data, dynamic_values)
    # various helper functions
    return json.loads(data)
