import json

from pocsuite3.lib.yaml.nuclei.protocols.common.expressions import evaluate, UNRESOLVED_VARIABLE, Marker


class UnresolvedVariableException(Exception):
    pass


def marker_replace(data, dynamic_values):
    """replaces placeholders in template with values
    """
    data = json.dumps(data)
    for k, v in dynamic_values.items():
        if k in data:
            data = data.replace(f'{Marker.General}{k}{Marker.General}', str(v))
            data = data.replace(f'{Marker.ParenthesisOpen}{k}{Marker.ParenthesisClose}', str(v))

    # execute various helper functions
    data = evaluate(data, dynamic_values)

    if UNRESOLVED_VARIABLE in data:
        raise UnresolvedVariableException

    return json.loads(data)
