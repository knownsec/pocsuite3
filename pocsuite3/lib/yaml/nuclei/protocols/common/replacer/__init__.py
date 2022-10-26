import json


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
            data = data.replace(f'{Marker.General}{k}{Marker.General}', v)
            data = data.replace(f'{Marker.ParenthesisOpen}{k}{Marker.ParenthesisClose}', v)

    # TODO
    # various helper functions
    return json.loads(data)
