import itertools
from collections import OrderedDict

from pocsuite3.lib.core.common import check_file, get_file_items
from pocsuite3.lib.yaml.nuclei.model import CaseInsensitiveEnum


class AttackType(CaseInsensitiveEnum):
    BatteringRamAttack = "batteringram"
    PitchForkAttack = "pitchfork"
    ClusterBombAttack = "clusterbomb"


def payload_generator(payloads: dict, attack_type: AttackType) -> OrderedDict:
    payloads_final = OrderedDict()
    payloads_final.update(payloads)

    for k, v in payloads_final.items():
        if isinstance(v, str) and check_file(v):
            payloads_final[k] = get_file_items(v)

    payload_keys, payload_vals = payloads_final.keys(), payloads_final.values()
    payload_vals = [i if isinstance(i, list) else [i] for i in payload_vals]

    if attack_type == AttackType.PitchForkAttack:
        for instance in zip(*payload_vals):
            yield dict(zip(payload_keys, instance))
    else:
        for instance in itertools.product(*payload_vals):
            yield dict(zip(payload_keys, instance))
