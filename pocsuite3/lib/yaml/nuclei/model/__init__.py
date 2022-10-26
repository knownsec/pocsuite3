from dataclasses import dataclass, field
from enum import Enum
from typing import NewType, Union

StrSlice = NewType('StrSlice', Union[str, list])


class Severify(Enum):
    Info = 'info'
    Low = 'low'
    Medium = 'medium'
    High = 'high'
    Critical = 'critical'
    Unknown = 'unknown'


# Classification contains the vulnerability classification data for a template.
@dataclass
class Classification:
    cve_id: StrSlice = field(default_factory=list)
    cwe_id: StrSlice = field(default_factory=list)
    cvss_metrics: str = ''
    cvss_score: float = 0.0


# Info contains metadata information abount a template
@dataclass
class Info:
    name: str = ''
    author: StrSlice = field(default_factory=list)
    tags: StrSlice = field(default_factory=list)
    description: str = ''
    reference: StrSlice = field(default_factory=list)
    severity: Severify = 'unknown'
    metadata: dict = field(default_factory=dict)
    classification: Classification = field(default_factory=Classification)
    remediation: str = ''
