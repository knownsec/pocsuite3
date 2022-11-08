from dataclasses import dataclass, field
from enum import Enum
from typing import NewType, Union

StrSlice = NewType('StrSlice', Union[str, list])


class CaseInsensitiveEnum(Enum):
    @classmethod
    def _missing_(cls, value: str):
        for member in cls:
            if member.value == value.lower():
                return member


class Severify(CaseInsensitiveEnum):
    Info = 'info'
    Low = 'low'
    Medium = 'medium'
    High = 'high'
    Critical = 'critical'
    Unknown = 'unknown'


@dataclass
class Classification:
    """Classification contains the vulnerability classification data for a template.
    """
    cve_id: StrSlice = field(default_factory=list)
    cwe_id: StrSlice = field(default_factory=list)
    cvss_metrics: str = ''
    cvss_score: float = 0.0


@dataclass
class Info:
    """Info contains metadata information about a template
    """
    name: str = ''
    author: StrSlice = field(default_factory=list)
    tags: StrSlice = field(default_factory=list)
    description: str = ''
    reference: StrSlice = field(default_factory=list)
    severity: Severify = Severify.Unknown
    metadata: dict = field(default_factory=dict)
    classification: Classification = field(default_factory=Classification)
    remediation: str = ''
