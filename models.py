from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    title: str
    file: str
    line: int
    message: str
    evidence: list[str] = field(default_factory=list)