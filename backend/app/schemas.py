import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_HOST = re.compile(r"^[a-z0-9:]([a-z0-9.:\-]{0,251}[a-z0-9:])?$", re.I)


class DemoAuditRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target_label: str = Field(default="LAB-DEMO", min_length=1, max_length=100, pattern=r"^[\w .\-]+$")


class ConnectCheckRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str = Field(min_length=1, max_length=253)
    ports: list[int] = Field(min_length=1, max_length=10)
    engagement_id: str = Field(pattern=r"^[A-Za-z0-9._\-]{3,100}$")
    authorization_confirmed: bool

    @field_validator("target")
    @classmethod
    def _target(cls, v: str) -> str:
        v = v.strip()
        if not _HOST.match(v):
            raise ValueError("invalid target")
        return v

    @field_validator("ports")
    @classmethod
    def _ports(cls, v: list[int]) -> list[int]:
        if len(set(v)) != len(v) or any(not 0 < p < 65536 for p in v):
            raise ValueError("invalid ports")
        return v


class Finding(BaseModel):
    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    description: str
    evidence: str
    simulated: bool = False
    recommendation: str = ""
