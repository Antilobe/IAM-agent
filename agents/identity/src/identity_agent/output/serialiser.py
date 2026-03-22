"""JSON serialisation helpers for assessment output."""

from __future__ import annotations

import json
from datetime import datetime

from identity_agent.models.assessment import IdentityAssessment


class AssessmentSerialiser:
    """Serialise/deserialise IdentityAssessment to/from JSON."""

    @staticmethod
    def to_json(assessment: IdentityAssessment, *, indent: int = 2) -> str:
        return assessment.model_dump_json(indent=indent)

    @staticmethod
    def to_dict(assessment: IdentityAssessment) -> dict:
        return assessment.model_dump(mode="json")

    @staticmethod
    def from_json(data: str) -> IdentityAssessment:
        return IdentityAssessment.model_validate_json(data)

    @staticmethod
    def from_dict(data: dict) -> IdentityAssessment:
        return IdentityAssessment.model_validate(data)
