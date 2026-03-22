"""Graph API ingestors for the Identity Security Agent."""

from identity_agent.ingest.access_reviews import AccessReviewsIngestor
from identity_agent.ingest.app_registrations import AppRegistrationsIngestor
from identity_agent.ingest.auth_methods import AuthMethodsIngestor
from identity_agent.ingest.base import BaseIngestor
from identity_agent.ingest.break_glass import BreakGlassIngestor
from identity_agent.ingest.conditional_access import ConditionalAccessIngestor
from identity_agent.ingest.directory_roles import DirectoryRolesIngestor
from identity_agent.ingest.guests import GuestsIngestor
from identity_agent.ingest.hardening import HardeningIngestor
from identity_agent.ingest.mfa_registration import MFARegistrationIngestor
from identity_agent.ingest.pim import PIMIngestor
from identity_agent.ingest.risky_users import RiskyUsersIngestor
from identity_agent.ingest.sign_in_risk import SignInRiskIngestor

__all__ = [
    "AccessReviewsIngestor",
    "AppRegistrationsIngestor",
    "AuthMethodsIngestor",
    "BaseIngestor",
    "BreakGlassIngestor",
    "ConditionalAccessIngestor",
    "DirectoryRolesIngestor",
    "GuestsIngestor",
    "HardeningIngestor",
    "MFARegistrationIngestor",
    "PIMIngestor",
    "RiskyUsersIngestor",
    "SignInRiskIngestor",
]
