"""Import every model so Alembic autogenerate and ``create_all`` see the full schema."""
from .email_identity import (  # noqa: F401
    DnsAuthenticationResult, DomainAnalysis, EmailInvestigationReport, EmailRiskAssessment,
    EmailVerificationRecord, OwnershipVerificationToken, VerificationAuditLog,
)
from .foundation import (  # noqa: F401
    AuditLog, Document, DocumentChunk, Incident, Report, Tenant, ThreatIndicator, User,
)
