"""Governance and audit features for AuthZEN PDP.

This module provides governance features:
- Audit logging for all access decisions
- Decision metadata and tracing
- Governance API endpoints
- Policy versioning
"""

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
from enum import Enum

logger = logging.getLogger(__name__)


class DecisionType(Enum):
    """Type of access decision."""
    ALLOW = "allow"
    DENY = "deny"
    NO_MATCH = "no_match"


class AuditLevel(Enum):
    """Audit log level."""
    DECISION = "decision"      # Log all decisions
    DENY_ONLY = "deny_only"   # Log only denied requests
    NONE = "none"          # No audit logging


@dataclass
class DecisionMetadata:
    """Metadata for an access decision."""
    request_id: str
    timestamp: str
    pdp_version: str = "1.0"
    policy_version: str | None = None
    policy_id: str | None = None
    matched_rule: str | None = None
    evaluation_time_ms: float = 0.0
    trace: list[str] = field(default_factory=list)


@dataclass
class AuditEntry:
    """Audit log entry."""
    id: str
    timestamp: str
    subject_type: str
    subject_id: str
    action: str
    resource_type: str
    resource_id: str
    decision: str
    decision_type: str
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


class AuditLogger:
    """Audit logger for access decisions."""
    
    def __init__(
        self,
        level: AuditLevel = AuditLevel.DECISION,
        storage: list[AuditEntry] | None = None,
    ):
        self.level = level
        self._storage: list[AuditEntry] = storage or []
        self._id_counter = 0
    
    def log(
        self,
        subject_type: str,
        subject_id: str,
        action: str,
        resource_type: str,
        resource_id: str,
        decision: bool,
        context: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> AuditEntry:
        """Log an access decision."""
        self._id_counter += 1
        entry = AuditEntry(
            id=f"audit-{self._id_counter}",
            timestamp=datetime.utcnow().isoformat(),
            subject_type=subject_type,
            subject_id=subject_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            decision="allow" if decision else "deny",
            decision_type=(
                DecisionType.ALLOW.value if decision 
                else DecisionType.DENY.value
            ),
            context=context or {},
            metadata=metadata or {},
        )
        
        # Skip if not logging this level
        if self.level == AuditLevel.DENY_ONLY and decision:
            return entry
        
        if self.level != AuditLevel.NONE:
            self._storage.append(entry)
            logger.info(f"AUDIT: {entry.decision} {subject_type}:{subject_id} {action} {resource_type}:{resource_id}")
        
        return entry
    
    def get_entries(
        self,
        subject_type: str | None = None,
        subject_id: str | None = None,
        resource_type: str | None = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        """Query audit entries."""
        results = self._storage
        
        if subject_type:
            results = [e for e in results if e.subject_type == subject_type]
        if subject_id:
            results = [e for e in results if e.subject_id == subject_id]
        if resource_type:
            results = [e for e in results if e.resource_type == resource_type]
        
        return results[-limit:]
    
    def clear(self) -> None:
        """Clear audit logs."""
        self._storage.clear()


@dataclass
class PolicyVersion:
    """Policy version information."""
    version: str
    created_at: str
    description: str
    rules: list[dict[str, Any]]
    active: bool = True


class PolicyVersionStore:
    """Store for policy versions."""
    
    def __init__(self):
        self._versions: list[PolicyVersion] = []
        self._active_version: str | None = None
    
    def add_version(
        self,
        version: str,
        rules: list[dict[str, Any]],
        description: str = "",
    ) -> PolicyVersion:
        """Add a new policy version."""
        pv = PolicyVersion(
            version=version,
            created_at=datetime.utcnow().isoformat(),
            description=description,
            rules=rules,
            active=True,
        )
        self._versions.append(pv)
        
        # Deactivate others
        for v in self._versions[:-1]:
            v.active = False
        
        self._active_version = version
        return pv
    
    def get_active(self) -> PolicyVersion | None:
        """Get the active policy version."""
        if self._active_version:
            for v in self._versions:
                if v.version == self._active_version:
                    return v
        return self._versions[-1] if self._versions else None
    
    def get_version(self, version: str) -> PolicyVersion | None:
        """Get a specific policy version."""
        for v in self._versions:
            if v.version == version:
                return v
        return None
    
    def list_versions(self) -> list[PolicyVersion]:
        """List all policy versions."""
        return self._versions.copy()


# Governance API Models
@dataclass
class GovernanceMetrics:
    """Governance metrics."""
    total_requests: int = 0
    allowed_requests: int = 0
    denied_requests: int = 0
    avg_decision_time_ms: float = 0.0
    unique_subjects: int = 0
    unique_resources: int = 0


class GovernanceService:
    """Governance service for PDP."""
    
    def __init__(
        self,
        audit_level: AuditLevel = AuditLevel.DECISION,
        policy_store: PolicyVersionStore | None = None,
    ):
        self.audit = AuditLogger(level=audit_level)
        self.policy_store = policy_store or PolicyVersionStore()
        self._start_time = time.time()
    
    def get_metrics(self) -> GovernanceMetrics:
        """Calculate governance metrics."""
        entries = self.audit.get_entries(limit=10000)
        
        metrics = GovernanceMetrics()
        metrics.total_requests = len(entries)
        
        for entry in entries:
            if entry.decision == "allow":
                metrics.allowed_requests += 1
            else:
                metrics.denied_requests += 1
        
        # Calculate unique subjects/resources
        subjects = set()
        resources = set()
        for entry in entries:
            subjects.add(entry.subject_id)
            resources.add(f"{entry.resource_type}:{entry.resource_id}")
        
        metrics.unique_subjects = len(subjects)
        metrics.unique_resources = len(resources)
        
        return metrics
    
    def export_audit_log(self, format: str = "json") -> str:
        """Export audit log."""
        entries = self.audit.get_entries(limit=10000)
        
        if format == "json":
            return json.dumps([
                {
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "subject": f"{e.subject_type}:{e.subject_id}",
                    "action": e.action,
                    "resource": f"{e.resource_type}:{e.resource_id}",
                    "decision": e.decision,
                }
                for e in entries
            ], indent=2)
        
        return str(entries)


def create_governance_pdp(pdp, audit_level: AuditLevel = AuditLevel.DECISION):
    """Create a PDP with governance features."""
    from authzen.pdp import PDPInterface
    
    class GovernancePDP(PDPInterface):
        """PDP with governance."""
        
        def __init__(self):
            self.inner = pdp
            self.governance = GovernanceService(audit_level=audit_level)
        
        def evaluate(self, subject, action, resource, context=None):
            start = time.time()
            decision = self.inner.evaluate(subject, action, resource, context)
            elapsed = (time.time() - start) * 1000
            
            # Log to audit
            self.governance.audit.log(
                subject_type=subject.type,
                subject_id=subject.id,
                action=action.name,
                resource_type=resource.type,
                resource_id=resource.id,
                decision=decision.decision,
                context=context.properties if context else None,
                metadata={"evaluation_time_ms": elapsed},
            )
            
            return decision
        
        def evaluate_batch(self, evaluations):
            results = []
            for eval_request in evaluations:
                subject = type(eval_request["subject"]).__from_dict__(eval_request["subject"])
                action = type(eval_request["action"]).__from_dict__(eval_request["action"])
                resource = type(eval_request["resource"]).__from_dict__(eval_request["resource"])
                context = type(eval_request.get("context", {}).__from_dict__(eval_request.get("context", {}))
                
                decision = self.evaluate(subject, action, resource, context)
                results.append(decision)
            
            return results
    
    return GovernancePDP()
