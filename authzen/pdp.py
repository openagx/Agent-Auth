"""AuthZEN PDP (Policy Decision Point) base implementation.

The PDP is responsible for evaluating authorization requests and returning decisions.
"""

from abc import ABC, abstractmethod
from typing import Any

from authzen.models import Action, Context, Decision, Resource, Subject


class PDPInterface(ABC):
    """Abstract base class for AuthZEN PDP implementations.
    
    PDP implementations must implement the evaluate method to provide
    authorization decisions.
    """
    
    @abstractmethod
    def evaluate(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        """Evaluate an authorization request.
        
        Args:
            subject: The subject requesting access
            action: The action being requested
            resource: The resource being accessed
            context: Optional context information
            
        Returns:
            A Decision object with the authorization result
        """
        pass
    
    @abstractmethod
    def evaluate_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[Decision]:
        """Evaluate multiple authorization requests.
        
        Args:
            evaluations: List of evaluation requests
            
        Returns:
            List of Decision objects
        """
        pass


class SimplePDP(PDPInterface):
    """A simple PDP implementation with a basic policy language.
    
    This PDP makes decisions based on configurable allow/deny rules.
    """
    
    def __init__(self):
        """Initialize the simple PDP."""
        self._rules: list[dict[str, Any]] = []
    
    def add_rule(
        self,
        subject_type: str | None = None,
        subject_id: str | None = None,
        action_name: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        allowed: bool = True,
    ):
        """Add an authorization rule.
        
        Args:
            subject_type: Match subject type (None = any)
            subject_id: Match subject ID (None = any)
            action_name: Match action name (None = any)
            resource_type: Match resource type (None = any)
            resource_id: Match resource ID (None = any)
            allowed: Whether to allow or deny
        """
        rule = {
            "subject_type": subject_type,
            "subject_id": subject_id,
            "action_name": action_name,
            "resource_type": resource_type,
            "resource_id": resource_id,
            "allowed": allowed,
        }
        self._rules.append(rule)
    
    def _match(self, value: str | None, pattern: str | None) -> bool:
        """Check if a value matches a pattern."""
        if pattern is None:
            return True
        if value is None:
            return False
        return value == pattern
    
    def _evaluate_rule(
        self,
        rule: dict[str, Any],
        subject: Subject,
        action: Action,
        resource: Resource,
    ) -> bool | None:
        """Evaluate a single rule."""
        if not self._match(subject.type, rule.get("subject_type")):
            return None
        if not self._match(subject.id, rule.get("subject_id")):
            return None
        if not self._match(action.name, rule.get("action_name")):
            return None
        if not self._match(resource.type, rule.get("resource_type")):
            return None
        if not self._match(resource.id, rule.get("resource_id")):
            return None
        return rule["allowed"]
    
    def evaluate(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        """Evaluate an authorization request."""
        # Check each rule in order
        for rule in self._rules:
            result = self._evaluate_rule(rule, subject, action, resource)
            if result is not None:
                return Decision(decision=result)
        
        # Default deny if no rules match
        return Decision(decision=False)
    
    def evaluate_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[Decision]:
        """Evaluate multiple authorization requests."""
        results = []
        for eval_request in evaluations:
            subject = Subject.from_dict(eval_request["subject"])
            action = Action.from_dict(eval_request["action"])
            resource = Resource.from_dict(eval_request["resource"])
            context = Context.from_dict(eval_request.get("context", {}))
            
            decision = self.evaluate(subject, action, resource, context)
            results.append(decision)
        
        return results


class AlwaysAllowPDP(PDPInterface):
    """A PDP that always returns allow."""
    
    def evaluate(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        """Always return allow."""
        return Decision(decision=True)
    
    def evaluate_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[Decision]:
        """Always return allow for all evaluations."""
        return [Decision(decision=True) for _ in evaluations]


class AlwaysDenyPDP(PDPInterface):
    """A PDP that always returns deny."""
    
    def evaluate(
        self,
        subject: Subject,
        action: Action,
        resource: Resource,
        context: Context | None = None,
    ) -> Decision:
        """Always return deny."""
        return Decision(decision=False, context={"reason": "Access denied by policy"})
    
    def evaluate_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[Decision]:
        """Always return deny for all evaluations."""
        return [
            Decision(decision=False, context={"reason": "Access denied by policy"})
            for _ in evaluations
        ]
