"""Tests for AuthZEN SDK."""

import pytest
from authzen.models import Subject, Resource, Action, Context, Decision
from authzen.pdp import SimplePDP, AlwaysAllowPDP, AlwaysDenyPDP, PDPInterface
from authzen.schema import validate_request, validate_response
from authzen.pep import PEPClient


# ==================== Model Tests ====================

class TestModels:
    """Test domain models."""
    
    def test_subject_creation(self):
        subject = Subject(type="user", id="alice@example.com")
        assert subject.type == "user"
        assert subject.id == "alice@example.com"
        assert subject.properties == {}
    
    def test_subject_with_properties(self):
        subject = Subject(
            type="user",
            id="alice@example.com",
            properties={"department": "Sales", "role": "admin"}
        )
        assert subject.properties["department"] == "Sales"
    
    def test_subject_to_dict(self):
        subject = Subject(type="user", id="alice@example.com")
        d = subject.to_dict()
        assert d == {"type": "user", "id": "alice@example.com"}
    
    def test_subject_from_dict(self):
        data = {"type": "user", "id": "alice@example.com", "properties": {"dept": "IT"}}
        subject = Subject.from_dict(data)
        assert subject.type == "user"
        assert subject.id == "alice@example.com"
        assert subject.properties == {"dept": "IT"}
    
    def test_resource_creation(self):
        resource = Resource(type="document", id="123")
        assert resource.type == "document"
        assert resource.id == "123"
    
    def test_resource_to_dict(self):
        resource = Resource(type="document", id="123")
        d = resource.to_dict()
        assert d == {"type": "document", "id": "123"}
    
    def test_action_creation(self):
        action = Action(name="can_read")
        assert action.name == "can_read"
    
    def test_action_with_properties(self):
        action = Action(name="extend-loan", properties={"period": "2W"})
        assert action.properties["period"] == "2W"
    
    def test_context_creation(self):
        context = Context(properties={"time": "2024-01-01T12:00:00Z"})
        assert context.properties["time"] == "2024-01-01T12:00:00Z"
    
    def test_decision_creation(self):
        decision = Decision(decision=True)
        assert decision.decision is True
        assert decision.allowed is True
        assert decision.denied is False
    
    def test_decision_with_context(self):
        decision = Decision(decision=False, context={"reason": "Not authorized"})
        assert decision.decision is False
        assert decision.denied is True
        assert decision.context["reason"] == "Not authorized"


# ==================== SimplePDP Tests ====================

class TestSimplePDP:
    """Test SimplePDP implementation."""
    
    def test_always_deny_by_default(self):
        pdp = SimplePDP()
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="read"),
            Resource(type="doc", id="1"),
        )
        assert decision.decision is False
    
    def test_allow_with_rule(self):
        pdp = SimplePDP()
        pdp.add_rule(
            subject_type="user",
            action_name="read",
            resource_type="doc",
            allowed=True,
        )
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="read"),
            Resource(type="doc", id="1"),
        )
        assert decision.decision is True
    
    def test_deny_rule(self):
        pdp = SimplePDP()
        pdp.add_rule(subject_type="user", action_name="delete", resource_type="doc", allowed=False)
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="delete"),
            Resource(type="doc", id="1"),
        )
        assert decision.decision is False
    
    def test_wildcard_subject(self):
        pdp = SimplePDP()
        pdp.add_rule(action_name="read", resource_type="doc", allowed=True)
        
        # Should match any subject
        decision = pdp.evaluate(
            Subject(type="user", id="any"),
            Action(name="read"),
            Resource(type="doc", id="1"),
        )
        assert decision.decision is True
    
    def test_wildcard_resource(self):
        pdp = SimplePDP()
        pdp.add_rule(subject_type="user", action_name="read", allowed=True)
        
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="read"),
            Resource(type="anything", id="1"),
        )
        assert decision.decision is True
    
    def test_batch_evaluation(self):
        pdp = SimplePDP()
        pdp.add_rule(action_name="read", allowed=True)
        
        evaluations = [
            {"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}},
            {"subject": {"type": "user", "id": "bob"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "2"}},
        ]
        
        results = pdp.evaluate_batch(evaluations)
        assert len(results) == 2
        assert all(r.decision for r in results)


class TestAlwaysAllowPDP:
    """Test AlwaysAllowPDP."""
    
    def test_always_allows(self):
        pdp = AlwaysAllowPDP()
        decision = pdp.evaluate(
            Subject(type="user", id="anyone"),
            Action(name="anything"),
            Resource(type="anything", id="anything"),
        )
        assert decision.decision is True


class TestAlwaysDenyPDP:
    """Test AlwaysDenyPDP."""
    
    def test_always_denies(self):
        pdp = AlwaysDenyPDP()
        decision = pdp.evaluate(
            Subject(type="user", id="anyone"),
            Action(name="anything"),
            Resource(type="anything", id="anything"),
        )
        assert decision.decision is False
        assert "reason" in decision.context


# ==================== Search Tests ====================

class TestSearch:
    """Test search functionality."""
    
    def test_search_subjects(self):
        pdp = SimplePDP()
        
        # Add subjects
        pdp.set_subjects([
            Subject(type="user", id="alice"),
            Subject(type="user", id="bob"),
            Subject(type="user", id="charlie"),
        ])
        
        # Add resources
        pdp.set_resources([
            Resource(type="doc", id="1"),
        ])
        
        # Allow all users to read doc 1
        pdp.add_rule(subject_type="user", action_name="read", resource_type="doc", resource_id="1", allowed=True)
        
        # Search for subjects who can read doc 1
        results = pdp.search_subjects(
            action=Action(name="read"),
            resource=Resource(type="doc", id="1"),
        )
        
        assert len(results) == 3
    
    def test_search_resources(self):
        pdp = SimplePDP()
        
        pdp.set_subjects([
            Subject(type="user", id="alice"),
        ])
        
        pdp.set_resources([
            Resource(type="doc", id="1"),
            Resource(type="doc", id="2"),
            Resource(type="doc", id="3"),
        ])
        
        # Allow alice to read docs 1 and 2
        pdp.add_rule(subject_type="user", subject_id="alice", action_name="read", resource_type="doc", resource_id="1", allowed=True)
        pdp.add_rule(subject_type="user", subject_id="alice", action_name="read", resource_type="doc", resource_id="2", allowed=True)
        
        results = pdp.search_resources(
            subject=Subject(type="user", id="alice"),
            action=Action(name="read"),
        )
        
        assert len(results) == 2
        ids = [r.id for r in results]
        assert "1" in ids
        assert "2" in ids
        assert "3" not in ids
    
    def test_search_actions(self):
        pdp = SimplePDP()
        
        pdp.set_subjects([
            Subject(type="user", id="alice"),
        ])
        
        pdp.set_resources([
            Resource(type="doc", id="1"),
        ])
        
        pdp.set_actions([
            Action(name="read"),
            Action(name="write"),
            Action(name="delete"),
        ])
        
        # Allow read only
        pdp.add_rule(subject_type="user", subject_id="alice", action_name="read", resource_type="doc", resource_id="1", allowed=True)
        
        results = pdp.search_actions(
            subject=Subject(type="user", id="alice"),
            resource=Resource(type="doc", id="1"),
        )
        
        assert len(results) == 1
        assert results[0].name == "read"


# ==================== Schema Tests ====================

class TestSchema:
    """Test schema validation."""
    
    def test_validate_valid_request(self):
        request = {
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "read"},
            "resource": {"type": "doc", "id": "1"},
        }
        is_valid, error = validate_request(request)
        assert is_valid is True
        assert error is None
    
    def test_validate_missing_subject(self):
        request = {
            "action": {"name": "read"},
            "resource": {"type": "doc", "id": "1"},
        }
        is_valid, error = validate_request(request)
        assert is_valid is False
        assert "subject" in error.lower()
    
    def test_validate_valid_response(self):
        response = {"decision": True}
        is_valid, error = validate_response(response)
        assert is_valid is True
    
    def test_validate_missing_decision(self):
        response = {}
        is_valid, error = validate_response(response)
        assert is_valid is False


# ==================== Integration Tests ====================

class TestIntegration:
    """Integration tests."""
    
    def test_full_authorization_flow(self):
        """Test a complete authorization flow."""
        # Setup PDP with rules
        pdp = SimplePDP()
        pdp.add_rule(
            subject_type="user",
            action_name="read",
            resource_type="document",
            allowed=True,
        )
        pdp.add_rule(
            subject_type="user",
            action_name="write",
            resource_type="document",
            allowed=False,
        )
        
        # Test read - should be allowed
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="read"),
            Resource(type="document", id="report"),
        )
        assert decision.allowed is True
        
        # Test write - should be denied
        decision = pdp.evaluate(
            Subject(type="user", id="alice"),
            Action(name="write"),
            Resource(type="document", id="report"),
        )
        assert decision.denied is True
    
    def test_batch_with_mixed_results(self):
        """Test batch evaluation with mixed allow/deny."""
        pdp = SimplePDP()
        pdp.add_rule(action_name="read", allowed=True)
        pdp.add_rule(action_name="write", allowed=False)
        
        evaluations = [
            {"subject": {"type": "user", "id": "alice"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "1"}},
            {"subject": {"type": "user", "id": "bob"}, "action": {"name": "write"}, "resource": {"type": "doc", "id": "1"}},
            {"subject": {"type": "user", "id": "charlie"}, "action": {"name": "read"}, "resource": {"type": "doc", "id": "2"}},
        ]
        
        results = pdp.evaluate_batch(evaluations)
        
        assert results[0].allowed is True   # alice read
        assert results[1].denied is True     # bob write
        assert results[2].allowed is True     # charlie read
    
    def test_search_with_limit(self):
        """Test search respects limit."""
        pdp = SimplePDP()
        
        pdp.set_subjects([
            Subject(type="user", id=f"user{i}") for i in range(10)
        ])
        pdp.set_resources([Resource(type="doc", id="1")])
        
        pdp.add_rule(subject_type="user", action_name="read", resource_type="doc", allowed=True)
        
        results = pdp.search_subjects(
            action=Action(name="read"),
            resource=Resource(type="doc", id="1"),
            limit=3,
        )
        
        assert len(results) == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
