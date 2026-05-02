# AuthZEN - Open Agent Authorization SDK

[![PyPI Version](https://img.shields.io/pypi/v/authzen.svg)](https://pypi.org/project/authzen/)
[![Python Versions](https://img.shields.io/pypi/pyversions/authzen.svg)](https://pypi.org/project/authzen/)
[![License](https://img.shields.io/pypi/l/authzen.svg)](LICENSE)

AuthZEN is a Python SDK for implementing the [AuthZEN Authorization API](https://openid.net/wg/authzen/) specification from the OpenID Foundation. It provides a standardized way for Policy Enforcement Points (PEPs) to communicate with Policy Decision Points (PDPs).

## What is AuthZEN?

AuthZEN defines a standard interface between Policy Enforcement Points and Policy Decision Points, enabling interoperability across different vendors and platforms. It aims to become "the OpenID Connect of Authorization."

## Installation

```bash
pip install authzen
```

## Quick Start

### Using the PEP Client

```python
from authzen import PEPClient, Subject, Action, Resource

# Create a PEP client pointing to your PDP
client = PEPClient("https://pdp.example.com")

# Check access for a single request
decision = client.check_access(
    Subject(type="user", id="alice@example.com"),
    Action(name="can_read"),
    Resource(type="document", id="123"),
)

if decision.allowed:
    print("Access granted!")
else:
    print(f"Access denied: {decision.context}")
```

### Using a Built-in PDP

```python
from authzen import SimplePDP, Subject, Action, Resource

# Create a simple PDP with rules
pdp = SimplePDP()

# Add allow rules
pdp.add_rule(
    subject_type="user",
    action_name="can_read",
    resource_type="document",
    allowed=True,
)

# Evaluate an access request
decision = pdp.evaluate(
    Subject(type="user", id="alice@example.com"),
    Action(name="can_read"),
    Resource(type="document", id="123"),
)

print(f"Decision: {'allowed' if decision.allowed else 'denied'}")
```

### Batch Evaluations

```python
from authzen import PEPClient, Subject, Action, Resource

client = PEPClient("https://pdp.example.com")

# Check access for multiple requests in one call
evaluations = [
    {"subject": {"type": "user", "id": "alice@example.com"},
     "action": {"name": "can_read"},
     "resource": {"type": "document", "id": "1"}},
    {"subject": {"type": "user", "id": "alice@example.com"},
     "action": {"name": "can_read"},
     "resource": {"type": "document", "id": "2"}},
    {"subject": {"type": "user", "id": "bob@example.com"},
     "action": {"name": "can_write"},
     "resource": {"type": "document", "id": "1"}},
]

results = client.check_access_batch(evaluations)
for i, decision in enumerate(results):
    print(f"Evaluation {i}: {'allowed' if decision.allowed else 'denied'}")
```

## Core Concepts

### Models

- **Subject**: The user or machine principal requesting access
- **Resource**: The target of an access request
- **Action**: The type of access being requested
- **Context**: The environment of the access request
- **Decision**: The result of the authorization evaluation

### PDP Implementations

- **SimplePDP**: A basic PDP with configurable allow/deny rules
- **AlwaysAllowPDP**: Always returns allow (useful for testing)
- **AlwaysDenyPDP**: Always returns deny (useful for testing)

## API Reference

### PEPClient

```python
PEPClient(pdp_url: str, timeout: float = 30.0, headers: dict = None)
```

| Method | Description |
|--------|-------------|
| `check_access(subject, action, resource, context)` | Evaluate a single access request |
| `check_access_batch(evaluations)` | Evaluate multiple requests in one call |
| `is_allowed(subject, action, resource, context)` | Quick check returning bool |
| `is_denied(subject, action, resource, context)` | Quick check returning bool |

### Models

All models support `to_dict()` and `from_dict()` for serialization:

```python
 Subject(type="user", id="alice@example.com", properties={"department": "Sales"})
 Resource(type="document", id="123", properties={"title": "Report"})
 Action(name="can_read", properties={"method": "GET"})
 Context(properties={"time": "2024-01-01T12:00:00Z"})
 Decision(decision=True, context={"reason": "Allowed by policy"})
```

## Resources

- [AuthZEN Specification](https://openid.net/wg/authzen/)
- [AuthZEN GitHub Repository](https://github.com/openid/authzen)
- [OpenID Foundation](https://openid.net/)

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.
