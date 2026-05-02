"""AuthZEN - Open Agent Authorization based on AuthZen.

A Python SDK for implementing the AuthZEN Authorization API specification.

Models:
    - Subject: The user or machine principal requesting access
    - Resource: The target of an access request
    - Action: The type of access being requested
    - Context: The environment of the access request
    - Decision: The result of the authorization evaluation

Clients:
    - PEPClient: Client for communicating with a PDP (Policy Decision Point)

PDP Implementations:
    - PDPInterface: Abstract base class for PDP implementations
    - SimplePDP: A simple PDP with configurable rules
    - AlwaysAllowPDP: A PDP that always allows access
    - AlwaysDenyPDP: A PDP that always denies access

API Server:
    - create_app: Create a FastAPI PDP server
    - run_server: Run the PDP server

MCP Server:
    - MCPAuthZENServer: MCP server for AI assistants
    - create_mcp_server: Create an MCP server

Example usage:
    >>> from authzen import PEPClient, Subject, Action, Resource
    >>>
    >>> # As a PEP client
    >>> client = PEPClient("https://pdp.example.com")
    >>> decision = client.check_access(
    ...     Subject(type="user", id="alice@example.com"),
    ...     Action(name="can_read"),
    ...     Resource(type="document", id="123"),
    ... )
    >>> if decision.allowed:
    ...     print("Access granted!")
"""

from authzen.models import Action, Context, Decision, Resource, Subject
from authzen.pdp import AlwaysAllowPDP, AlwaysDenyPDP, PDPInterface, SimplePDP
from authzen.schema import (
    EVALUATION_REQUEST_SCHEMA,
    EVALUATION_RESPONSE_SCHEMA,
    validate_request,
    validate_response,
)
from authzen.pep import PEPClient

__version__ = "0.1.0"

__all__ = [
    # Models
    "Subject",
    "Resource",
    "Action",
    "Context",
    "Decision",
    # PDP
    "PDPInterface",
    "SimplePDP",
    "AlwaysAllowPDP",
    "AlwaysDenyPDP",
    # PEP Client
    "PEPClient",
    # Schema
    "EVALUATION_REQUEST_SCHEMA",
    "EVALUATION_RESPONSE_SCHEMA",
    "validate_request",
    "validate_response",
]
