"""AuthZEN domain models for the Authorization API."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Subject:
    """A Subject is the user or machine principal about whom the Authorization API is being invoked.
    
    Attributes:
        type: The type of the Subject (e.g., "user", "service", "device")
        id: The unique identifier of the Subject, scoped to the type
        properties: Additional attributes for the Subject
    """
    type: str
    id: str
    properties: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {"type": self.type, "id": self.id}
        if self.properties:
            result["properties"] = self.properties
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Subject":
        """Create Subject from dictionary."""
        return cls(
            type=data["type"],
            id=data["id"],
            properties=data.get("properties", {})
        )


@dataclass
class Resource:
    """A Resource is the target of an access request.
    
    Attributes:
        type: The type of the Resource (e.g., "document", "account", "file")
        id: The unique identifier of the Resource, scoped to the type
        properties: Additional attributes for the Resource
    """
    type: str
    id: str
    properties: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {"type": self.type, "id": self.id}
        if self.properties:
            result["properties"] = self.properties
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Resource":
        """Create Resource from dictionary."""
        return cls(
            type=data["type"],
            id=data["id"],
            properties=data.get("properties", {})
        )


@dataclass
class Action:
    """An Action is the type of access that the requester intends to perform.
    
    Attributes:
        name: The name of the Action (e.g., "can_read", "can_write", "delete")
        properties: Additional attributes for the Action
    """
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {"name": self.name}
        if self.properties:
            result["properties"] = self.properties
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Action":
        """Create Action from dictionary."""
        return cls(
            name=data["name"],
            properties=data.get("properties", {})
        )


@dataclass
class Context:
    """The Context represents the environment of the access evaluation request.
    
    Attributes:
        properties: Additional context attributes (e.g., time, location)
    """
    properties: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        return self.properties if self.properties else {}
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Context":
        """Create Context from dictionary."""
        return cls(properties=data or {})


@dataclass
class Decision:
    """A Decision is the result of the evaluation of an access request.
    
    Attributes:
        decision: Whether the access request is permitted (True) or denied (False)
        context: Additional information for the PEP about the decision
    """
    decision: bool
    context: dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary representation."""
        result = {"decision": self.decision}
        if self.context:
            result["context"] = self.context
        return result
    
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Decision":
        """Create Decision from dictionary."""
        return cls(
            decision=data["decision"],
            context=data.get("context", {})
        )
    
    @property
    def allowed(self) -> bool:
        """Returns True if the decision is to allow the operation."""
        return self.decision
    
    @property
    def denied(self) -> bool:
        """Returns True if the decision is to deny the operation."""
        return not self.decision
