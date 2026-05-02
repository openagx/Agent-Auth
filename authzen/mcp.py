"""AuthZEN MCP Server.

This module provides an MCP (Model Context Protocol) server implementation
that exposes the AuthZEN PDP functionality to AI assistants.
"""

from typing import Any

from authzen.models import Action, Context, Decision, Resource, Subject
from authzen.pdp import AlwaysAllowPDP, PDPInterface, SimplePDP


class MCPAuthZENServer:
    """MCP Server for AuthZEN PDP access.
    
    This server exposes the PDP functionality via MCP, allowing AI assistants
    to query authorization decisions.
    """
    
    def __init__(self, pdp: PDPInterface | None = None):
        """Initialize the MCP server.
        
        Args:
            pdp: The PDP implementation to use. If None, uses AlwaysAllowPDP.
        """
        self.pdp = pdp if pdp else AlwaysAllowPDP()
    
    def get_tools(self) -> list[dict[str, Any]]:
        """Get the list of tools exposed by this MCP server."""
        return [
            {
                "name": "authzen_check_access",
                "description": "Check if a subject can perform an action on a resource. "
                             "Returns True if allowed, False if denied.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject_type": {
                            "type": "string",
                            "description": "The type of the subject (e.g., 'user', 'service')",
                        },
                        "subject_id": {
                            "type": "string",
                            "description": "The unique identifier of the subject",
                        },
                        "subject_properties": {
                            "type": "object",
                            "description": "Additional properties for the subject",
                        },
                        "action_name": {
                            "type": "string",
                            "description": "The name of the action (e.g., 'can_read', 'can_write')",
                        },
                        "action_properties": {
                            "type": "object",
                            "description": "Additional properties for the action",
                        },
                        "resource_type": {
                            "type": "string",
                            "description": "The type of the resource (e.g., 'document', 'file')",
                        },
                        "resource_id": {
                            "type": "string",
                            "description": "The unique identifier of the resource",
                        },
                        "resource_properties": {
                            "type": "object",
                            "description": "Additional properties for the resource",
                        },
                        "context_properties": {
                            "type": "object",
                            "description": "Context properties (e.g., time, location)",
                        },
                    },
                    "required": ["subject_type", "subject_id", "action_name", "resource_type", "resource_id"],
                },
            },
            {
                "name": "authzen_check_access_batch",
                "description": "Check access for multiple requests in a single call.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "evaluations": {
                            "type": "array",
                            "description": "Array of evaluation requests",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "subject_type": {"type": "string"},
                                    "subject_id": {"type": "string"},
                                    "action_name": {"type": "string"},
                                    "resource_type": {"type": "string"},
                                    "resource_id": {"type": "string"},
                                },
                                "required": ["subject_type", "subject_id", "action_name", "resource_type", "resource_id"],
                            },
                        },
                    },
                    "required": ["evaluations"],
                },
            },
            {
                "name": "authzen_get_decision",
                "description": "Get a detailed decision with context.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "subject_type": {
                            "type": "string",
                            "description": "The type of the subject",
                        },
                        "subject_id": {
                            "type": "string",
                            "description": "The unique identifier of the subject",
                        },
                        "action_name": {
                            "type": "string",
                            "description": "The name of the action",
                        },
                        "resource_type": {
                            "type": "string",
                            "description": "The type of the resource",
                        },
                        "resource_id": {
                            "type": "string",
                            "description": "The unique identifier of the resource",
                        },
                    },
                    "required": ["subject_type", "subject_id", "action_name", "resource_type", "resource_id"],
                },
            },
        ]
    
    def get_resources(self) -> list[dict[str, Any]]:
        """Get the list of resources exposed by this MCP server."""
        return [
            {
                "uri": "authzen://pdp/info",
                "name": "PDP Information",
                "description": "Information about this PDP",
                "mimeType": "application/json",
            },
        ]
    
    def get_pdp_info(self) -> dict[str, Any]:
        """Get PDP information."""
        return {
            "name": "AuthZEN MCP PDP",
            "version": "1.0",
            "pdp_type": type(self.pdp).__name__,
        }
    
    async def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        """Call an MCP tool.
        
        Args:
            tool_name: The name of the tool to call
            arguments: The arguments to pass to the tool
            
        Returns:
            The result of the tool call
        """
        if tool_name == "authzen_check_access":
            return await self._check_access(arguments)
        elif tool_name == "authzen_check_access_batch":
            return await self._check_access_batch(arguments)
        elif tool_name == "authzen_get_decision":
            return await self._get_decision(arguments)
        else:
            raise ValueError(f"Unknown tool: {tool_name}")
    
    async def _check_access(self, args: dict[str, Any]) -> dict[str, Any]:
        """Check access for a single request."""
        subject = Subject(
            type=args["subject_type"],
            id=args["subject_id"],
            properties=args.get("subject_properties", {}),
        )
        action = Action(
            name=args["action_name"],
            properties=args.get("action_properties", {}),
        )
        resource = Resource(
            type=args["resource_type"],
            id=args["resource_id"],
            properties=args.get("resource_properties", {}),
        )
        context = None
        if args.get("context_properties"):
            context = Context(properties=args["context_properties"])
        
        decision = self.pdp.evaluate(subject, action, resource, context)
        
        return {
            "allowed": decision.allowed,
            "decision": decision.decision,
            "context": decision.context,
        }
    
    async def _check_access_batch(self, args: dict[str, Any]) -> dict[str, Any]:
        """Check access for multiple requests."""
        evaluations = []
        for eval_data in args.get("evaluations", []):
            evaluations.append({
                "subject": {
                    "type": eval_data["subject_type"],
                    "id": eval_data["subject_id"],
                    "properties": eval_data.get("subject_properties", {}),
                },
                "action": {
                    "name": eval_data["action_name"],
                    "properties": eval_data.get("action_properties", {}),
                },
                "resource": {
                    "type": eval_data["resource_type"],
                    "id": eval_data["resource_id"],
                    "properties": eval_data.get("resource_properties", {}),
                },
                "context": eval_data.get("context_properties", {}),
            })
        
        decisions = self.pdp.evaluate_batch(evaluations)
        
        return {
            "results": [
                {
                    "allowed": d.allowed,
                    "decision": d.decision,
                    "context": d.context,
                }
                for d in decisions
            ],
        }
    
    async def _get_decision(self, args: dict[str, Any]) -> dict[str, Any]:
        """Get a detailed decision."""
        subject = Subject(
            type=args["subject_type"],
            id=args["subject_id"],
        )
        action = Action(name=args["action_name"])
        resource = Resource(
            type=args["resource_type"],
            id=args["resource_id"],
        )
        
        decision = self.pdp.evaluate(subject, action, resource)
        
        return {
            "decision": decision.decision,
            "allowed": decision.allowed,
            "denied": decision.denied,
            "context": decision.context,
        }
    
    async def read_resource(self, uri: str) -> dict[str, Any]:
        """Read a resource."""
        if uri == "authzen://pdp/info":
            return {
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": str(self.get_pdp_info()),
                }]
            }
        raise ValueError(f"Unknown resource: {uri}")


def create_mcp_server(pdp: PDPInterface | None = None) -> MCPAuthZENServer:
    """Create an MCP server.
    
    Args:
        pdp: The PDP implementation to use
        
    Returns:
        An MCP server instance
    """
    return MCPAuthZENServer(pdp)
