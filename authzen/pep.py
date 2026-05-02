"""AuthZEN PEP (Policy Enforcement Point) client implementation.

The PEP client communicates with a PDP (Policy Decision Point) to evaluate authorization requests.
"""

from typing import Any

import httpx

from authzen.models import Action, Context, Decision, Resource, Subject
from authzen.schema import validate_request, validate_response


class PEPClient:
    """Client for communicating with an AuthZEN-compatible PDP.
    
    Attributes:
        pdp_url: The base URL of the PDP
        timeout: Request timeout in seconds
        headers: Additional headers to include in requests
    """
    
    def __init__(
        self,
        pdp_url: str,
        timeout: float = 30.0,
        headers: dict[str, str] | None = None,
    ):
        """Initialize the PEP client.
        
        Args:
            pdp_url: The base URL of the PDP (e.g., "https://pdp.example.com")
            timeout: Request timeout in seconds
            headers: Additional headers to include in requests
        """
        self.pdp_url = pdp_url.rstrip("/")
        self.timeout = timeout
        self.headers = headers or {}
        self.client = httpx.Client(timeout=timeout)
    
    def close(self):
        """Close the HTTP client."""
        self.client.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
    
    def _build_request(
        self,
        subject: Subject | dict[str, Any],
        action: Action | dict[str, Any],
        resource: Resource | dict[str, Any],
        context: Context | dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build the request payload."""
        # Convert to dicts if needed
        if isinstance(subject, Subject):
            subject = subject.to_dict()
        if isinstance(action, Action):
            action = action.to_dict()
        if isinstance(resource, Resource):
            resource = resource.to_dict()
        if isinstance(context, Context):
            context = context.to_dict()
        
        request = {
            "subject": subject,
            "action": action,
            "resource": resource,
        }
        
        if context:
            request["context"] = context
        
        return request
    
    def check_access(
        self,
        subject: Subject | dict[str, Any],
        action: Action | dict[str, Any],
        resource: Resource | dict[str, Any],
        context: Context | dict[str, Any] | None = None,
    ) -> Decision:
        """Check if a subject can perform an action on a resource.
        
        This is a single access evaluation request to the PDP.
        
        Args:
            subject: The subject requesting access
            action: The action being requested
            resource: The resource being accessed
            context: Optional context information
            
        Returns:
            A Decision object with the authorization result
            
        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response is invalid
        """
        request = self._build_request(subject, action, resource, context)
        
        # Validate request
        is_valid, error = validate_request(request)
        if not is_valid:
            raise ValueError(f"Invalid request: {error}")
        
        # Make request to PDP
        url = f"{self.pdp_url}/access/v1/evaluations"
        response = self.client.post(url, json=request, headers=self.headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Validate response
        is_valid, error = validate_response(data)
        if not is_valid:
            raise ValueError(f"Invalid response: {error}")
        
        return Decision.from_dict(data)
    
    def check_access_batch(
        self,
        evaluations: list[dict[str, Any]],
    ) -> list[Decision]:
        """Check access for multiple evaluations in a single request.
        
        This is a batch evaluation request to the PDP (also known as "boxcarring").
        
        Args:
            evaluations: List of evaluation requests. Each request should contain
                subject, action, resource, and optionally context.
                
        Returns:
            List of Decision objects
            
        Raises:
            httpx.HTTPError: If the request fails
            ValueError: If the response is invalid
        """
        # Build batch request with default values from first evaluation
        if not evaluations:
            raise ValueError("At least one evaluation is required")
        
        first = evaluations[0]
        request = {}
        
        # Add defaults from first evaluation if present
        if "subject" in first:
            request["subject"] = first["subject"]
        if "action" in first:
            request["action"] = first["action"]
        if "resource" in first:
            request["resource"] = first["resource"]
        if "context" in first:
            request["context"] = first["context"]
        
        request["evaluations"] = evaluations
        
        # Make request to PDP
        url = f"{self.pdp_url}/access/v1/evaluations"
        response = self.client.post(url, json=request, headers=self.headers)
        response.raise_for_status()
        
        data = response.json()
        
        # Extract results
        results = data.get("results", [])
        return [Decision.from_dict(r) for r in results]
    
    def is_allowed(
        self,
        subject: Subject | dict[str, Any],
        action: Action | dict[str, Any],
        resource: Resource | dict[str, Any],
        context: Context | dict[str, Any] | None = None,
    ) -> bool:
        """Quick check to determine if access is allowed.
        
        A convenience method that returns True if the decision is to allow,
        False otherwise.
        
        Args:
            subject: The subject requesting access
            action: The action being requested
            resource: The resource being accessed
            context: Optional context information
            
        Returns:
            True if access is allowed, False otherwise
        """
        decision = self.check_access(subject, action, resource, context)
        return decision.allowed
    
    def is_denied(
        self,
        subject: Subject | dict[str, Any],
        action: Action | dict[str, Any],
        resource: Resource | dict[str, Any],
        context: Context | dict[str, Any] | None = None,
    ) -> bool:
        """Quick check to determine if access is denied.
        
        A convenience method that returns True if the decision is to deny,
        False otherwise.
        
        Args:
            subject: The subject requesting access
            action: The action being requested
            resource: The resource being accessed
            context: Optional context information
            
        Returns:
            True if access is denied, False otherwise
        """
        decision = self.check_access(subject, action, resource, context)
        return decision.denied
