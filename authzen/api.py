"""AuthZEN PDP API server using FastAPI.

This module provides a FastAPI-based implementation of an AuthZEN-compatible
Policy Decision Point (PDP) server.
"""

from typing import Any

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, Field

from authzen.models import Action, Context, Decision, Resource, Subject
from authzen.pdp import AlwaysAllowPDP, AlwaysDenyPDP, PDPInterface, SimplePDP


# Request/Response Models
class SubjectModel(BaseModel):
    """Subject model for API requests."""
    type: str = Field(..., description="The type of the Subject")
    id: str = Field(..., description="The unique identifier of the Subject")
    properties: dict[str, Any] = Field(default_factory=dict, description="Additional subject properties")


class ResourceModel(BaseModel):
    """Resource model for API requests."""
    type: str = Field(..., description="The type of the Resource")
    id: str = Field(..., description="The unique identifier of the Resource")
    properties: dict[str, Any] = Field(default_factory=dict, description="Additional resource properties")


class ActionModel(BaseModel):
    """Action model for API requests."""
    name: str = Field(..., description="The name of the Action")
    properties: dict[str, Any] = Field(default_factory=dict, description="Additional action properties")


class ContextModel(BaseModel):
    """Context model for API requests."""
    properties: dict[str, Any] = Field(default_factory=dict, description="Context properties")


class EvaluationRequest(BaseModel):
    """Single evaluation request."""
    subject: SubjectModel
    action: ActionModel
    resource: ResourceModel
    context: ContextModel | None = Field(default=None, description="Optional context")


class BatchEvaluationRequest(BaseModel):
    """Batch evaluation request with defaults."""
    subject: SubjectModel | None = Field(default=None, description="Default subject")
    action: ActionModel | None = Field(default=None, description="Default action")
    resource: ResourceModel | None = Field(default=None, description="Default resource")
    context: ContextModel | None = Field(default=None, description="Default context")
    evaluations: list[EvaluationRequest] = Field(default_factory=list, description="Individual evaluations")


class DecisionResponse(BaseModel):
    """Decision response."""
    decision: bool = Field(..., description="The authorization decision")
    context: dict[str, Any] = Field(default_factory=dict, description="Optional context information")


class BatchDecisionResponse(BaseModel):
    """Batch decision response."""
    results: list[DecisionResponse] = Field(default_factory=list, description="Array of decisions")


def create_app(pdp: PDPInterface | None = None) -> FastAPI:
    """Create a FastAPI application with AuthZEN endpoints.
    
    Args:
        pdp: The PDP implementation to use. If None, uses AlwaysAllowPDP.
        
    Returns:
        A FastAPI application configured with AuthZEN endpoints.
    """
    if pdp is None:
        pdp = AlwaysAllowPDP()
    
    app = FastAPI(
        title="AuthZEN PDP",
        description="Policy Decision Point implementing the AuthZEN Authorization API",
        version="1.0",
    )
    
    @app.get("/")
    def root():
        """Root endpoint."""
        return {"name": "AuthZEN PDP", "version": "1.0"}
    
    @app.get("/health")
    def health():
        """Health check endpoint."""
        return {"status": "healthy"}
    
    @app.post("/access/v1/evaluations", response_model=DecisionResponse)
    def evaluate_access(request: EvaluationRequest) -> DecisionResponse:
        """Evaluate a single access request.
        
        This endpoint implements the AuthZEN Access Evaluation API.
        """
        try:
            subject = Subject(
                type=request.subject.type,
                id=request.subject.id,
                properties=request.subject.properties,
            )
            action = Action(
                name=request.action.name,
                properties=request.action.properties,
            )
            resource = Resource(
                type=request.resource.type,
                id=request.resource.id,
                properties=request.resource.properties,
            )
            context = None
            if request.context:
                context = Context(properties=request.context.properties)
            
            decision = pdp.evaluate(subject, action, resource, context)
            
            return DecisionResponse(
                decision=decision.decision,
                context=decision.context,
            )
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    @app.post("/access/v1/evaluations/batch", response_model=BatchDecisionResponse)
    def evaluate_access_batch(request: BatchEvaluationRequest) -> BatchDecisionResponse:
        """Evaluate multiple access requests in a single call.
        
        This endpoint implements the AuthZEN Access Evaluations API (boxcarring).
        """
        try:
            evaluations = []
            
            # Convert individual evaluations
            for req in request.evaluations:
                evaluations.append({
                    "subject": {
                        "type": req.subject.type,
                        "id": req.subject.id,
                        "properties": req.subject.properties,
                    },
                    "action": {
                        "name": req.action.name,
                        "properties": req.action.properties,
                    },
                    "resource": {
                        "type": req.resource.type,
                        "id": req.resource.id,
                        "properties": req.resource.properties,
                    },
                    "context": req.context.properties if req.context else {},
                })
            
            # Apply defaults from request to any missing fields
            default_subject = request.subject.model_dump() if request.subject else None
            default_action = request.action.model_dump() if request.action else None
            default_resource = request.resource.model_dump() if request.resource else None
            default_context = request.context.properties if request.context else None
            
            # Merge defaults with evaluations
            for eval_req in evaluations:
                if default_subject and "subject" not in eval_req:
                    eval_req["subject"] = default_subject
                if default_action and "action" not in eval_req:
                    eval_req["action"] = default_action
                if default_resource and "resource" not in eval_req:
                    eval_req["resource"] = default_resource
                if default_context and "context" not in eval_req:
                    eval_req["context"] = default_context
            
            decisions = pdp.evaluate_batch(evaluations)
            
            results = [
                DecisionResponse(
                    decision=d.decision,
                    context=d.context,
                )
                for d in decisions
            ]
            
            return BatchDecisionResponse(results=results)
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    return app


def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    pdp: PDPInterface | None = None,
) -> None:
    """Run the AuthZEN PDP server.
    
    Args:
        host: The host to bind to
        port: The port to bind to
        pdp: The PDP implementation to use
    """
    import uvicorn
    app = create_app(pdp)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_server()


# Search API Models
class SubjectSearchRequest(BaseModel):
    """Subject search request."""
    action: ActionModel
    resource: ResourceModel
    context: ContextModel | None = Field(default=None)


class ResourceSearchRequest(BaseModel):
    """Resource search request."""
    subject: SubjectModel
    action: ActionModel
    context: ContextModel | None = Field(default=None)


class ActionSearchRequest(BaseModel):
    """Action search request."""
    subject: SubjectModel
    resource: ResourceModel
    context: ContextModel | None = Field(default=None)


class SearchResponse(BaseModel):
    """Search results response."""
    results: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0


# Search API endpoints
@app.post("/search/v1/subjects", response_model=SearchResponse)
def search_subjects(request: SubjectSearchRequest) -> SearchResponse:
    """Search for subjects that can perform an action on a resource.
    
    This endpoint implements the AuthZEN Subject Search API.
    """
    try:
        # This is a placeholder - implement actual search logic in PDP
        return SearchResponse(results=[], total=0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/search/v1/resources", response_model=SearchResponse)
def search_resources(request: ResourceSearchRequest) -> SearchResponse:
    """Search for resources that a subject can perform an action on.
    
    This endpoint implements the AuthZEN Resource Search API.
    """
    try:
        # This is a placeholder - implement actual search logic in PDP
        return SearchResponse(results=[], total=0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/search/v1/actions", response_model=SearchResponse)
def search_actions(request: ActionSearchRequest) -> SearchResponse:
    """Search for actions that a subject can perform on a resource.
    
    This endpoint implements the AuthZEN Action Search API.
    """
    try:
        # This is a placeholder - implement actual search logic in PDP
        return SearchResponse(results=[], total=0)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# PDP Metadata
class PDPVersionMetadata(BaseModel):
    """PDP version metadata."""
    version: str = "1.0"
    spec_version: str = "1.0"
    name: str = "AuthZEN PDP"
    vendor: str = "openagx"


@app.get("/pdp/v1/metadata", response_model=PDPVersionMetadata)
def get_pdp_metadata() -> PDPVersionMetadata:
    """Get PDP metadata.
    
    This endpoint implements the AuthZEN PDP Metadata API.
    """
    return PDPVersionMetadata()
