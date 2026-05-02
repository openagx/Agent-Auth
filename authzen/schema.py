"""JSON Schema definitions for AuthZEN request/response validation."""

import json
from typing import Any

# AuthZEN Evaluation Request Schema
EVALUATION_REQUEST_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AuthZEN Evaluation Request",
    "type": "object",
    "required": ["subject", "action", "resource"],
    "properties": {
        "subject": {
            "type": "object",
            "required": ["type", "id"],
            "properties": {
                "type": {"type": "string"},
                "id": {"type": "string"},
                "properties": {"type": "object"}
            }
        },
        "resource": {
            "type": "object",
            "required": ["type", "id"],
            "properties": {
                "type": {"type": "string"},
                "id": {"type": "string"},
                "properties": {"type": "object"}
            }
        },
        "action": {
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "properties": {"type": "object"}
            }
        },
        "context": {
            "type": "object",
            "properties": {}
        },
        "evaluations": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["subject", "action", "resource"],
                "properties": {
                    "subject": {
                        "type": "object",
                        "required": ["type", "id"],
                        "properties": {
                            "type": {"type": "string"},
                            "id": {"type": "string"},
                            "properties": {"type": "object"}
                        }
                    },
                    "resource": {
                        "type": "object",
                        "required": ["type", "id"],
                        "properties": {
                            "type": {"type": "string"},
                            "id": {"type": "string"},
                            "properties": {"type": "object"}
                        }
                    },
                    "action": {
                        "type": "object",
                        "required": ["name"],
                        "properties": {
                            "name": {"type": "string"},
                            "properties": {"type": "object"}
                        }
                    },
                    "context": {
                        "type": "object",
                        "properties": {}
                    }
                }
            }
        }
    }
}

# AuthZEN Evaluation Response Schema
EVALUATION_RESPONSE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AuthZEN Evaluation Response",
    "type": "object",
    "required": ["decision"],
    "properties": {
        "decision": {"type": "boolean"},
        "context": {
            "type": "object",
            "properties": {}
        }
    }
}

# AuthZEN Batch Evaluation Response Schema
BATCH_EVALUATION_RESPONSE_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "AuthZEN Batch Evaluation Response",
    "type": "object",
    "required": ["results"],
    "properties": {
        "results": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["decision"],
                "properties": {
                    "decision": {"type": "boolean"},
                    "context": {
                        "type": "object",
                        "properties": {}
                    }
                }
            }
        }
    }
}


def validate_request(data: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate an AuthZEN evaluation request against the schema.
    
    Args:
        data: The request data to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=EVALUATION_REQUEST_SCHEMA)
        return True, None
    except ImportError:
        # If jsonschema is not installed, perform basic validation
        required = ["subject", "action", "resource"]
        for field in required:
            if field not in data:
                return False, f"Missing required field: {field}"
        return True, None
    except jsonschema.ValidationError as e:
        return False, str(e)


def validate_response(data: dict[str, Any]) -> tuple[bool, str | None]:
    """Validate an AuthZEN evaluation response against the schema.
    
    Args:
        data: The response data to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        import jsonschema
        jsonschema.validate(instance=data, schema=EVALUATION_RESPONSE_SCHEMA)
        return True, None
    except ImportError:
        # Basic validation without jsonschema
        if "decision" not in data:
            return False, "Missing required field: decision"
        if not isinstance(data["decision"], bool):
            return False, "Field 'decision' must be a boolean"
        return True, None
    except jsonschema.ValidationError as e:
        return False, str(e)


def get_request_schema() -> dict:
    """Get the evaluation request schema as JSON."""
    return json.dumps(EVALUATION_REQUEST_SCHEMA, indent=2)


def get_response_schema() -> dict:
    """Get the evaluation response schema as JSON."""
    return json.dumps(EVALUATION_RESPONSE_SCHEMA, indent=2)
