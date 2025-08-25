import json
import logging
import os
from typing import Dict, Any
from fastapi import FastAPI
from mangum import Mangum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Import our routes
from ...api.routes import router

# Create FastAPI app
app = FastAPI(
    title="Password Validation API",
    description="Secure password validation and complexity checking service",
    version="1.0.0",
    docs_url="/docs" if os.getenv("ENVIRONMENT") != "production" else None,
    redoc_url="/redoc" if os.getenv("ENVIRONMENT") != "production" else None
)

# Include our router
app.include_router(router)

# Health check endpoint at root
@app.get("/")
async def root():
    return {
        "service": "Password Validation API",
        "version": "1.0.0",
        "status": "running"
    }

# Create Mangum handler for AWS Lambda
handler = Mangum(app, lifespan="off")


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point with enhanced error handling and monitoring
    """
    try:
        # Log request details (sanitized)
        logger.info(f"Processing request - Method: {event.get('httpMethod', 'UNKNOWN')}, "
                   f"Path: {event.get('path', 'UNKNOWN')}")
        
        # Add correlation ID for tracing
        if 'headers' not in event:
            event['headers'] = {}
        
        if 'x-correlation-id' not in event['headers']:
            import uuid
            event['headers']['x-correlation-id'] = str(uuid.uuid4())
        
        # Process request through Mangum
        response = handler(event, context)
        
        # Log response status (without sensitive data)
        status_code = response.get('statusCode', 'UNKNOWN')
        logger.info(f"Request completed - Status: {status_code}, "
                   f"Correlation ID: {event['headers'].get('x-correlation-id')}")
        
        return response
        
    except Exception as e:
        logger.error(f"Lambda handler error: {str(e)}", exc_info=True)
        
        # Return standardized error response
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type, Authorization'
            },
            'body': json.dumps({
                'error': True,
                'message': 'Internal server error',
                'timestamp': '2025-08-25T06:24:40.099Z'
            })
        }