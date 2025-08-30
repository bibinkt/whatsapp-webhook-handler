# main.py
import os
import hmac
import hashlib
import logging
from typing import Optional, Dict, Any
from datetime import datetime
import asyncio
import aiohttp
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, HTTPException, BackgroundTasks, Header
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
class Config:
    VERIFY_TOKEN = os.getenv("VERIFY_TOKEN", "apexelement_recipe_2024")
    APP_SECRET = os.getenv("APP_SECRET", "")  # Meta App Secret for signature verification
    N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL", "https://bibinkt.app.n8n.cloud/webhook/c28c1061-bb85-4111-9e06-7166f5bf13f2")
    N8N_API_KEY = os.getenv("N8N_API_KEY", "")  # Optional: if your n8n webhook requires auth
    MAX_RETRIES = int(os.getenv("MAX_RETRIES", "3"))
    RETRY_DELAY = int(os.getenv("RETRY_DELAY", "5"))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "10"))
    ENABLE_SIGNATURE_VERIFICATION = os.getenv("ENABLE_SIGNATURE_VERIFICATION", "true").lower() == "true"

config = Config()

# Global aiohttp session
aiohttp_session: Optional[aiohttp.ClientSession] = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    global aiohttp_session
    aiohttp_session = aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=config.REQUEST_TIMEOUT)
    )
    logger.info("Application started, aiohttp session created")
    yield
    # Shutdown
    await aiohttp_session.close()
    logger.info("Application shutdown, aiohttp session closed")

# Initialize FastAPI app
app = FastAPI(
    title="WhatsApp Webhook Handler",
    description="FastAPI service to handle Meta WhatsApp webhooks and forward to n8n",
    version="1.0.0",
    lifespan=lifespan
)

# Pydantic models for request/response
class WebhookVerification(BaseModel):
    hub_mode: str = Field(alias="hub.mode")
    hub_verify_token: str = Field(alias="hub.verify_token")
    hub_challenge: str = Field(alias="hub.challenge")

class WebhookPayload(BaseModel):
    object: str
    entry: list

class ForwardResponse(BaseModel):
    success: bool
    message: str
    timestamp: str
    n8n_response: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

# Utility functions
def verify_webhook_signature(payload: bytes, signature: str) -> bool:
    """Verify the webhook signature from Meta"""
    if not config.APP_SECRET or not config.ENABLE_SIGNATURE_VERIFICATION:
        return True
    
    if not signature or not signature.startswith('sha256='):
        logger.warning("Invalid signature format")
        return False
    
    expected_signature = hmac.new(
        config.APP_SECRET.encode('utf-8'),
        payload,
        hashlib.sha256
    ).hexdigest()
    
    provided_signature = signature.split('sha256=')[-1]
    
    # Use hmac.compare_digest to prevent timing attacks
    is_valid = hmac.compare_digest(expected_signature, provided_signature)
    
    if not is_valid:
        logger.warning(f"Signature verification failed")
    
    return is_valid

async def forward_to_n8n(payload: dict, retries: int = 0) -> Dict[str, Any]:
    """Forward the webhook payload to n8n with retry logic"""
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "WhatsApp-Webhook-Forwarder/1.0"
    }
    
    # Add n8n API key if configured
    if config.N8N_API_KEY:
        headers["Authorization"] = f"Bearer {config.N8N_API_KEY}"
    
    try:
        async with aiohttp_session.post(
            config.N8N_WEBHOOK_URL,
            json=payload,
            headers=headers
        ) as response:
            response_data = await response.json() if response.content_type == 'application/json' else await response.text()
            
            if response.status >= 200 and response.status < 300:
                logger.info(f"Successfully forwarded to n8n. Status: {response.status}")
                return {
                    "status": response.status,
                    "data": response_data,
                    "success": True
                }
            else:
                logger.warning(f"n8n responded with status {response.status}")
                raise aiohttp.ClientResponseError(
                    request_info=response.request_info,
                    history=response.history,
                    status=response.status
                )
    
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"Error forwarding to n8n (attempt {retries + 1}): {str(e)}")
        
        if retries < config.MAX_RETRIES - 1:
            await asyncio.sleep(config.RETRY_DELAY * (retries + 1))  # Exponential backoff
            return await forward_to_n8n(payload, retries + 1)
        
        raise e

# API Routes
@app.get("/")
async def root():
    """Root endpoint for health check"""
    return {
        "status": "healthy",
        "service": "WhatsApp Webhook Handler",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint for monitoring"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "config": {
            "n8n_webhook_configured": bool(config.N8N_WEBHOOK_URL),
            "signature_verification_enabled": config.ENABLE_SIGNATURE_VERIFICATION
        }
    }

@app.get("/webhook")
async def verify_webhook(
    request: Request,
    hub_mode: str = None,
    hub_verify_token: str = None,
    hub_challenge: str = None
):
    """Handle webhook verification from Meta"""
    logger.info(f"Webhook verification request received")
    
    # Get query parameters manually if not provided
    if not all([hub_mode, hub_verify_token, hub_challenge]):
        params = request.query_params
        hub_mode = params.get("hub.mode")
        hub_verify_token = params.get("hub.verify_token")
        hub_challenge = params.get("hub.challenge")
    
    if hub_mode == "subscribe" and hub_verify_token == config.VERIFY_TOKEN:
        logger.info("Webhook verified successfully")
        return Response(content=hub_challenge, media_type="text/plain")
    
    logger.warning(f"Webhook verification failed. Mode: {hub_mode}, Token valid: {hub_verify_token == config.VERIFY_TOKEN}")
    raise HTTPException(status_code=403, detail="Verification failed")

@app.post("/webhook")
async def handle_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_hub_signature_256: Optional[str] = Header(None)
):
    """Handle incoming webhook from Meta WhatsApp"""
    try:
        # Get raw body for signature verification
        body = await request.body()
        
        # Verify signature if enabled
        if config.ENABLE_SIGNATURE_VERIFICATION:
            if not verify_webhook_signature(body, x_hub_signature_256 or ""):
                logger.error("Webhook signature verification failed")
                raise HTTPException(status_code=401, detail="Invalid signature")
        
        # Parse JSON payload
        payload = await request.json()
        
        # Log the incoming webhook
        logger.info(f"Received webhook: {payload.get('object', 'unknown')}")
        
        # Process messages from the payload
        if payload.get("object") == "whatsapp_business_account":
            for entry in payload.get("entry", []):
                for change in entry.get("changes", []):
                    if change.get("field") == "messages":
                        value = change.get("value", {})
                        messages = value.get("messages", [])
                        for message in messages:
                            logger.info(f"Processing message from {message.get('from', 'unknown')}")
        
        # Forward to n8n in background to return quickly to Meta
        background_tasks.add_task(forward_webhook_background, payload)
        
        # Return 200 OK immediately to Meta
        return JSONResponse(
            status_code=200,
            content={
                "status": "received",
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error processing webhook: {str(e)}")
        # Still return 200 to Meta to avoid retries
        return JSONResponse(
            status_code=200,
            content={
                "status": "error",
                "message": "Internal processing error",
                "timestamp": datetime.utcnow().isoformat()
            }
        )

async def forward_webhook_background(payload: dict):
    """Background task to forward webhook to n8n"""
    try:
        result = await forward_to_n8n(payload)
        logger.info(f"Successfully forwarded webhook to n8n: {result}")
    except Exception as e:
        logger.error(f"Failed to forward webhook to n8n after all retries: {str(e)}")

@app.post("/test-forward")
async def test_forward(payload: dict):
    """Test endpoint to manually forward data to n8n"""
    try:
        result = await forward_to_n8n(payload)
        return ForwardResponse(
            success=True,
            message="Successfully forwarded to n8n",
            timestamp=datetime.utcnow().isoformat(),
            n8n_response=result
        )
    except Exception as e:
        return ForwardResponse(
            success=False,
            message="Failed to forward to n8n",
            timestamp=datetime.utcnow().isoformat(),
            error=str(e)
        )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8000")),
        reload=os.getenv("ENVIRONMENT", "production") == "development"
    )
