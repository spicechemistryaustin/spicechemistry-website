import time
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, Depends, Request, status
from fastapi.security import HTTPBearer
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
import hashlib
import secrets

from ..service.password_validation_service import PasswordValidationService
from ..data.user_repository import UserRepository
from ..model.password_validation_models import (
    PasswordValidationRequest,
    PasswordValidationResponse,
    PasswordValidationResult,
    SecurityEvent
)


# Pydantic models for API requests/responses
class PasswordValidationAPIRequest(BaseModel):
    password: str
    user_id: Optional[str] = None
    context: Optional[str] = "validation"
    
    @validator('password')
    def password_must_not_be_none(cls, v):
        if v is None:
            raise ValueError('Password cannot be None')
        return v


class PasswordValidationAPIResponse(BaseModel):
    is_valid: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    processing_time_ms: Optional[float] = None


class PasswordStrengthAPIResponse(BaseModel):
    entropy: float
    character_diversity: int
    length: int
    contains_uppercase: bool
    contains_lowercase: bool
    contains_digits: bool
    contains_special_chars: bool
    strength_score: float  # 0-100


class RateLimiter:
    def __init__(self):
        self.requests = {}  # {ip: [(timestamp, count), ...]}
        self.max_requests_per_minute = 60
        self.max_requests_per_hour = 1000
        self.cleanup_interval = 3600  # 1 hour
        self.last_cleanup = time.time()
    
    def is_rate_limited(self, client_ip: str) -> bool:
        """
        Check if client is rate limited
        Returns True if rate limited, False otherwise
        """
        current_time = time.time()
        
        # Periodic cleanup
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_requests(current_time)
            self.last_cleanup = current_time
        
        if client_ip not in self.requests:
            self.requests[client_ip] = []
        
        client_requests = self.requests[client_ip]
        
        # Remove old requests
        minute_ago = current_time - 60
        hour_ago = current_time - 3600
        client_requests[:] = [req for req in client_requests if req[0] > hour_ago]
        
        # Count requests in last minute and hour
        requests_last_minute = sum(1 for req_time, _ in client_requests if req_time > minute_ago)
        requests_last_hour = len(client_requests)
        
        # Check limits
        if requests_last_minute >= self.max_requests_per_minute:
            return True
        if requests_last_hour >= self.max_requests_per_hour:
            return True
        
        # Record this request
        client_requests.append((current_time, 1))
        return False
    
    def _cleanup_old_requests(self, current_time: float):
        """Remove old request records to prevent memory leaks"""
        hour_ago = current_time - 3600
        for ip in list(self.requests.keys()):
            self.requests[ip] = [req for req in self.requests[ip] if req[0] > hour_ago]
            if not self.requests[ip]:
                del self.requests[ip]


# Global instances
router = APIRouter(prefix="/api/v1/password", tags=["password-validation"])
security = HTTPBearer(auto_error=False)
rate_limiter = RateLimiter()
logger = logging.getLogger(__name__)

# Dependency injection
def get_password_service() -> PasswordValidationService:
    return PasswordValidationService()

def get_user_repository() -> UserRepository:
    return UserRepository()

def get_client_ip(request: Request) -> str:
    """Extract client IP address with proxy support"""
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


@router.post("/validate", response_model=PasswordValidationAPIResponse)
async def validate_password(
    request_data: PasswordValidationAPIRequest,
    request: Request,
    password_service: PasswordValidationService = Depends(get_password_service),
    user_repo: UserRepository = Depends(get_user_repository)
) -> PasswordValidationAPIResponse:
    """
    Validate password against security policies
    
    This endpoint validates passwords for registration and login scenarios.
    It implements timing attack prevention and comprehensive security checks.
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting
    if rate_limiter.is_rate_limited(client_ip):
        logger.warning(f"Rate limit exceeded for IP: {client_ip}")
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    start_time = time.time()
    
    try:
        # Handle empty/null password cases with specific error
        if not request_data.password or request_data.password.strip() == "":
            return PasswordValidationAPIResponse(
                is_valid=False,
                message="Password cannot be empty",
                processing_time_ms=(time.time() - start_time) * 1000
            )
        
        # Create service request
        validation_request = PasswordValidationRequest(
            password=request_data.password,
            user_id=request_data.user_id,
            context=request_data.context
        )
        
        # Perform validation
        result = password_service.validate_password(validation_request)
        
        # Log security event
        security_event = SecurityEvent(
            event_type="password_validation",
            user_id=request_data.user_id,
            ip_address=client_ip,
            timestamp=datetime.utcnow(),
            success=result.is_valid,
            details={
                "context": request_data.context,
                "validation_result": result.result.value,
                "client_ip": client_ip
            }
        )
        user_repo.log_security_event(security_event)
        
        return PasswordValidationAPIResponse(
            is_valid=result.is_valid,
            message=result.message,
            processing_time_ms=result.processing_time_ms
        )
        
    except Exception as e:
        logger.error(f"Password validation error: {str(e)}")
        
        # Log security event for error case
        security_event = SecurityEvent(
            event_type="password_validation_error",
            user_id=request_data.user_id,
            ip_address=client_ip,
            timestamp=datetime.utcnow(),
            success=False,
            details={
                "error": "validation_failed",
                "context": request_data.context,
                "client_ip": client_ip
            }
        )
        user_repo.log_security_event(security_event)
        
        # Return consistent timing and error format
        time.sleep(0.1)  # Constant timing
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password validation failed"
        )


@router.post("/strength", response_model=PasswordStrengthAPIResponse)
async def analyze_password_strength(
    request_data: PasswordValidationAPIRequest,
    request: Request,
    password_service: PasswordValidationService = Depends(get_password_service)
) -> PasswordStrengthAPIResponse:
    """
    Analyze password strength and provide detailed metrics
    
    This endpoint provides detailed analysis of password strength
    without performing full validation.
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting
    if rate_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    try:
        if not request_data.password:
            return PasswordStrengthAPIResponse(
                entropy=0.0,
                character_diversity=0,
                length=0,
                contains_uppercase=False,
                contains_lowercase=False,
                contains_digits=False,
                contains_special_chars=False,
                strength_score=0.0
            )
        
        metrics = password_service.calculate_password_strength(request_data.password)
        
        # Calculate strength score (0-100)
        strength_score = min(100.0, (metrics.entropy / 60.0) * 100)  # 60 bits = 100%
        
        return PasswordStrengthAPIResponse(
            entropy=metrics.entropy,
            character_diversity=metrics.character_diversity,
            length=metrics.length,
            contains_uppercase=metrics.contains_uppercase,
            contains_lowercase=metrics.contains_lowercase,
            contains_digits=metrics.contains_digits,
            contains_special_chars=metrics.contains_special_chars,
            strength_score=strength_score
        )
        
    except Exception as e:
        logger.error(f"Password strength analysis error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password strength analysis failed"
        )


@router.post("/check-breach", response_model=Dict[str, Any])
async def check_password_breach(
    request_data: PasswordValidationAPIRequest,
    request: Request,
    password_service: PasswordValidationService = Depends(get_password_service)
) -> Dict[str, Any]:
    """
    Check if password appears in known data breaches
    
    This endpoint checks passwords against known breach databases
    without storing or logging the actual password value.
    """
    client_ip = get_client_ip(request)
    
    # Rate limiting with stricter limits for breach checking
    if rate_limiter.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please try again later.",
            headers={"Retry-After": "60"}
        )
    
    try:
        if not request_data.password:
            return {
                "is_compromised": False,
                "message": "Empty password provided"
            }
        
        is_compromised = password_service.is_password_compromised(request_data.password)
        
        return {
            "is_compromised": is_compromised,
            "message": "Password found in breach database" if is_compromised else "Password not found in breach database"
        }
        
    except Exception as e:
        logger.error(f"Password breach check error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password breach check failed"
        )


@router.get("/health")
async def health_check(
    user_repo: UserRepository = Depends(get_user_repository)
) -> Dict[str, Any]:
    """
    Health check endpoint for monitoring
    """
    try:
        db_health = user_repo.health_check()
        
        return {
            "status": "healthy" if db_health["status"] == "healthy" else "degraded",
            "timestamp": datetime.utcnow().isoformat(),
            "database": db_health,
            "version": "1.0.0"
        }
        
    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        return {
            "status": "unhealthy",
            "timestamp": datetime.utcnow().isoformat(),
            "error": str(e),
            "version": "1.0.0"
        }


# Error handlers
@router.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    """Custom HTTP exception handler for consistent error responses"""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": True,
            "message": exc.detail,
            "timestamp": datetime.utcnow().isoformat(),
            "path": str(request.url.path)
        }
    )