import re
import time
import hashlib
import secrets
from typing import List, Set, Dict, Optional, Any
from datetime import datetime, timedelta
import logging
from pathlib import Path

from ..model.password_validation_models import (
    PasswordValidationRequest,
    PasswordValidationResponse,
    PasswordValidationResult,
    SecurityEvent,
    PasswordStrengthMetrics
)


class PasswordValidationService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._common_passwords = self._load_common_passwords()
        self._dictionary_words = self._load_dictionary_words()
        self._min_length = 8
        self._max_length = 128
        self._timing_constant = 0.1  # Constant time for timing attack prevention
        
    def _load_common_passwords(self) -> Set[str]:
        """Load common passwords from a predefined list"""
        # Top 1000 most common passwords (subset for security)
        common_passwords = {
            "password", "123456", "123456789", "12345678", "12345", "1234567",
            "qwerty", "abc123", "111111", "123123", "admin", "password123",
            "letmein", "welcome", "monkey", "dragon", "password1", "123321",
            "654321", "superman", "qazwsx", "michael", "football", "baseball",
            "liverpool", "jordan23", "princess", "charlie", "aa123456", "donald",
            "password12", "qwerty123", "123qwe", "zxcvbnm", "killer", "trustno1",
            "hunter", "sunshine", "iloveyou", "password!", "123456a", "password@",
            "welcome123", "admin123", "root", "toor", "guest", "test", "demo"
        }
        return common_passwords
    
    def _load_dictionary_words(self) -> Set[str]:
        """Load dictionary words for validation"""
        # Common English dictionary words that should be rejected
        dictionary_words = {
            "password", "welcome", "admin", "login", "user", "account", "system",
            "computer", "internet", "website", "database", "server", "network",
            "security", "access", "private", "public", "secret", "hidden",
            "company", "business", "service", "application", "software", "program",
            "windows", "linux", "apple", "google", "microsoft", "facebook",
            "twitter", "amazon", "yahoo", "gmail", "email", "phone", "mobile",
            "address", "street", "house", "apartment", "office", "building"
        }
        return dictionary_words
    
    def validate_password(self, request: PasswordValidationRequest) -> PasswordValidationResponse:
        """
        Validate password against all security rules with timing attack prevention
        """
        start_time = time.time()
        
        try:
            # Always perform full validation to prevent timing attacks
            validation_results = self._perform_all_validations(request.password)
            
            # Determine overall result
            if not validation_results:
                result = PasswordValidationResult.VALID
                is_valid = True
                message = "Password meets all security requirements"
            else:
                # Return the first (most critical) validation failure
                result = validation_results[0]
                is_valid = False
                message = self._get_error_message(result)
            
            # Log security event (sanitized)
            self._log_security_event(request, result, is_valid)
            
        except Exception as e:
            self.logger.error(f"Password validation error: {str(e)}")
            result = PasswordValidationResult.INVALID_CHARACTERS
            is_valid = False
            message = "Password validation failed"
        
        # Ensure consistent timing to prevent timing attacks
        elapsed_time = time.time() - start_time
        if elapsed_time < self._timing_constant:
            time.sleep(self._timing_constant - elapsed_time)
        
        processing_time = (time.time() - start_time) * 1000
        
        return PasswordValidationResponse(
            is_valid=is_valid,
            result=result,
            message=message,
            processing_time_ms=processing_time
        )
    
    def _perform_all_validations(self, password: str) -> List[PasswordValidationResult]:
        """Perform all validation checks and return list of violations"""
        violations = []
        
        # Empty password check
        if not password or password.strip() == "":
            violations.append(PasswordValidationResult.EMPTY_PASSWORD)
            return violations  # No need to check further if empty
        
        # Length checks
        if len(password) < self._min_length:
            violations.append(PasswordValidationResult.TOO_SHORT)
        elif len(password) > self._max_length:
            violations.append(PasswordValidationResult.TOO_LONG)
        
        # Character composition checks
        if not re.search(r'[A-Z]', password):
            violations.append(PasswordValidationResult.MISSING_UPPERCASE)
        
        if not re.search(r'[a-z]', password):
            violations.append(PasswordValidationResult.MISSING_LOWERCASE)
        
        if not re.search(r'\d', password):
            violations.append(PasswordValidationResult.MISSING_DIGIT)
        
        if not re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password):
            violations.append(PasswordValidationResult.MISSING_SPECIAL_CHAR)
        
        # Common password check (case-insensitive)
        if password.lower() in self._common_passwords:
            violations.append(PasswordValidationResult.COMMON_PASSWORD)
        
        # Dictionary word check (case-insensitive)
        if password.lower() in self._dictionary_words:
            violations.append(PasswordValidationResult.DICTIONARY_WORD)
            
        # Check for dictionary words as substrings (for longer passwords)
        password_lower = password.lower()
        for word in self._dictionary_words:
            if len(word) >= 4 and word in password_lower:
                violations.append(PasswordValidationResult.DICTIONARY_WORD)
                break
        
        return violations
    
    def _get_error_message(self, result: PasswordValidationResult) -> str:
        """Get user-friendly error message for validation result"""
        messages = {
            PasswordValidationResult.EMPTY_PASSWORD: "Password cannot be empty",
            PasswordValidationResult.TOO_SHORT: f"Password must be at least {self._min_length} characters long",
            PasswordValidationResult.TOO_LONG: f"Password must not exceed {self._max_length} characters",
            PasswordValidationResult.MISSING_UPPERCASE: "Password must contain at least one uppercase letter",
            PasswordValidationResult.MISSING_LOWERCASE: "Password must contain at least one lowercase letter", 
            PasswordValidationResult.MISSING_DIGIT: "Password must contain at least one digit",
            PasswordValidationResult.MISSING_SPECIAL_CHAR: "Password must contain at least one special character",
            PasswordValidationResult.COMMON_PASSWORD: "Password is too common and easily guessable",
            PasswordValidationResult.DICTIONARY_WORD: "Password contains dictionary words and is easily guessable",
            PasswordValidationResult.INVALID_CHARACTERS: "Password contains invalid characters"
        }
        return messages.get(result, "Password validation failed")
    
    def _log_security_event(self, request: PasswordValidationRequest, result: PasswordValidationResult, success: bool):
        """Log security event without exposing sensitive data"""
        event = SecurityEvent(
            event_type="password_validation",
            user_id=request.user_id,
            timestamp=datetime.utcnow(),
            success=success,
            details={
                "validation_result": result.value,
                "context": request.context,
                "password_length": len(request.password) if request.password else 0,
                "has_uppercase": bool(re.search(r'[A-Z]', request.password)) if request.password else False,
                "has_lowercase": bool(re.search(r'[a-z]', request.password)) if request.password else False,
                "has_digits": bool(re.search(r'\d', request.password)) if request.password else False,
                "has_special_chars": bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', request.password)) if request.password else False
            }
        )
        
        # Log event (password value is never logged)
        self.logger.info(
            f"Password validation event - User: {event.user_id}, "
            f"Result: {result.value}, Success: {success}, "
            f"Context: {request.context}, Length: {len(request.password) if request.password else 0}"
        )
    
    def calculate_password_strength(self, password: str) -> PasswordStrengthMetrics:
        """Calculate detailed password strength metrics"""
        if not password:
            return PasswordStrengthMetrics(
                entropy=0.0, character_diversity=0, length=0,
                contains_uppercase=False, contains_lowercase=False,
                contains_digits=False, contains_special_chars=False,
                repeated_characters=0, sequential_characters=0
            )
        
        # Character set analysis
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\?]', password))
        
        # Calculate character set size
        charset_size = 0
        if has_lower:
            charset_size += 26
        if has_upper:
            charset_size += 26
        if has_digits:
            charset_size += 10
        if has_special:
            charset_size += 32  # Approximate special character count
        
        # Calculate entropy (bits)
        import math
        entropy = len(password) * math.log2(charset_size) if charset_size > 0 else 0
        
        # Character diversity
        unique_chars = len(set(password))
        
        # Repeated characters
        repeated = len(password) - unique_chars
        
        # Sequential characters (simplified check)
        sequential = 0
        for i in range(len(password) - 2):
            if (ord(password[i+1]) == ord(password[i]) + 1 and 
                ord(password[i+2]) == ord(password[i]) + 2):
                sequential += 1
        
        return PasswordStrengthMetrics(
            entropy=entropy,
            character_diversity=unique_chars,
            length=len(password),
            contains_uppercase=has_upper,
            contains_lowercase=has_lower,  
            contains_digits=has_digits,
            contains_special_chars=has_special,
            repeated_characters=repeated,
            sequential_characters=sequential
        )
    
    def is_password_compromised(self, password: str) -> bool:
        """Check if password appears in known breach databases (placeholder)"""
        # In a real implementation, this would check against breach databases
        # like HaveIBeenPwned API, but for testing we'll use our common passwords list
        return password.lower() in self._common_passwords