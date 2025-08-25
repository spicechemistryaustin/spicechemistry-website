from dataclasses import dataclass
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class PasswordValidationResult(Enum):
    VALID = "valid"
    TOO_SHORT = "too_short"
    TOO_LONG = "too_long"
    MISSING_UPPERCASE = "missing_uppercase"
    MISSING_LOWERCASE = "missing_lowercase"
    MISSING_DIGIT = "missing_digit"
    MISSING_SPECIAL_CHAR = "missing_special_char"
    COMMON_PASSWORD = "common_password"
    DICTIONARY_WORD = "dictionary_word"
    EMPTY_PASSWORD = "empty_password"
    INVALID_CHARACTERS = "invalid_characters"


@dataclass
class ValidationRule:
    name: str
    enabled: bool = True
    parameters: Optional[Dict[str, Any]] = None


@dataclass
class PasswordValidationRequest:
    password: str
    user_id: Optional[str] = None
    context: Optional[str] = None  # 'registration' or 'login' or 'change'


@dataclass
class PasswordValidationResponse:
    is_valid: bool
    result: PasswordValidationResult
    message: str
    details: Optional[Dict[str, Any]] = None
    processing_time_ms: Optional[float] = None


@dataclass
class SecurityEvent:
    event_type: str
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime
    details: Dict[str, Any]
    success: bool


@dataclass
class UserSecurityProfile:
    user_id: str
    failed_attempts: int = 0
    last_failed_attempt: Optional[datetime] = None
    last_successful_login: Optional[datetime] = None
    account_locked: bool = False
    lock_until: Optional[datetime] = None


@dataclass
class PasswordStrengthMetrics:
    entropy: float
    character_diversity: int
    length: int
    contains_uppercase: bool
    contains_lowercase: bool
    contains_digits: bool
    contains_special_chars: bool
    repeated_characters: int
    sequential_characters: int