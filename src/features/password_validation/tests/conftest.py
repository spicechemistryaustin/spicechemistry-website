import pytest
import asyncio
import time
import threading
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from typing import Dict, Any, List, Generator
import boto3
from moto import mock_dynamodb
from fastapi.testclient import TestClient
import psutil
import os

from ..api.routes import router, rate_limiter
from ..service.password_validation_service import PasswordValidationService
from ..data.user_repository import UserRepository
from ..model.password_validation_models import (
    PasswordValidationRequest,
    SecurityEvent,
    UserSecurityProfile
)


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def client():
    """Create a test client for the FastAPI app."""
    from fastapi import FastAPI
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


@pytest.fixture
def mock_dynamodb_table():
    """Create a mock DynamoDB table for testing."""
    with mock_dynamodb():
        # Create DynamoDB resource
        dynamodb = boto3.resource('dynamodb', region_name='us-east-1')
        
        # Create table
        table = dynamodb.create_table(
            TableName='Users',
            KeySchema=[
                {'AttributeName': 'PK', 'KeyType': 'HASH'},
                {'AttributeName': 'SK', 'KeyType': 'RANGE'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'PK', 'AttributeType': 'S'},
                {'AttributeName': 'SK', 'AttributeType': 'S'}
            ],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Wait for table to be created
        table.wait_until_exists()
        yield table


@pytest.fixture
def user_repository(mock_dynamodb_table):
    """Create a UserRepository instance with mocked DynamoDB."""
    repo = UserRepository(table_name='Users')
    repo._table = mock_dynamodb_table
    return repo


@pytest.fixture
def password_service():
    """Create a PasswordValidationService instance."""
    return PasswordValidationService()


@pytest.fixture
def sample_security_event():
    """Create a sample security event for testing."""
    return SecurityEvent(
        event_type="password_validation",
        user_id="test_user_123",
        ip_address="192.168.1.1",
        timestamp=datetime.utcnow(),
        success=True,
        details={
            "validation_result": "valid",
            "context": "registration",
            "password_length": 12,
            "client_ip": "192.168.1.1"
        }
    )


@pytest.fixture
def sample_user_security_profile():
    """Create a sample user security profile for testing."""
    return UserSecurityProfile(
        user_id="test_user_123",
        failed_attempts=0,
        last_failed_attempt=None,
        last_successful_login=datetime.utcnow(),
        account_locked=False,
        lock_until=None
    )


@pytest.fixture
def unicode_password_samples():
    """Provide various Unicode password samples for testing."""
    return [
        "Pássw0rd!🔒",  # Portuguese with emoji
        "Пароль123!",    # Cyrillic
        "密码Password1!",  # Chinese
        "パスワード1!",     # Japanese
        "كلمةالمرور1!",   # Arabic
        "Hëllö123!",     # Accented letters
        "Test🚀123!",    # Emoji
        "Café☕123!",     # Mixed accents and emoji
    ]


@pytest.fixture
def sql_injection_payloads():
    """Provide SQL injection test payloads."""
    return [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "' UNION SELECT * FROM users --",
        "admin'--",
        "admin' #",
        "admin'/*",
        "' OR 1=1--",
        "' OR 'a'='a",
        "') OR ('1'='1",
        "'; EXEC xp_cmdshell('dir'); --"
    ]


@pytest.fixture
def xss_injection_payloads():
    """Provide XSS injection test payloads."""
    return [
        "<script>alert('xss')</script>",
        "<img src=x onerror=alert('xss')>",
        "javascript:alert('xss')",
        "<svg onload=alert('xss')>",
        "<iframe src=javascript:alert('xss')>",
        "&#60;script&#62;alert('xss')&#60;/script&#62;",
        "<script>document.cookie</script>",
        "<img src='x' onerror='eval(String.fromCharCode(97,108,101,114,116,40,39,120,115,115,39,41))'>",
        "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//",
        "&lt;script&gt;alert('xss')&lt;/script&gt;"
    ]


@pytest.fixture
def boundary_length_passwords():
    """Provide password samples at boundary lengths."""
    return {
        "empty": "",
        "single_char": "A",
        "min_length_minus_1": "Abc123!",  # 7 chars
        "min_length": "Abc1234!",         # 8 chars
        "normal": "MyPassword123!",       # 13 chars
        "max_length": "A" * 127 + "1!",   # 129 chars (max + 1)
        "max_length_valid": "A" * 125 + "1!", # 127 chars (max - 1)
        "very_long": "A" * 255 + "1!",    # 257 chars
    }


@pytest.fixture
def memory_monitor():
    """Memory monitoring fixture for leak detection."""
    class MemoryMonitor:
        def __init__(self):
            self.initial_memory = None
            self.peak_memory = None
            self.final_memory = None
            
        def start_monitoring(self):
            self.initial_memory = psutil.Process().memory_info().rss
            self.peak_memory = self.initial_memory
            
        def update_peak(self):
            current_memory = psutil.Process().memory_info().rss
            if current_memory > self.peak_memory:
                self.peak_memory = current_memory
                
        def stop_monitoring(self):
            self.final_memory = psutil.Process().memory_info().rss
            
        def get_memory_growth_percent(self):
            if self.initial_memory and self.final_memory:
                growth = ((self.final_memory - self.initial_memory) / self.initial_memory) * 100
                return growth
            return 0
            
        def get_peak_memory_growth_percent(self):
            if self.initial_memory and self.peak_memory:
                growth = ((self.peak_memory - self.initial_memory) / self.initial_memory) * 100
                return growth
            return 0
    
    return MemoryMonitor()


@pytest.fixture
def concurrent_request_helper():
    """Helper for concurrent request testing."""
    class ConcurrentRequestHelper:
        def __init__(self):
            self.results = []
            self.errors = []
            self.lock = threading.Lock()
            
        def make_request(self, client, endpoint, data, headers=None):
            try:
                start_time = time.time()
                response = client.post(endpoint, json=data, headers=headers or {})
                end_time = time.time()
                
                with self.lock:
                    self.results.append({
                        'status_code': response.status_code,
                        'response_time': (end_time - start_time) * 1000,  # ms
                        'response_data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
                    })
            except Exception as e:
                with self.lock:
                    self.errors.append(str(e))
                    
        def execute_concurrent_requests(self, client, endpoint, data_list, thread_count=100, headers=None):
            threads = []
            
            for i in range(min(thread_count, len(data_list))):
                data = data_list[i % len(data_list)]
                thread = threading.Thread(
                    target=self.make_request,
                    args=(client, endpoint, data, headers)
                )
                threads.append(thread)
                thread.start()
                
            for thread in threads:
                thread.join()
                
            return {
                'total_requests': len(threads),
                'successful_requests': len(self.results),
                'failed_requests': len(self.errors),
                'results': self.results,
                'errors': self.errors,
                'average_response_time': sum(r['response_time'] for r in self.results) / len(self.results) if self.results else 0,
                'max_response_time': max(r['response_time'] for r in self.results) if self.results else 0,
                'min_response_time': min(r['response_time'] for r in self.results) if self.results else 0
            }
    
    return ConcurrentRequestHelper()


@pytest.fixture
def db_connection_simulator():
    """Simulate database connection issues for resilience testing."""
    class DBConnectionSimulator:
        def __init__(self, user_repository):
            self.user_repository = user_repository
            self.original_table = user_repository._table
            
        def simulate_connection_drop(self):
            """Simulate connection drop by replacing table with None."""
            self.user_repository._table = None
            self.user_repository._dynamodb = None
            
        def simulate_timeout(self):
            """Simulate timeout by mocking table operations to raise timeout."""
            mock_table = Mock()
            mock_table.get_item.side_effect = Exception("Connection timed out")
            mock_table.put_item.side_effect = Exception("Connection timed out")
            mock_table.query.side_effect = Exception("Connection timed out")
            self.user_repository._table = mock_table
            
        def simulate_throttling(self):
            """Simulate DynamoDB throttling."""
            from botocore.exceptions import ClientError
            mock_table = Mock()
            throttle_error = ClientError(
                {'Error': {'Code': 'ProvisionedThroughputExceededException'}},
                'GetItem'
            )
            mock_table.get_item.side_effect = throttle_error
            mock_table.put_item.side_effect = throttle_error
            self.user_repository._table = mock_table
            
        def restore_connection(self):
            """Restore normal connection."""
            self.user_repository._table = self.original_table
    
    return DBConnectionSimulator


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Reset rate limiter between tests."""
    yield
    rate_limiter.requests.clear()


@pytest.fixture
def test_data_dir():
    """Get test data directory path."""
    return os.path.join(os.path.dirname(__file__), "test_data")


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing log outputs."""
    with patch('logging.getLogger') as mock_get_logger:
        mock_logger = Mock()
        mock_get_logger.return_value = mock_logger
        yield mock_logger


@pytest.fixture
def timing_attack_detector():
    """Helper to detect timing attacks by measuring response times."""
    class TimingAttackDetector:
        def __init__(self):
            self.measurements = []
            
        def measure_request_time(self, func, *args, **kwargs):
            start_time = time.perf_counter()
            result = func(*args, **kwargs)
            end_time = time.perf_counter()
            
            elapsed_time = (end_time - start_time) * 1000  # Convert to milliseconds
            self.measurements.append(elapsed_time)
            return result, elapsed_time
            
        def analyze_timing_consistency(self, tolerance_ms=50):
            """Analyze if response times are consistent (within tolerance)."""
            if len(self.measurements) < 2:
                return True, 0
                
            avg_time = sum(self.measurements) / len(self.measurements)
            max_deviation = max(abs(t - avg_time) for t in self.measurements)
            
            is_consistent = max_deviation <= tolerance_ms
            return is_consistent, max_deviation
            
        def get_statistics(self):
            if not self.measurements:
                return {}
                
            return {
                'count': len(self.measurements),
                'min': min(self.measurements),
                'max': max(self.measurements),
                'avg': sum(self.measurements) / len(self.measurements),
                'std_dev': (sum((x - sum(self.measurements) / len(self.measurements)) ** 2 for x in self.measurements) / len(self.measurements)) ** 0.5
            }
    
    return TimingAttackDetector()


@pytest.fixture
def performance_validator():
    """Validator for performance requirements."""
    class PerformanceValidator:
        def __init__(self):
            self.response_times = []
            
        def add_response_time(self, response_time_ms):
            self.response_times.append(response_time_ms)
            
        def validate_95th_percentile(self, threshold_ms=2000):
            """Validate 95th percentile response time."""
            if not self.response_times:
                return False, 0
                
            sorted_times = sorted(self.response_times)
            index_95th = int(len(sorted_times) * 0.95)
            percentile_95th = sorted_times[index_95th]
            
            return percentile_95th <= threshold_ms, percentile_95th
            
        def validate_error_rate(self, error_count, total_requests, threshold_percent=5):
            """Validate error rate is below threshold."""
            if total_requests == 0:
                return True, 0
                
            error_rate = (error_count / total_requests) * 100
            return error_rate <= threshold_percent, error_rate
            
        def get_statistics(self):
            if not self.response_times:
                return {}
                
            sorted_times = sorted(self.response_times)
            return {
                'count': len(sorted_times),
                'min': min(sorted_times),
                'max': max(sorted_times),
                'avg': sum(sorted_times) / len(sorted_times),
                'median': sorted_times[len(sorted_times) // 2],
                'p95': sorted_times[int(len(sorted_times) * 0.95)],
                'p99': sorted_times[int(len(sorted_times) * 0.99)]
            }
    
    return PerformanceValidator()