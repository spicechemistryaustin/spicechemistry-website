"""
TC_29d0cf_003: SQL Injection Prevention
Description: Test malicious SQL payloads in password fields (' OR '1'='1, UNION SELECT, DROP TABLE) 
return authentication failures, not database errors or unauthorized access.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient
from unittest.mock import patch


class TestSQLInjectionPrevention:
    """Test cases for SQL injection prevention in password validation."""
    
    def test_basic_sql_injection_payloads(self, client: TestClient, sql_injection_payloads):
        """Test that basic SQL injection payloads are handled safely."""
        for payload in sql_injection_payloads:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": payload,
                    "user_id": "test_user",
                    "context": "login"
                }
            )
            
            # Should return 200 with validation failure, NOT database errors
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Should be treated as invalid password, not cause database errors
            assert "is_valid" in data
            assert data["is_valid"] is False
            
            # Should not return database error messages
            assert "database" not in data.get("message", "").lower()
            assert "sql" not in data.get("message", "").lower()
            assert "syntax" not in data.get("message", "").lower()
            assert "error" not in data.get("message", "").lower() or "Password" in data.get("message", "")
            
    def test_sql_injection_in_user_id_field(self, client: TestClient):
        """Test SQL injection attempts in the user_id field."""
        sql_payloads = [
            "admin'; DROP TABLE users; --",
            "' OR '1'='1",
            "'; SELECT * FROM users; --",
            "admin' UNION SELECT * FROM passwords --"
        ]
        
        for payload in sql_payloads:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": "ValidPass123!",
                    "user_id": payload,
                    "context": "login"
                }
            )
            
            # Should handle gracefully without database errors
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]
            
            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                assert "is_valid" in data
                
    def test_sql_injection_in_context_field(self, client: TestClient):
        """Test SQL injection attempts in the context field."""
        sql_contexts = [
            "login'; DROP TABLE sessions; --",
            "' OR 1=1 --",
            "registration'; DELETE FROM users; --"
        ]
        
        for malicious_context in sql_contexts:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": "ValidPass123!",
                    "user_id": "test_user",
                    "context": malicious_context
                }
            )
            
            # Should handle without database errors
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST, status.HTTP_422_UNPROCESSABLE_ENTITY]
            
    def test_complex_sql_injection_scenarios(self, client: TestClient):
        """Test complex SQL injection scenarios."""
        complex_payloads = [
            {
                "password": "'; WAITFOR DELAY '00:00:05'; --",
                "description": "Time-based blind SQL injection"
            },
            {
                "password": "' AND (SELECT COUNT(*) FROM users) > 0 --",
                "description": "Boolean-based blind SQL injection"
            },
            {
                "password": "' UNION SELECT username, password FROM users WHERE '1'='1",
                "description": "Union-based SQL injection"
            },
            {
                "password": "'; EXEC xp_cmdshell('whoami'); --",
                "description": "Command injection via SQL"
            },
            {
                "password": "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
                "description": "Exists-based SQL injection"
            }
        ]
        
        for payload_info in complex_payloads:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": payload_info["password"],
                    "user_id": "test_user", 
                    "context": "validation"
                }
            )
            
            # All should be handled safely
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Should be treated as password validation failure
            assert data["is_valid"] is False
            
            # Response should not indicate successful SQL execution
            message = data.get("message", "").lower()
            assert "executed" not in message
            assert "selected" not in message
            assert "deleted" not in message
            assert "dropped" not in message
            
    def test_sql_injection_response_timing(self, client: TestClient, timing_attack_detector):
        """Test that SQL injection attempts don't cause timing differences."""
        test_cases = [
            "ValidPassword123!",  # Normal password
            "' OR '1'='1",       # SQL injection
            "'; WAITFOR DELAY '00:00:05'; --",  # Time-based attack
            "Normal123!",         # Another normal password
        ]
        
        for password in test_cases:
            timing_attack_detector.measure_request_time(
                client.post,
                "/api/v1/password/validate",
                json={
                    "password": password,
                    "context": "validation"
                }
            )
            
        # Response times should be consistent regardless of SQL payload
        is_consistent, max_deviation = timing_attack_detector.analyze_timing_consistency(
            tolerance_ms=500  # Allow some tolerance for processing
        )
        
        # SQL injection shouldn't cause significant timing differences
        assert max_deviation < 2000, f"SQL injection caused timing attack vulnerability: {max_deviation}ms"
        
    def test_database_error_handling(self, client: TestClient, user_repository, mock_logger):
        """Test that database errors are handled securely without information leakage."""
        # Simulate database error during SQL injection attempt
        with patch.object(user_repository, 'log_security_event') as mock_log:
            mock_log.side_effect = Exception("Database connection failed")
            
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": "'; DROP TABLE users; --",
                    "user_id": "test_user",
                    "context": "validation"
                }
            )
            
            # Should still return proper response, not expose database error
            assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]
            
            if response.status_code == status.HTTP_200_OK:
                data = response.json()
                # Should not expose internal database error details
                message = data.get("message", "").lower()
                assert "database connection failed" not in message
                assert "exception" not in message
                assert "traceback" not in message
                
    def test_parameterized_query_simulation(self, client: TestClient, user_repository):
        """Test that the system behaves as if using parameterized queries."""
        # The system should treat SQL injection as literal strings, not commands
        sql_password = "admin'; SELECT password FROM users WHERE username='admin'--"
        
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": sql_password,
                "user_id": "test_user",
                "context": "validation"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should validate the SQL string as a password, not execute it
        assert data["is_valid"] is False  # Likely fails complexity requirements
        
        # The SQL should be treated as literal text, not executed
        # This is evidenced by getting a validation response, not a database error
        
    def test_sql_injection_logging_security(self, client: TestClient, mock_logger):
        """Test that SQL injection attempts are logged securely."""
        sql_payload = "'; DROP TABLE users; SELECT * FROM passwords; --"
        
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": sql_payload,
                "user_id": "test_user",
                "context": "validation"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Check that logs don't contain the actual SQL payload
        for call in mock_logger.info.call_args_list + mock_logger.error.call_args_list:
            log_message = str(call[0][0])
            # Should log metadata but not the actual malicious password
            assert "DROP TABLE" not in log_message
            assert "SELECT *" not in log_message
            # Should log length but not content
            if "Length:" in log_message:
                assert len(sql_payload) == int(log_message.split("Length:")[1].strip().split()[0])
                
    def test_service_layer_sql_injection_handling(self, password_service):
        """Test that the service layer handles SQL injection securely."""
        from ..model.password_validation_models import PasswordValidationRequest
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "admin'--"
        ]
        
        for payload in sql_payloads:
            request = PasswordValidationRequest(
                password=payload,
                user_id="test_user",
                context="validation"
            )
            
            # Should process without throwing database exceptions
            response = password_service.validate_password(request)
            
            assert response is not None
            assert hasattr(response, 'is_valid')
            assert response.is_valid is False  # SQL strings should fail validation
            
            # Should not indicate SQL execution success
            assert "executed" not in response.message.lower()
            assert "selected" not in response.message.lower()
            
    def test_concurrent_sql_injection_attacks(self, client: TestClient, concurrent_request_helper):
        """Test concurrent SQL injection attempts."""
        sql_payloads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "' UNION SELECT * FROM passwords --",
            "admin'; DELETE FROM sessions; --",
            "'; EXEC sp_configure 'show advanced options', 1; --"
        ]
        
        test_data = [
            {"password": payload, "context": "validation", "user_id": f"user_{i}"}
            for i, payload in enumerate(sql_payloads)
        ]
        
        results = concurrent_request_helper.execute_concurrent_requests(
            client=client,
            endpoint="/api/v1/password/validate",
            data_list=test_data,
            thread_count=25
        )
        
        # All requests should be handled safely
        assert results["successful_requests"] >= 20  # Allow some failures due to rate limiting
        assert results["failed_requests"] <= 5
        
        # No request should have caused database errors
        for result in results["results"]:
            if result["status_code"] == status.HTTP_200_OK:
                response_data = result["response_data"]
                assert "is_valid" in response_data
                # Should be validation failures, not database errors
                message = response_data.get("message", "").lower()
                assert "database" not in message or "error" not in message
                
    def test_strength_endpoint_sql_injection(self, client: TestClient):
        """Test SQL injection attempts against strength analysis endpoint."""
        sql_payload = "' UNION SELECT password FROM users WHERE username='admin'--"
        
        response = client.post(
            "/api/v1/password/strength",
            json={
                "password": sql_payload
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should analyze the SQL string as text, not execute it
        assert "entropy" in data
        assert "length" in data
        assert data["length"] == len(sql_payload)
        
    def test_breach_check_sql_injection(self, client: TestClient):
        """Test SQL injection attempts against breach check endpoint."""
        sql_payload = "'; SELECT * FROM breached_passwords; --"
        
        response = client.post(
            "/api/v1/password/check-breach",
            json={
                "password": sql_payload
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Should check the SQL string as a literal password
        assert "is_compromised" in data
        assert isinstance(data["is_compromised"], bool)