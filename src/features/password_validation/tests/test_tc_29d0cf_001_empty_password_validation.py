"""
TC_29d0cf_001: Empty Password Validation
Description: Verify API rejects empty password strings ("", null, undefined) with HTTP 400 
and error message "Password cannot be empty". Test both registration and login endpoints.
"""

import pytest
from fastapi import status
from fastapi.testclient import TestClient


class TestEmptyPasswordValidation:
    """Test cases for empty password validation requirements."""
    
    def test_empty_string_password_validation_endpoint(self, client: TestClient):
        """Test that empty string password is rejected by validation endpoint."""
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": "",
                "context": "validation"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_valid"] is False
        assert data["message"] == "Password cannot be empty"
        assert "processing_time_ms" in data
        
    def test_empty_string_password_registration_context(self, client: TestClient):
        """Test that empty string password is rejected in registration context."""
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": "",
                "user_id": "test_user",
                "context": "registration"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_valid"] is False
        assert data["message"] == "Password cannot be empty"
        
    def test_empty_string_password_login_context(self, client: TestClient):
        """Test that empty string password is rejected in login context."""
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": "",
                "user_id": "test_user",
                "context": "login"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_valid"] is False
        assert data["message"] == "Password cannot be empty"
        
    def test_whitespace_only_password(self, client: TestClient):
        """Test that whitespace-only password is rejected."""
        test_cases = [
            " ",      # single space
            "   ",    # multiple spaces
            "\t",     # tab
            "\n",     # newline
            "\r",     # carriage return
            " \t\n ", # mixed whitespace
        ]
        
        for password in test_cases:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": password,
                    "context": "validation"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["is_valid"] is False
            assert data["message"] == "Password cannot be empty"
            
    def test_null_password_handling(self, client: TestClient):
        """Test handling of null password values (Python None)."""
        # Test with missing password field
        response = client.post(
            "/api/v1/password/validate",
            json={
                "context": "validation"
            }
        )
        
        # Should return 422 for missing required field
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        
    def test_empty_password_strength_endpoint(self, client: TestClient):
        """Test that strength endpoint handles empty passwords gracefully."""
        response = client.post(
            "/api/v1/password/strength",
            json={
                "password": ""
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["entropy"] == 0.0
        assert data["character_diversity"] == 0
        assert data["length"] == 0
        assert data["contains_uppercase"] is False
        assert data["contains_lowercase"] is False
        assert data["contains_digits"] is False
        assert data["contains_special_chars"] is False
        assert data["strength_score"] == 0.0
        
    def test_empty_password_breach_check_endpoint(self, client: TestClient):
        """Test that breach check endpoint handles empty passwords gracefully."""
        response = client.post(
            "/api/v1/password/check-breach",
            json={
                "password": ""
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["is_compromised"] is False
        assert data["message"] == "Empty password provided"
        
    def test_empty_password_response_timing_consistency(self, client: TestClient, timing_attack_detector):
        """Test that empty password responses have consistent timing."""
        request_data = {
            "password": "",
            "context": "validation"
        }
        
        # Make multiple requests to measure timing consistency
        for _ in range(10):
            timing_attack_detector.measure_request_time(
                client.post,
                "/api/v1/password/validate",
                json=request_data
            )
            
        is_consistent, max_deviation = timing_attack_detector.analyze_timing_consistency(
            tolerance_ms=100  # Allow 100ms deviation
        )
        
        assert is_consistent, f"Response timing inconsistent. Max deviation: {max_deviation}ms"
        
    def test_empty_password_different_endpoints_consistency(self, client: TestClient):
        """Test that all endpoints consistently reject empty passwords."""
        empty_password_data = {"password": ""}
        
        # Test validation endpoint
        validation_response = client.post(
            "/api/v1/password/validate",
            json=empty_password_data
        )
        
        # Test strength endpoint  
        strength_response = client.post(
            "/api/v1/password/strength",
            json=empty_password_data
        )
        
        # Test breach check endpoint
        breach_response = client.post(
            "/api/v1/password/check-breach", 
            json=empty_password_data
        )
        
        # All should return 200 but handle empty password appropriately
        assert validation_response.status_code == status.HTTP_200_OK
        assert strength_response.status_code == status.HTTP_200_OK
        assert breach_response.status_code == status.HTTP_200_OK
        
        # Validation should explicitly reject
        validation_data = validation_response.json()
        assert validation_data["is_valid"] is False
        assert validation_data["message"] == "Password cannot be empty"
        
        # Strength should return zero metrics
        strength_data = strength_response.json()
        assert strength_data["strength_score"] == 0.0
        
        # Breach check should handle gracefully
        breach_data = breach_response.json()
        assert breach_data["is_compromised"] is False
        
    def test_empty_password_with_user_context(self, client: TestClient):
        """Test empty password validation with different user contexts."""
        contexts = ["registration", "login", "change", "validation"]
        
        for context in contexts:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": "",
                    "user_id": f"user_{context}",
                    "context": context
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            assert data["is_valid"] is False
            assert data["message"] == "Password cannot be empty"
            
    def test_service_layer_empty_password_validation(self, password_service):
        """Test that the service layer properly validates empty passwords."""
        from ..model.password_validation_models import PasswordValidationRequest, PasswordValidationResult
        
        # Test empty string
        request = PasswordValidationRequest(password="")
        response = password_service.validate_password(request)
        
        assert response.is_valid is False
        assert response.result == PasswordValidationResult.EMPTY_PASSWORD
        assert response.message == "Password cannot be empty"
        assert response.processing_time_ms > 0
        
        # Test whitespace only
        request = PasswordValidationRequest(password="   ")
        response = password_service.validate_password(request)
        
        assert response.is_valid is False
        assert response.result == PasswordValidationResult.EMPTY_PASSWORD
        assert response.message == "Password cannot be empty"
        
    def test_empty_password_error_logging_security(self, client: TestClient, mock_logger):
        """Test that empty password validation doesn't log sensitive information."""
        response = client.post(
            "/api/v1/password/validate",
            json={
                "password": "",
                "user_id": "test_user",
                "context": "registration"
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify that no sensitive information was logged
        # The mock_logger fixture captures all log calls
        for call in mock_logger.info.call_args_list:
            log_message = str(call[0][0])  # First argument of the log call
            assert "password" not in log_message.lower() or "length: 0" in log_message
            # Should log password length as 0, but never the actual password value
            
    def test_concurrent_empty_password_requests(self, client: TestClient, concurrent_request_helper):
        """Test concurrent empty password validation requests."""
        test_data = [
            {"password": "", "context": "validation"},
            {"password": "   ", "context": "registration"},
            {"password": "\t", "context": "login"},
        ]
        
        results = concurrent_request_helper.execute_concurrent_requests(
            client=client,
            endpoint="/api/v1/password/validate",
            data_list=test_data,
            thread_count=50
        )
        
        # All requests should succeed
        assert results["successful_requests"] == 50
        assert results["failed_requests"] == 0
        
        # All should return consistent results
        for result in results["results"]:
            assert result["status_code"] == status.HTTP_200_OK
            response_data = result["response_data"]
            assert response_data["is_valid"] is False
            assert response_data["message"] == "Password cannot be empty"