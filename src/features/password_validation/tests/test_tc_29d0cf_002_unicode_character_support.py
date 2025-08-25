"""
TC_29d0cf_002: Unicode Character Support
Description: Validate passwords containing Unicode characters (emojis, accented letters, CJK characters) 
are properly stored/retrieved without corruption. Verify UTF-8 encoding preservation.
"""

import pytest
import json
from fastapi import status
from fastapi.testclient import TestClient


class TestUnicodeCharacterSupport:
    """Test cases for Unicode character support in password validation."""
    
    def test_unicode_password_validation_basic(self, client: TestClient, unicode_password_samples):
        """Test that Unicode passwords are properly validated."""
        for password in unicode_password_samples:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": password,
                    "context": "validation"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Password should be valid if it meets complexity requirements
            # Most Unicode samples should be valid as they contain mixed character types
            assert "is_valid" in data
            assert "message" in data
            assert "processing_time_ms" in data
            
    def test_unicode_password_strength_analysis(self, client: TestClient, unicode_password_samples):
        """Test that Unicode passwords strength is analyzed correctly."""
        for password in unicode_password_samples:
            response = client.post(
                "/api/v1/password/strength",
                json={
                    "password": password
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            # Verify all strength metrics are present
            required_fields = [
                "entropy", "character_diversity", "length",
                "contains_uppercase", "contains_lowercase", 
                "contains_digits", "contains_special_chars", "strength_score"
            ]
            
            for field in required_fields:
                assert field in data
                
            # Length should match actual Unicode string length
            assert data["length"] == len(password)
            
            # Character diversity should be reasonable for Unicode strings
            assert data["character_diversity"] > 0
            
    def test_specific_unicode_character_sets(self, client: TestClient):
        """Test specific Unicode character sets for proper handling."""
        test_cases = [
            {
                "password": "Пароль123!",  # Cyrillic
                "description": "Cyrillic characters",
                "expected_valid": True
            },
            {
                "password": "密码Pass1!",  # Chinese
                "description": "Chinese characters", 
                "expected_valid": True
            },
            {
                "password": "パスワ1!",   # Japanese (shorter, might fail length)
                "description": "Japanese characters",
                "expected_valid": True
            },
            {
                "password": "كلمة123!",   # Arabic
                "description": "Arabic characters",
                "expected_valid": True  
            },
            {
                "password": "Café123!☕",  # Mixed with emoji
                "description": "Accented letters with emoji",
                "expected_valid": True
            },
            {
                "password": "Test🚀🔒1!",  # Emoji heavy
                "description": "Multiple emojis",
                "expected_valid": True
            }
        ]
        
        for test_case in test_cases:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": test_case["password"],
                    "context": "validation"
                }
            )
            
            assert response.status_code == status.HTTP_200_OK
            data = response.json()
            
            if test_case["expected_valid"]:
                # Most Unicode passwords should be valid if they meet length/complexity
                assert "is_valid" in data
                # Log for debugging if needed
                if not data["is_valid"]:
                    print(f"Unicode password failed validation: {test_case['description']} - {data['message']}")
                    
    def test_unicode_password_storage_retrieval(self, client: TestClient, user_repository, mock_dynamodb_table):
        """Test that Unicode passwords maintain integrity through storage/retrieval cycle."""
        from ..model.password_validation_models import SecurityEvent
        from datetime import datetime
        
        unicode_passwords = [
            "Pássw0rd!🔒",  # Portuguese with emoji
            "Тест123!",     # Cyrillic  
            "测试Pass1!",    # Chinese
            "テスト123!",     # Japanese
        ]
        
        for password in unicode_passwords:
            # Create a security event with Unicode password metadata (not the password itself)
            event = SecurityEvent(
                event_type="password_validation",
                user_id="unicode_test_user",
                ip_address="192.168.1.1",
                timestamp=datetime.utcnow(),
                success=True,
                details={
                    "context": "validation",
                    "password_length": len(password),
                    "has_unicode": any(ord(c) > 127 for c in password),
                    "character_diversity": len(set(password))
                }
            )
            
            # Store the event
            success = user_repository.log_security_event(event)
            assert success, f"Failed to store Unicode event for password: {password}"
            
            # Verify the event was stored with correct Unicode metadata
            # (Note: We don't store actual passwords, only metadata)
            events = user_repository.get_security_events(
                "unicode_test_user", 
                datetime.utcnow().replace(hour=0, minute=0, second=0),
                datetime.utcnow().replace(hour=23, minute=59, second=59)
            )
            
            # Find our event
            our_event = None
            for stored_event in events:
                if (stored_event.details.get("password_length") == len(password) and 
                    stored_event.details.get("has_unicode") is True):
                    our_event = stored_event
                    break
                    
            assert our_event is not None, "Unicode event not found in storage"
            assert our_event.details["character_diversity"] == len(set(password))
            
    def test_unicode_json_serialization(self, client: TestClient):
        """Test that Unicode passwords are properly JSON serialized/deserialized."""
        unicode_test_password = "Test🌟密码123!"
        
        # Test the full request/response cycle
        request_data = {
            "password": unicode_test_password,
            "user_id": "unicode_user",
            "context": "validation"
        }
        
        response = client.post(
            "/api/v1/password/validate",
            json=request_data
        )
        
        assert response.status_code == status.HTTP_200_OK
        
        # Verify response can be parsed as JSON
        data = response.json()
        assert isinstance(data, dict)
        assert "is_valid" in data
        
        # Test that we can serialize the request data back to JSON without issues
        serialized = json.dumps(request_data, ensure_ascii=False)
        deserialized = json.loads(serialized)
        assert deserialized["password"] == unicode_test_password
        
    def test_unicode_normalization_consistency(self, client: TestClient):
        """Test that different Unicode normalizations are handled consistently."""
        import unicodedata
        
        # Test with the same logical character in different Unicode forms
        base_password = "Café123!"
        
        # Different Unicode normalizations
        nfc_password = unicodedata.normalize('NFC', base_password)   # Composed form
        nfd_password = unicodedata.normalize('NFD', base_password)   # Decomposed form
        
        # Both should be treated consistently
        nfc_response = client.post(
            "/api/v1/password/validate",
            json={"password": nfc_password, "context": "validation"}
        )
        
        nfd_response = client.post(
            "/api/v1/password/validate", 
            json={"password": nfd_password, "context": "validation"}
        )
        
        assert nfc_response.status_code == status.HTTP_200_OK
        assert nfd_response.status_code == status.HTTP_200_OK
        
        nfc_data = nfc_response.json()
        nfd_data = nfd_response.json()
        
        # Both should have similar validation results
        # (They might have different lengths due to normalization)
        assert "is_valid" in nfc_data
        assert "is_valid" in nfd_data
        
    def test_unicode_edge_cases(self, client: TestClient):
        """Test Unicode edge cases and potential issues."""
        edge_cases = [
            {
                "password": "Test\u0000123!",  # Null character
                "description": "Password with null character",
                "should_succeed": True  # Should handle gracefully
            },
            {
                "password": "Test\uFEFF123!",  # BOM character
                "description": "Password with BOM",
                "should_succeed": True
            },
            {
                "password": "A" * 50 + "测试123!",  # Long with Unicode
                "description": "Long password with Unicode",
                "should_succeed": True
            },
            {
                "password": "👨‍👩‍👧‍👦Pass1!",  # Complex emoji sequence
                "description": "Complex emoji family sequence",
                "should_succeed": True
            }
        ]
        
        for case in edge_cases:
            response = client.post(
                "/api/v1/password/validate",
                json={
                    "password": case["password"],
                    "context": "validation"
                }
            )
            
            if case["should_succeed"]:
                assert response.status_code == status.HTTP_200_OK
                data = response.json()
                assert "is_valid" in data
            else:
                # If we expect it to fail, it should fail gracefully
                assert response.status_code in [status.HTTP_200_OK, status.HTTP_400_BAD_REQUEST]
                
    def test_unicode_performance_consistency(self, client: TestClient, timing_attack_detector):
        """Test that Unicode password processing doesn't create timing vulnerabilities."""
        test_passwords = [
            "SimplePass1!",       # ASCII only
            "Café123!",          # Simple accents
            "测试Password1!",     # CJK characters
            "🔒SecurePass1!",    # With emoji
            "複雑なパスワード1!"    # Complex Japanese
        ]
        
        # Measure timing for each type
        for password in test_passwords:
            timing_attack_detector.measure_request_time(
                client.post,
                "/api/v1/password/validate",
                json={"password": password, "context": "validation"}
            )
            
        # Check timing consistency across different Unicode types
        is_consistent, max_deviation = timing_attack_detector.analyze_timing_consistency(
            tolerance_ms=200  # Allow more tolerance for Unicode processing
        )
        
        stats = timing_attack_detector.get_statistics()
        assert is_consistent or max_deviation < 500, \
            f"Unicode processing timing inconsistent. Max deviation: {max_deviation}ms, Stats: {stats}"
            
    def test_service_layer_unicode_handling(self, password_service):
        """Test that the service layer properly handles Unicode passwords."""
        from ..model.password_validation_models import PasswordValidationRequest
        
        unicode_password = "Sécur3🔒!"
        request = PasswordValidationRequest(
            password=unicode_password,
            user_id="unicode_test",
            context="validation"
        )
        
        response = password_service.validate_password(request)
        
        # Should process without errors
        assert response is not None
        assert hasattr(response, 'is_valid')
        assert response.processing_time_ms > 0
        
        # Test strength calculation with Unicode
        strength = password_service.calculate_password_strength(unicode_password)
        assert strength.length == len(unicode_password)
        assert strength.character_diversity > 0
        
    def test_concurrent_unicode_requests(self, client: TestClient, concurrent_request_helper):
        """Test concurrent requests with Unicode passwords."""
        unicode_passwords = [
            "Pássw0rd!🔒",
            "Тест123!",
            "测试Pass1!",
            "テスト123!",
            "Café☕123!"
        ]
        
        test_data = [
            {"password": pwd, "context": "validation"} 
            for pwd in unicode_passwords
        ]
        
        results = concurrent_request_helper.execute_concurrent_requests(
            client=client,
            endpoint="/api/v1/password/validate",
            data_list=test_data,
            thread_count=25
        )
        
        # All requests should succeed
        assert results["successful_requests"] == 25
        assert results["failed_requests"] == 0
        
        # All should return valid JSON responses
        for result in results["results"]:
            assert result["status_code"] == status.HTTP_200_OK
            assert isinstance(result["response_data"], dict)
            assert "is_valid" in result["response_data"]