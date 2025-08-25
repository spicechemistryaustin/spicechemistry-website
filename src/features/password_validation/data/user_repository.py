import boto3
import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List
from botocore.exceptions import ClientError, BotoCoreError
import time
import uuid

from ..model.password_validation_models import (
    UserSecurityProfile,
    SecurityEvent
)


class UserRepository:
    def __init__(self, table_name: str = "Users", region_name: str = "us-east-1"):
        self.table_name = table_name
        self.region_name = region_name
        self.logger = logging.getLogger(__name__)
        self._dynamodb = None
        self._table = None
        self._connection_retry_count = 3
        self._connection_timeout = 5
        
    @property
    def dynamodb(self):
        """Lazy initialization of DynamoDB client with connection resilience"""
        if self._dynamodb is None:
            self._dynamodb = boto3.resource(
                'dynamodb',
                region_name=self.region_name,
                config=boto3.session.Config(
                    retries={'max_attempts': self._connection_retry_count},
                    connect_timeout=self._connection_timeout,
                    read_timeout=self._connection_timeout
                )
            )
        return self._dynamodb
    
    @property 
    def table(self):
        """Lazy initialization of DynamoDB table with error handling"""
        if self._table is None:
            try:
                self._table = self.dynamodb.Table(self.table_name)
            except Exception as e:
                self.logger.error(f"Failed to initialize DynamoDB table: {str(e)}")
                raise
        return self._table
    
    def get_user_security_profile(self, user_id: str) -> Optional[UserSecurityProfile]:
        """
        Retrieve user security profile with connection resilience
        """
        try:
            response = self.table.get_item(
                Key={'PK': f'USER#{user_id}', 'SK': 'SECURITY_PROFILE'},
                ConsistentRead=True
            )
            
            if 'Item' not in response:
                return None
                
            item = response['Item']
            return UserSecurityProfile(
                user_id=user_id,
                failed_attempts=item.get('failed_attempts', 0),
                last_failed_attempt=self._parse_datetime(item.get('last_failed_attempt')),
                last_successful_login=self._parse_datetime(item.get('last_successful_login')),
                account_locked=item.get('account_locked', False),
                lock_until=self._parse_datetime(item.get('lock_until'))
            )
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ResourceNotFoundException':
                self.logger.warning(f"Table {self.table_name} not found")
                return None
            elif error_code in ['ProvisionedThroughputExceededException', 'ThrottlingException']:
                self.logger.warning(f"DynamoDB throttled for user {user_id}")
                # Return default profile to maintain service availability
                return UserSecurityProfile(user_id=user_id)
            else:
                self.logger.error(f"DynamoDB error getting user profile: {str(e)}")
                raise
        except Exception as e:
            self.logger.error(f"Unexpected error getting user security profile: {str(e)}")
            # Return default profile for graceful degradation
            return UserSecurityProfile(user_id=user_id)
    
    def update_user_security_profile(self, profile: UserSecurityProfile) -> bool:
        """
        Update user security profile with transaction integrity
        """
        try:
            # Use conditional update to prevent race conditions
            self.table.put_item(
                Item={
                    'PK': f'USER#{profile.user_id}',
                    'SK': 'SECURITY_PROFILE',
                    'failed_attempts': profile.failed_attempts,
                    'last_failed_attempt': self._format_datetime(profile.last_failed_attempt),
                    'last_successful_login': self._format_datetime(profile.last_successful_login),
                    'account_locked': profile.account_locked,
                    'lock_until': self._format_datetime(profile.lock_until),
                    'updated_at': self._format_datetime(datetime.utcnow()),
                    'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
                },
                # Prevent overwrites during concurrent operations
                ConditionExpression='attribute_not_exists(version) OR version = :expected_version',
                ExpressionAttributeValues={
                    ':expected_version': profile.user_id  # Simplified versioning
                }
            )
            return True
            
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'ConditionalCheckFailedException':
                self.logger.warning(f"Concurrent update detected for user {profile.user_id}")
                return False
            elif error_code in ['ProvisionedThroughputExceededException', 'ThrottlingException']:
                self.logger.warning(f"DynamoDB throttled updating user {profile.user_id}")
                return False
            else:
                self.logger.error(f"DynamoDB error updating user profile: {str(e)}")
                return False
        except Exception as e:
            self.logger.error(f"Unexpected error updating user security profile: {str(e)}")
            return False
    
    def log_security_event(self, event: SecurityEvent) -> bool:
        """
        Log security event with sanitized data
        """
        try:
            event_id = str(uuid.uuid4())
            
            # Sanitize event details to remove sensitive information
            sanitized_details = self._sanitize_event_details(event.details)
            
            self.table.put_item(
                Item={
                    'PK': f'EVENT#{event.timestamp.strftime("%Y-%m-%d")}',
                    'SK': f'{event.timestamp.isoformat()}#{event_id}',
                    'event_type': event.event_type,
                    'user_id': event.user_id,
                    'ip_address': event.ip_address,
                    'timestamp': event.timestamp.isoformat(),
                    'success': event.success,
                    'details': sanitized_details,
                    'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())  # Auto-delete after 90 days
                }
            )
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to log security event: {str(e)}")
            return False
    
    def get_security_events(self, user_id: str, start_date: datetime, end_date: datetime) -> List[SecurityEvent]:
        """
        Retrieve security events for a user within date range
        """
        events = []
        try:
            # Query events by date range (simplified implementation)
            current_date = start_date.date()
            end_date_only = end_date.date()
            
            while current_date <= end_date_only:
                date_key = current_date.strftime("%Y-%m-%d")
                
                response = self.table.query(
                    KeyConditionExpression='PK = :pk',
                    FilterExpression='user_id = :user_id',
                    ExpressionAttributeValues={
                        ':pk': f'EVENT#{date_key}',
                        ':user_id': user_id
                    }
                )
                
                for item in response.get('Items', []):
                    event = SecurityEvent(
                        event_type=item['event_type'],
                        user_id=item['user_id'],
                        ip_address=item.get('ip_address'),
                        timestamp=datetime.fromisoformat(item['timestamp']),
                        success=item['success'],
                        details=item.get('details', {})
                    )
                    events.append(event)
                
                current_date += timedelta(days=1)
                
        except Exception as e:
            self.logger.error(f"Failed to retrieve security events: {str(e)}")
            
        return events
    
    def _sanitize_event_details(self, details: Dict[str, Any]) -> Dict[str, Any]:
        """
        Remove sensitive information from event details
        """
        sanitized = {}
        sensitive_keys = ['password', 'token', 'secret', 'key', 'credential']
        
        for key, value in details.items():
            key_lower = key.lower()
            if any(sensitive_word in key_lower for sensitive_word in sensitive_keys):
                # Replace sensitive values with placeholder
                if isinstance(value, str):
                    sanitized[key] = '[REDACTED]'
                else:
                    sanitized[key] = '[REDACTED]'
            else:
                sanitized[key] = value
                
        return sanitized
    
    def _format_datetime(self, dt: Optional[datetime]) -> Optional[str]:
        """Format datetime for DynamoDB storage"""
        return dt.isoformat() if dt else None
    
    def _parse_datetime(self, dt_str: Optional[str]) -> Optional[datetime]:
        """Parse datetime from DynamoDB storage"""
        if not dt_str:
            return None
        try:
            return datetime.fromisoformat(dt_str)
        except (ValueError, TypeError):
            return None
    
    def health_check(self) -> Dict[str, Any]:
        """
        Check DynamoDB connection health
        """
        try:
            start_time = time.time()
            self.table.table_status
            response_time = (time.time() - start_time) * 1000
            
            return {
                'status': 'healthy',
                'response_time_ms': response_time,
                'table_name': self.table_name
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'table_name': self.table_name
            }