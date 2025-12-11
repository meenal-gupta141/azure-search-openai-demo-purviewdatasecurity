"""
Microsoft Entra Information Protection Service Integration

This module provides integration with Microsoft Entra Information Protection Service
(formerly Microsoft Information Protection or MIP) for managing sensitivity labels,
protection policies, and content encryption.

Key Features:
- Retrieve and manage sensitivity label policies
- Apply protection policies to content
- Decrypt protected content for authorized users
- Automatic content classification based on policies
- Integration with existing LabelHelper for unified label management
"""

import logging
import time
from typing import Optional, List, Dict, Any
import aiohttp
from azure.identity.aio import DefaultAzureCredential


class InformationProtectionError(Exception):
    """Base exception for Information Protection service errors"""
    pass


class InformationProtectionClient:
    """
    Client for interacting with Microsoft Entra Information Protection Service.
    
    This client provides methods for:
    - Managing sensitivity labels and policies
    - Applying protection to content
    - Decrypting protected content
    - Evaluating automatic label recommendations
    
    Example:
        ```python
        from azure.identity.aio import DefaultAzureCredential
        
        credential = DefaultAzureCredential()
        ip_client = InformationProtectionClient(
            tenant_id="your-tenant-id",
            credential=credential
        )
        
        # Get label policies
        policies = await ip_client.get_label_policies()
        
        # Apply protection
        protection_info = await ip_client.apply_protection(
            content="Sensitive data",
            label_id="label-guid",
            owner_email="user@example.com"
        )
        ```
    """
    
    def __init__(
        self,
        tenant_id: str,
        credential: DefaultAzureCredential,
        endpoint: Optional[str] = None,
        timeout: float = 30.0
    ):
        """
        Initialize the Information Protection client.
        
        Args:
            tenant_id: Azure AD tenant ID
            credential: Azure credential for authentication
            endpoint: Optional custom endpoint (defaults to public cloud)
            timeout: HTTP request timeout in seconds (default: 30.0)
        """
        self.tenant_id = tenant_id
        self.credential = credential
        self.endpoint = endpoint or "https://api.aadrm.com"
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self.timeout = timeout
        self._access_token: Optional[str] = None
        self._token_expiry: float = 0
        self._logger = logging.getLogger(__name__)
        
    async def _get_access_token(self) -> str:
        """
        Get or refresh the access token for Microsoft Graph API.
        
        Tokens are cached and only refreshed when they expire (with 5 min buffer).
        
        Returns:
            Valid access token string
            
        Raises:
            InformationProtectionError: If token acquisition fails
        """
        # Check if we have a valid cached token (5 min buffer before expiry)
        if self._access_token and time.time() < self._token_expiry - 300:
            return self._access_token
            
        try:
            # Get new token
            token = await self.credential.get_token(
                "https://graph.microsoft.com/.default"
            )
            self._access_token = token.token
            self._token_expiry = token.expires_on
            
            self._logger.debug("Successfully acquired access token")
            return self._access_token
        except Exception as e:
            self._logger.error("Failed to acquire access token: %s", e)
            raise InformationProtectionError(
                f"Failed to acquire access token: {str(e)}"
            ) from e
    
    async def get_label_policies(self) -> List[Dict[str, Any]]:
        """
        Retrieve all available sensitivity label policies from Entra IS.
        
        Label policies define the sensitivity labels available in the organization
        and their associated protection settings.
        
        Returns:
            List of label policy objects with their settings. Each policy contains:
            - id: Policy identifier
            - name: Policy name
            - isActive: Whether the policy is currently active
            - labels: List of sensitivity labels in this policy
            
        Example:
            ```python
            policies = await ip_client.get_label_policies()
            for policy in policies:
                print(f"Policy: {policy['name']}")
                for label in policy.get('labels', []):
                    print(f"  - {label['displayName']}")
            ```
        """
        try:
            access_token = await self._get_access_token()
            url = f"{self.graph_endpoint}/security/informationProtection/labelPolicies"
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                    "User-Agent": "Azure-Search-OpenAI-Demo/1.0"
                }
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        data = await response.json()
                        policies = data.get("value", [])
                        self._logger.info("Retrieved %d label policies", len(policies))
                        return policies
                    else:
                        error_text = await response.text()
                        self._logger.error(
                            "Failed to retrieve label policies: %s - %s",
                            response.status,
                            error_text
                        )
                        return []
        except Exception as e:
            self._logger.exception("Error retrieving label policies: %s", e)
            return []
    
    async def get_label_by_id(self, label_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a specific sensitivity label by its ID.
        
        Args:
            label_id: The GUID of the sensitivity label
            
        Returns:
            Label object or None if not found. Contains:
            - id: Label identifier
            - name: Label name
            - displayName: Localized display name
            - color: Visual color code
            - priority: Priority for label inheritance
            - parent: Parent label (if sublabel)
        """
        try:
            access_token = await self._get_access_token()
            url = f"{self.graph_endpoint}/security/informationProtection/labels/{label_id}"
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
                
                async with session.get(url, headers=headers, timeout=self.timeout) as response:
                    if response.status == 200:
                        label = await response.json()
                        self._logger.debug("Retrieved label: %s", label.get("displayName"))
                        return label
                    else:
                        self._logger.warning(
                            "Failed to retrieve label %s: %s",
                            label_id,
                            response.status
                        )
                        return None
        except Exception as e:
            self._logger.exception("Error retrieving label %s: %s", label_id, e)
            return None
    
    async def evaluate_application(
        self,
        content: str,
        content_format: str = "text/plain",
        context: Optional[Dict[str, Any]] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Evaluate which label should be applied to content based on configured policies.
        
        This uses automatic classification rules to recommend appropriate sensitivity
        labels for the given content.
        
        Args:
            content: The content to evaluate
            content_format: MIME type of the content (e.g., "text/plain", "application/json")
            context: Additional context for evaluation including:
                - identifier: Content identifier
                - metadata: List of metadata name/value pairs
                
        Returns:
            Evaluation result containing:
            - recommendedLabel: Suggested label with confidence score
            - actions: Recommended actions to apply
            or None if evaluation fails
            
        Example:
            ```python
            result = await ip_client.evaluate_application(
                content="SSN: 123-45-6789",
                content_format="text/plain",
                context={"identifier": "chat-message"}
            )
            if result:
                recommended = result.get("recommendedLabel", {})
                print(f"Recommended label: {recommended.get('labelId')}")
            ```
        """
        try:
            access_token = await self._get_access_token()
            url = f"{self.graph_endpoint}/security/informationProtection/policy/labels/evaluateApplication"
            
            payload = {
                "contentInfo": {
                    "format": content_format,
                    "identifier": context.get("identifier") if context else None,
                    "metadata": context.get("metadata", []) if context else []
                },
                "labelingOptions": {
                    "assignmentMethod": "auto",
                    "extendedProperties": []
                }
            }
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
                
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self._logger.debug("Content evaluation completed successfully")
                        return result
                    else:
                        self._logger.warning(
                            "Failed to evaluate label application: %s - %s",
                            response.status,
                            await response.text()
                        )
                        return None
        except Exception as e:
            self._logger.exception("Error evaluating label application: %s", e)
            return None
    
    async def apply_protection(
        self,
        content: str,
        label_id: str,
        owner_email: Optional[str] = None,
        metadata: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        """
        Apply protection policy to content based on sensitivity label.
        
        This encrypts the content according to the protection settings defined
        in the sensitivity label.
        
        Args:
            content: Content to protect
            label_id: Sensitivity label ID to apply
            owner_email: Email of content owner (optional)
            metadata: Additional metadata to attach (optional)
            
        Returns:
            Protected content metadata including:
            - publishingLicense: Protection license
            - encryptedContent: Encrypted content (if applicable)
            - contentId: Unique content identifier
            Empty dict if protection fails
            
        Example:
            ```python
            protection = await ip_client.apply_protection(
                content="Confidential information",
                label_id="label-guid",
                owner_email="user@example.com",
                metadata=[{"name": "source", "value": "ai-chat"}]
            )
            ```
            
        Note:
            This is a simplified implementation. For production use, consider
            using the full MIP SDK for comprehensive protection features.
        """
        try:
            access_token = await self._get_access_token()
            
            # Note: The actual Graph API endpoint for encryption may vary
            # This is a conceptual implementation based on MIP SDK patterns
            url = f"{self.graph_endpoint}/security/informationProtection/encrypt"
            
            payload = {
                "labelId": label_id,
                "contentInfo": {
                    "format": "text/plain",
                    "identifier": None,
                    "state": "use",
                    "metadata": metadata or []
                },
                "ownerEmail": owner_email
            }
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
                
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        protection_info = await response.json()
                        self._logger.info(
                            "Successfully applied protection with label %s",
                            label_id
                        )
                        return protection_info
                    else:
                        error_text = await response.text()
                        self._logger.error(
                            "Failed to apply protection: %s - %s",
                            response.status,
                            error_text
                        )
                        return {}
        except Exception as e:
            self._logger.exception("Error applying protection: %s", e)
            return {}
    
    async def decrypt_content(
        self,
        protected_content: bytes,
        user_email: str
    ) -> Optional[bytes]:
        """
        Decrypt protected content for an authorized user.
        
        Args:
            protected_content: Encrypted content bytes
            user_email: Email of user requesting access
            
        Returns:
            Decrypted content bytes or None if unauthorized/failed
            
        Note:
            This is a simplified example. Production implementations should use
            the full MIP SDK for proper content decryption with rights management.
            
        Example:
            ```python
            decrypted = await ip_client.decrypt_content(
                protected_content=encrypted_bytes,
                user_email="user@example.com"
            )
            if decrypted:
                print("Successfully decrypted content")
            ```
        """
        try:
            access_token = await self._get_access_token()
            
            # Note: Actual decryption typically requires the MIP SDK
            # This is a conceptual implementation
            url = f"{self.graph_endpoint}/security/informationProtection/decrypt"
            
            # Convert bytes to string for JSON payload
            try:
                content_str = protected_content.decode('utf-8')
            except UnicodeDecodeError:
                # If not UTF-8, use base64 encoding
                import base64
                content_str = base64.b64encode(protected_content).decode('ascii')
            
            payload = {
                "encryptedContent": content_str,
                "userEmail": user_email
            }
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json",
                    "Accept": "application/json"
                }
                
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        decrypted_content = result.get("decryptedContent")
                        if decrypted_content:
                            self._logger.info(
                                "Successfully decrypted content for user %s",
                                user_email
                            )
                            return decrypted_content.encode('utf-8')
                    else:
                        self._logger.warning(
                            "Failed to decrypt content for user %s: %s - %s",
                            user_email,
                            response.status,
                            await response.text()
                        )
                        return None
        except Exception as e:
            self._logger.exception("Error decrypting content: %s", e)
            return None
    
    async def extract_label_from_content(
        self,
        content: str,
        content_format: str = "text/plain"
    ) -> Optional[str]:
        """
        Extract existing sensitivity label ID from content metadata.
        
        Args:
            content: Content to inspect
            content_format: MIME type of the content
            
        Returns:
            Label ID if found, None otherwise
        """
        try:
            access_token = await self._get_access_token()
            url = f"{self.graph_endpoint}/security/informationProtection/policy/labels/extractLabel"
            
            payload = {
                "contentInfo": {
                    "format": content_format,
                    "identifier": None,
                    "state": "rest"
                }
            }
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Content-Type": "application/json"
                }
                
                async with session.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=self.timeout
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get("labelId")
                    else:
                        self._logger.debug(
                            "No label found in content: %s",
                            response.status
                        )
                        return None
        except Exception as e:
            self._logger.exception("Error extracting label from content: %s", e)
            return None
    
    async def close(self):
        """
        Clean up resources.
        
        Call this method when done using the client to ensure proper cleanup.
        """
        # Close credential if it has a close method
        if hasattr(self.credential, 'close'):
            await self.credential.close()
        
        self._access_token = None
        self._logger.debug("Information Protection client closed")
