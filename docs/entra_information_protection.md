# Integrating with Microsoft Entra Information Protection Service

This guide demonstrates how to integrate the RAG chat application with **Microsoft Entra Information Protection Service** (formerly Microsoft Information Protection or MIP) to provide advanced data security features including:

- **Sensitivity label management**: Retrieve and apply sensitivity labels from Entra
- **Protection policies**: Apply encryption and rights management to documents
- **Content inspection**: Scan and classify content automatically
- **Label enforcement**: Ensure proper labeling of AI-generated responses

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Configuration](#configuration)
- [Code Integration](#code-integration)
  - [Initialize Entra IS Client](#initialize-entra-is-client)
  - [Retrieve Label Policies](#retrieve-label-policies)
  - [Apply Protection Policies](#apply-protection-policies)
  - [Decrypt Protected Content](#decrypt-protected-content)
- [Usage Examples](#usage-examples)
- [Environment Variables](#environment-variables)
- [Troubleshooting](#troubleshooting)

## Overview

Microsoft Entra Information Protection Service provides a unified framework for protecting sensitive data across your organization. This integration allows the RAG chat application to:

1. **Label documents** with sensitivity classifications
2. **Apply protection** policies to control access
3. **Inspect content** for automatic classification
4. **Track usage** of protected documents

The integration builds on the existing `LabelHelper` class and extends it with Entra IS capabilities.

## Prerequisites

Before integrating with Entra Information Protection Service, ensure you have:

1. **Microsoft Entra ID tenant** with Information Protection enabled
2. **Azure account permissions**:
   - Permission to manage sensitivity labels in Microsoft Purview compliance portal
   - Permission to configure Information Protection policies
3. **App registrations** configured with appropriate API permissions:
   - `InformationProtectionPolicy.Read.All` - Read Information Protection policies
   - `UnifiedPolicy.UserOwnedFile.Read` - Read user-owned file protection info
   - `Content.SuperUser` - Decrypt and encrypt content (for service accounts)

## Configuration

### Step 1: Set up API Permissions

Navigate to your Azure AD app registration and add the following Microsoft Graph API permissions:

```
Microsoft Graph API (Delegated):
- InformationProtectionPolicy.Read
- UnifiedPolicy.UserOwnedFile.Read

Microsoft Graph API (Application):
- InformationProtectionPolicy.Read.All
- Content.SuperUser (for service-level operations)
```

### Step 2: Configure Environment Variables

Add the following environment variables to enable Entra IS integration:

```bash
# Enable Entra Information Protection integration
azd env set AZURE_ENABLE_INFORMATION_PROTECTION true

# Information Protection Service endpoint (optional, uses default if not set)
azd env set AZURE_INFORMATION_PROTECTION_ENDPOINT "https://api.aadrm.com"

# Enable content inspection for automatic classification
azd env set AZURE_ENABLE_CONTENT_INSPECTION true

# Enable protection policy enforcement
azd env set AZURE_ENFORCE_PROTECTION_POLICIES true
```

## Code Integration

### Initialize Entra IS Client

The following code snippet shows how to initialize the Entra Information Protection client:

```python
# File: app/backend/core/information_protection.py

import logging
from typing import Optional, List, Dict
from azure.identity.aio import DefaultAzureCredential
import aiohttp

class InformationProtectionClient:
    """
    Client for interacting with Microsoft Entra Information Protection Service.
    Provides methods for managing sensitivity labels and protection policies.
    """
    
    def __init__(
        self,
        tenant_id: str,
        credential: DefaultAzureCredential,
        endpoint: Optional[str] = None
    ):
        """
        Initialize the Information Protection client.
        
        Args:
            tenant_id: Azure AD tenant ID
            credential: Azure credential for authentication
            endpoint: Optional custom endpoint (defaults to public cloud)
        """
        self.tenant_id = tenant_id
        self.credential = credential
        self.endpoint = endpoint or "https://api.aadrm.com"
        self.graph_endpoint = "https://graph.microsoft.com/v1.0"
        self._access_token = None
        self._token_expiry = 0
        
    async def _get_access_token(self) -> str:
        """Get or refresh the access token for Graph API."""
        import time
        
        # Check if we have a valid cached token
        if self._access_token and time.time() < self._token_expiry - 300:
            return self._access_token
            
        # Get new token
        token = await self.credential.get_token(
            "https://graph.microsoft.com/.default"
        )
        self._access_token = token.token
        self._token_expiry = token.expires_on
        
        return self._access_token
    
    async def get_label_policies(self) -> List[Dict]:
        """
        Retrieve all available sensitivity label policies.
        
        Returns:
            List of label policy objects with their settings
        """
        try:
            access_token = await self._get_access_token()
            url = f"{self.graph_endpoint}/security/informationProtection/labelPolicies"
            
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json"
                }
                
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data.get("value", [])
                    else:
                        logging.error(
                            "Failed to retrieve label policies: %s - %s",
                            response.status,
                            await response.text()
                        )
                        return []
        except Exception as e:
            logging.exception("Error retrieving label policies: %s", e)
            return []
    
    async def evaluate_application(
        self,
        content: str,
        content_format: str = "text/plain",
        context: Optional[Dict] = None
    ) -> Optional[Dict]:
        """
        Evaluate which label should be applied to content based on policies.
        
        Args:
            content: The content to evaluate
            content_format: MIME type of the content
            context: Additional context for evaluation
            
        Returns:
            Recommended label information or None
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
                
                async with session.post(url, headers=headers, json=payload) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        logging.warning(
                            "Failed to evaluate label application: %s",
                            response.status
                        )
                        return None
        except Exception as e:
            logging.exception("Error evaluating label application: %s", e)
            return None
```

### Retrieve Label Policies

Integrate label policy retrieval into your existing authentication flow:

```python
# File: app/backend/core/labelhelper.py (enhancement)

async def get_active_policies(
    self,
    ip_client: 'InformationProtectionClient'
) -> List[Dict]:
    """
    Retrieve active Information Protection policies.
    
    Args:
        ip_client: InformationProtectionClient instance
        
    Returns:
        List of active protection policies
    """
    policies = await ip_client.get_label_policies()
    
    # Filter to active policies only
    active_policies = [
        policy for policy in policies
        if policy.get("isActive", False)
    ]
    
    # Cache policies for better performance
    for policy in active_policies:
        policy_id = policy.get("id")
        if policy_id:
            labels = policy.get("labels", [])
            for label in labels:
                label_id = label.get("id")
                if label_id:
                    # Cache the label from policy
                    sensitivity_label = SensitivityLabel(
                        id=label_id,
                        name=label.get("name", ""),
                        display_name=label.get("displayName"),
                        color=label.get("color", self._config.DEFAULT_COLOR),
                        priority=label.get("priority", 0),
                        icon=self._config.SUCCESS_ICON
                    )
                    self._cache_label(label_id, sensitivity_label)
    
    return active_policies
```

### Apply Protection Policies

Apply protection to AI-generated responses based on source document labels:

```python
# File: app/backend/core/information_protection.py (continued)

async def apply_protection(
    self,
    content: str,
    label_id: str,
    owner_email: Optional[str] = None
) -> Dict:
    """
    Apply protection policy to content based on sensitivity label.
    
    Args:
        content: Content to protect
        label_id: Sensitivity label ID to apply
        owner_email: Email of content owner
        
    Returns:
        Protected content metadata including encryption details
    """
    try:
        access_token = await self._get_access_token()
        url = f"{self.graph_endpoint}/security/informationProtection/encrypt"
        
        payload = {
            "labelId": label_id,
            "contentInfo": {
                "format": "text/plain",
                "identifier": None,
                "state": "use"
            },
            "ownerEmail": owner_email
        }
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    protection_info = await response.json()
                    logging.info(
                        "Successfully applied protection with label %s",
                        label_id
                    )
                    return protection_info
                else:
                    logging.error(
                        "Failed to apply protection: %s - %s",
                        response.status,
                        await response.text()
                    )
                    return {}
    except Exception as e:
        logging.exception("Error applying protection: %s", e)
        return {}
```

### Decrypt Protected Content

Decrypt protected documents when authorized users access them:

```python
# File: app/backend/core/information_protection.py (continued)

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
        Decrypted content or None if unauthorized
    """
    try:
        access_token = await self._get_access_token()
        url = f"{self.graph_endpoint}/security/informationProtection/decrypt"
        
        # Note: This is a simplified example. Production code should use
        # the full MIP SDK for proper content decryption
        
        payload = {
            "encryptedContent": protected_content.decode('utf-8'),
            "userEmail": user_email
        }
        
        async with aiohttp.ClientSession() as session:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            
            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    result = await response.json()
                    decrypted_content = result.get("decryptedContent")
                    if decrypted_content:
                        return decrypted_content.encode('utf-8')
                else:
                    logging.warning(
                        "Failed to decrypt content for user %s: %s",
                        user_email,
                        response.status
                    )
                    return None
    except Exception as e:
        logging.exception("Error decrypting content: %s", e)
        return None
```

## Usage Examples

### Example 1: Initialize and Use IP Client in app.py

```python
# File: app/backend/app.py (in setup_clients function)

# After setting up authentication helper...
if os.getenv("AZURE_ENABLE_INFORMATION_PROTECTION", "").lower() == "true":
    current_app.logger.info("Initializing Information Protection client")
    
    from core.information_protection import InformationProtectionClient
    
    ip_endpoint = os.getenv("AZURE_INFORMATION_PROTECTION_ENDPOINT")
    ip_client = InformationProtectionClient(
        tenant_id=AZURE_AUTH_TENANT_ID,
        credential=azure_credential,
        endpoint=ip_endpoint
    )
    
    # Retrieve and cache label policies
    policies = await label_helper.get_active_policies(ip_client)
    current_app.logger.info("Loaded %d active protection policies", len(policies))
    
    # Store client in app config for use in routes
    current_app.config["ip_client"] = ip_client
```

### Example 2: Apply Label to Chat Response

```python
# File: app/backend/approaches/approach.py (enhancement)

async def apply_response_protection(
    self,
    response_content: str,
    document_labels: List[DocumentLabel],
    user_email: str
) -> Dict:
    """
    Apply appropriate protection to chat response based on source documents.
    
    Note: Import current_app from quart at the top of your approach file:
    from quart import current_app
    
    Args:
        response_content: Generated chat response
        document_labels: Labels from source documents used
        user_email: Email of requesting user
        
    Returns:
        Protection metadata for the response
    """
    if not document_labels:
        return {}
    
    # Determine highest priority label
    highest_priority_label = max(
        document_labels,
        key=lambda dl: dl.label.priority
    ).label
    
    # Apply protection using IP client
    if ip_client := current_app.config.get("ip_client"):
        protection_info = await ip_client.apply_protection(
            content=response_content,
            label_id=highest_priority_label.id,
            owner_email=user_email
        )
        
        return {
            "labelId": highest_priority_label.id,
            "labelName": highest_priority_label.display_name,
            "protectionInfo": protection_info
        }
    
    return {}
```

### Example 3: Automatic Content Classification

```python
# File: app/backend/approaches/approach.py (enhancement)

async def classify_response_content(
    self,
    response_text: str,
    ip_client: 'InformationProtectionClient'
) -> Optional[str]:
    """
    Automatically classify response content and return recommended label.
    
    Args:
        response_text: Text content to classify
        ip_client: Information Protection client
        
    Returns:
        Recommended label ID or None
    """
    evaluation = await ip_client.evaluate_application(
        content=response_text,
        content_format="text/plain",
        context={
            "identifier": "chat-response",
            "metadata": [
                {"name": "source", "value": "ai-chat"}
            ]
        }
    )
    
    if evaluation:
        recommended_label = evaluation.get("recommendedLabel", {})
        label_id = recommended_label.get("labelId")
        
        if label_id:
            logging.info(
                "Auto-classification recommended label: %s (confidence: %s)",
                label_id,
                recommended_label.get("confidence", "N/A")
            )
            return label_id
    
    return None
```

## Environment Variables

Add these environment variables to your `.env` or `azd` environment:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `AZURE_ENABLE_INFORMATION_PROTECTION` | Enable Entra IS integration | `false` | No |
| `AZURE_INFORMATION_PROTECTION_ENDPOINT` | Custom IP service endpoint | `https://api.aadrm.com` | No |
| `AZURE_ENABLE_CONTENT_INSPECTION` | Enable automatic content classification | `false` | No |
| `AZURE_ENFORCE_PROTECTION_POLICIES` | Enforce protection on responses | `false` | No |
| `AZURE_IP_SUPER_USER_EMAIL` | Service account for decryption | None | Yes (if using decryption) |

## Troubleshooting

### Issue: Unable to retrieve label policies

**Solution**: Ensure your app registration has the `InformationProtectionPolicy.Read.All` permission and that admin consent has been granted.

### Issue: Protection policy application fails

**Solution**: Verify that:
1. The label ID is valid and exists in your tenant
2. The user has rights to apply the label
3. The app has appropriate permissions (`Content.SuperUser` for service accounts)

### Issue: Decryption fails for protected content

**Solution**: 
1. Confirm the user has access rights to the protected content
2. Verify the app is registered as a super user if acting on behalf of users
3. Check that the protection template is not corrupted

### Issue: Labels not appearing in UI

**Solution**:
1. Clear the label cache in `LabelHelper`
2. Verify Graph API connectivity
3. Check that labels are published in the Microsoft Purview compliance portal

## Best Practices

1. **Cache label metadata**: Use the built-in caching in `LabelHelper` to reduce API calls
2. **Handle failures gracefully**: Always provide fallback behavior when IP service is unavailable
3. **Minimize token requests**: Reuse access tokens until they expire
4. **Audit protection events**: Log all protection policy applications for compliance
5. **Test with different user roles**: Ensure protection works for all user types
6. **Monitor API quotas**: Be aware of Graph API throttling limits

## Additional Resources

- [Microsoft Information Protection SDK](https://learn.microsoft.com/information-protection/develop/)
- [Sensitivity labels overview](https://learn.microsoft.com/purview/sensitivity-labels)
- [Microsoft Graph Information Protection API](https://learn.microsoft.com/graph/api/resources/informationprotection)
- [Azure Information Protection documentation](https://learn.microsoft.com/azure/information-protection/)
