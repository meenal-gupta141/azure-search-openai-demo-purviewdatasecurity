# Entra Information Protection Service - Quick Start Guide

This guide provides a quick reference for integrating Microsoft Entra Information Protection Service (IS) with your RAG chat application.

## Quick Setup

### 1. Environment Variables

Set these environment variables before deployment:

```bash
# Enable Entra IS integration
azd env set AZURE_ENABLE_INFORMATION_PROTECTION true

# Optional: Custom endpoint
azd env set AZURE_INFORMATION_PROTECTION_ENDPOINT "https://api.aadrm.com"

# Optional: Enable content inspection
azd env set AZURE_ENABLE_CONTENT_INSPECTION true

# Optional: Enforce protection policies
azd env set AZURE_ENFORCE_PROTECTION_POLICIES true
```

### 2. Azure AD Permissions

Add these API permissions to your app registration:

**Microsoft Graph (Delegated):**
- `InformationProtectionPolicy.Read`
- `UnifiedPolicy.UserOwnedFile.Read`

**Microsoft Graph (Application):**
- `InformationProtectionPolicy.Read.All`
- `Content.SuperUser` (for service-level operations)

### 3. Code Integration

#### In `app.py` - Setup Phase

```python
from core.information_protection import InformationProtectionClient

# In the setup_clients() function, after setting up auth_helper:
if os.getenv("AZURE_ENABLE_INFORMATION_PROTECTION", "").lower() == "true":
    from core.information_protection import InformationProtectionClient
    
    ip_client = InformationProtectionClient(
        tenant_id=AZURE_AUTH_TENANT_ID,
        credential=azure_credential
    )
    
    # Load policies and cache labels
    policies = await label_helper.get_active_policies(ip_client)
    current_app.logger.info("Loaded %d IP policies", len(policies))
    
    # Store in app config
    current_app.config["ip_client"] = ip_client
```

#### In Approach Classes - Usage Phase

```python
# Add to your approach class (e.g., ChatReadRetrieveReadApproach)
# Note: Import current_app from quart at the top of your file:
# from quart import current_app

async def run(self, messages, context, session_state):
    # Your existing code...
    response = await self._generate_response(...)
    
    # Apply protection if IP client is available
    if ip_client := current_app.config.get("ip_client"):
        # Extract labels from source documents
        document_labels = await self.label_helper.extract_labels_from_search_results(
            search_results=self.search_results,
            user_access_token=context.get("auth_claims", {}).get("graph_access_token")
        )
        
        # Apply protection based on highest priority label
        if document_labels:
            highest_label = max(document_labels, key=lambda dl: dl.label.priority).label
            
            protection_info = await ip_client.apply_protection(
                content=response["answer"],
                label_id=highest_label.id,
                owner_email=context.get("auth_claims", {}).get("email", "")
            )
            
            response["protection"] = {
                "labelId": highest_label.id,
                "labelName": highest_label.display_name,
                "applied": bool(protection_info)
            }
    
    return response
```

## Code Snippets

### Snippet 1: Initialize IP Client

```python
from core.information_protection import InformationProtectionClient
from azure.identity.aio import DefaultAzureCredential

credential = DefaultAzureCredential()
ip_client = InformationProtectionClient(
    tenant_id="your-tenant-id",
    credential=credential
)
```

### Snippet 2: Get Label Policies

```python
# Retrieve all label policies
policies = await ip_client.get_label_policies()

# Filter to active policies
active_policies = [p for p in policies if p.get("isActive", False)]

# Print policy labels
for policy in active_policies:
    print(f"Policy: {policy['name']}")
    for label in policy.get("labels", []):
        print(f"  - {label['displayName']} (priority: {label['priority']})")
```

### Snippet 3: Apply Protection to Content

```python
# Apply sensitivity label protection
protection_info = await ip_client.apply_protection(
    content="Your sensitive content here",
    label_id="label-guid-here",
    owner_email="user@example.com",
    metadata=[
        {"name": "source", "value": "ai-chat"},
        {"name": "created", "value": "2024-01-01"}
    ]
)

if protection_info:
    print("Protection applied successfully")
```

### Snippet 4: Auto-Classify Content

```python
# Evaluate content for automatic label recommendation
evaluation = await ip_client.evaluate_application(
    content="This document contains SSN: 123-45-6789",
    content_format="text/plain",
    context={
        "identifier": "chat-response",
        "metadata": [{"name": "source", "value": "ai"}]
    }
)

if evaluation:
    recommended = evaluation.get("recommendedLabel", {})
    if recommended:
        label_id = recommended.get("labelId")
        confidence = recommended.get("confidence", 0)
        print(f"Recommended: {label_id} (confidence: {confidence})")
```

### Snippet 5: Integrate with LabelHelper

```python
from core.labelhelper import LabelHelper

label_helper = LabelHelper()

# Load policies and cache labels using IP client
policies = await label_helper.get_active_policies(ip_client)

# Resolve label with IP client fallback
label = await label_helper.resolve_label_with_ip_client(
    label_id="your-label-guid",
    ip_client=ip_client
)

if label:
    print(f"Label: {label.display_name} (priority: {label.priority})")
```

## Testing

Run the test script to verify your integration:

```bash
# Set required environment variables
export AZURE_AUTH_TENANT_ID="your-tenant-id"

# Run the test
python app/backend/examples/entra_is_integration_examples.py
```

Expected output:
```
Test 1: Retrieving label policies...
✓ Retrieved 2 policies

Test 2: Retrieving label...
✓ Retrieved label: Confidential

Test 3: Testing content evaluation...
✓ Content evaluation successful

✓ All tests completed successfully!
```

## Common Issues

### Issue: "Failed to acquire access token"
**Solution**: Ensure your app registration has the required API permissions and admin consent has been granted.

### Issue: "No label policies returned"
**Solution**: Verify that:
1. Labels are published in Microsoft Purview compliance portal
2. Your tenant has Information Protection enabled
3. The tenant ID is correct

### Issue: "Protection application failed"
**Solution**: Check that:
1. The label ID is valid and exists
2. The user has rights to apply the label
3. Content format is supported

## Next Steps

- Read the full documentation: [entra_information_protection.md](entra_information_protection.md)
- Review code examples: [entra_is_integration_examples.py](../app/backend/examples/entra_is_integration_examples.py)
- Configure advanced features like automatic classification and content inspection

## Resources

- [Microsoft Information Protection SDK](https://learn.microsoft.com/information-protection/develop/)
- [Sensitivity Labels Overview](https://learn.microsoft.com/purview/sensitivity-labels)
- [Graph API Information Protection](https://learn.microsoft.com/graph/api/resources/informationprotection)
