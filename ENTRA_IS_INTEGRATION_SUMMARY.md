# Entra Information Protection Service Integration - Summary

## Overview

This integration adds Microsoft Entra Information Protection Service (IS) capabilities to the Azure Search OpenAI Demo application. The integration enables:

1. **Sensitivity label management** via Microsoft Graph API
2. **Protection policy enforcement** on AI-generated responses
3. **Automatic content classification** based on configured rules
4. **Content encryption/decryption** for authorized users
5. **Label inheritance** from source documents to responses

## What Was Added

### 1. Core Components

#### `app/backend/core/information_protection.py`
A comprehensive client for Microsoft Entra Information Protection Service with:
- `InformationProtectionClient` class for all IP operations
- Methods for retrieving label policies
- Content protection application
- Content decryption capabilities
- Automatic label evaluation

**Key Methods:**
- `get_label_policies()` - Retrieve all label policies
- `get_label_by_id(label_id)` - Get specific label details
- `evaluate_application(content)` - Auto-classify content
- `apply_protection(content, label_id)` - Apply protection
- `decrypt_content(protected_content)` - Decrypt for authorized users

#### Enhanced `app/backend/core/labelhelper.py`
Extended existing LabelHelper with:
- `get_active_policies(ip_client)` - Load policies from Entra IS
- `resolve_label_with_ip_client(label_id, ip_client)` - Enhanced label resolution with IP fallback

### 2. Documentation

#### `docs/entra_information_protection.md` (20KB)
Complete integration guide including:
- Prerequisites and configuration steps
- Detailed code examples
- API permission requirements
- Environment variable reference
- Troubleshooting guide
- Best practices

#### `docs/entra_is_quickstart.md` (7KB)
Quick reference guide with:
- Fast setup instructions
- Ready-to-use code snippets
- Common issues and solutions
- Testing procedures

### 3. Examples

#### `app/backend/examples/entra_is_integration_examples.py` (10KB)
Practical code examples showing:
- How to initialize the IP client in app.py
- Applying protection to chat responses
- Automatic content classification
- Integration with existing approaches
- Testing and validation

## How to Use

### Quick Start

1. **Set environment variables:**
```bash
azd env set AZURE_ENABLE_INFORMATION_PROTECTION true
azd env set AZURE_ENABLE_CONTENT_INSPECTION true
```

2. **Configure API permissions** in Azure AD app registration:
   - `InformationProtectionPolicy.Read.All`
   - `UnifiedPolicy.UserOwnedFile.Read`
   - `Content.SuperUser`

3. **Add to app.py setup:**
```python
from core.information_protection import InformationProtectionClient

if os.getenv("AZURE_ENABLE_INFORMATION_PROTECTION", "").lower() == "true":
    ip_client = InformationProtectionClient(
        tenant_id=AZURE_AUTH_TENANT_ID,
        credential=azure_credential
    )
    policies = await label_helper.get_active_policies(ip_client)
    current_app.config["ip_client"] = ip_client
```

4. **Use in approaches:**
```python
# Apply protection based on source document labels
if ip_client := current_app.config.get("ip_client"):
    protection_info = await ip_client.apply_protection(
        content=response["answer"],
        label_id=highest_priority_label.id,
        owner_email=user_email
    )
```

### Code Snippets Location

All code snippets are available in:
- **Full guide:** `docs/entra_information_protection.md`
- **Quick reference:** `docs/entra_is_quickstart.md`
- **Working examples:** `app/backend/examples/entra_is_integration_examples.py`

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     User Request                         │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│            RAG Chat Application (app.py)                 │
│  ┌────────────────────────────────────────────────────┐ │
│  │         Authentication Helper                       │ │
│  │  - Validates user identity                          │ │
│  │  - Gets access tokens                               │ │
│  └────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────┐
│              Approach (ChatReadRetrieveRead)             │
│  ┌────────────────────────────────────────────────────┐ │
│  │ 1. Search documents (Azure AI Search)              │ │
│  │ 2. Extract labels from results (LabelHelper)       │ │
│  │ 3. Generate response (OpenAI)                      │ │
│  │ 4. Apply protection (InformationProtectionClient)  │ │
│  └────────────────────────────────────────────────────┘ │
└────────────────────┬────────────────────────────────────┘
                     │
        ┌────────────┴────────────┐
        ▼                         ▼
┌─────────────────┐     ┌─────────────────────────────┐
│  LabelHelper    │     │ InformationProtectionClient │
│                 │     │                             │
│ - Cache labels  │     │ - Get policies              │
│ - Resolve GUIDs │────▶│ - Apply protection          │
│ - Inheritance   │     │ - Auto-classify             │
└─────────────────┘     └──────────┬──────────────────┘
                                   │
                                   ▼
                    ┌──────────────────────────────┐
                    │  Microsoft Graph API         │
                    │  (Information Protection)    │
                    │                              │
                    │  - Label policies            │
                    │  - Protection templates      │
                    │  - Classification rules      │
                    └──────────────────────────────┘
```

## Configuration Options

| Variable | Description | Default |
|----------|-------------|---------|
| `AZURE_ENABLE_INFORMATION_PROTECTION` | Enable IP integration | `false` |
| `AZURE_INFORMATION_PROTECTION_ENDPOINT` | Custom IP endpoint | `https://api.aadrm.com` |
| `AZURE_ENABLE_CONTENT_INSPECTION` | Auto-classification | `false` |
| `AZURE_ENFORCE_PROTECTION_POLICIES` | Require protection | `false` |

## Testing

Run the included test script:

```bash
export AZURE_AUTH_TENANT_ID="your-tenant-id"
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

## Benefits

1. **Enhanced Security**: Apply organization-wide sensitivity labels to AI responses
2. **Compliance**: Meet regulatory requirements for data protection
3. **Automatic Classification**: Let the system suggest appropriate labels
4. **Label Inheritance**: Responses inherit labels from source documents
5. **Unified Management**: Centralized label management via Microsoft Purview
6. **Audit Trail**: Track which labels are applied to AI-generated content

## Integration Points

The integration plugs into existing code at these points:

1. **App Startup** (`app.py:setup_clients`):
   - Initialize InformationProtectionClient
   - Load and cache label policies

2. **Approach Execution** (`approaches/*`):
   - Extract labels from search results
   - Apply protection to generated responses
   - Auto-classify content without source labels

3. **Label Resolution** (`core/labelhelper.py`):
   - Enhanced label lookup with IP client fallback
   - Policy-based label caching

## No Breaking Changes

The integration is:
- ✅ **Optional** - Disabled by default
- ✅ **Backward Compatible** - Existing code works unchanged
- ✅ **Configurable** - Enable/disable via environment variables
- ✅ **Non-intrusive** - Only adds new capabilities

## Dependencies

All required dependencies are already in `requirements.txt`:
- ✅ `aiohttp` - For async HTTP requests to Graph API
- ✅ `azure-identity` - For Azure authentication
- ✅ Existing packages - No new dependencies added

## Next Steps

1. **Review documentation:**
   - Read `docs/entra_information_protection.md` for complete guide
   - Check `docs/entra_is_quickstart.md` for quick reference

2. **Try examples:**
   - Review `app/backend/examples/entra_is_integration_examples.py`
   - Copy relevant snippets to your code

3. **Configure environment:**
   - Set required environment variables
   - Configure API permissions in Azure AD
   - Grant admin consent

4. **Deploy and test:**
   - Run `azd up` to deploy with new integration
   - Test with sample content
   - Verify labels are applied correctly

## Support Resources

- [Microsoft Information Protection SDK](https://learn.microsoft.com/information-protection/develop/)
- [Sensitivity Labels](https://learn.microsoft.com/purview/sensitivity-labels)
- [Graph API - Information Protection](https://learn.microsoft.com/graph/api/resources/informationprotection)
- [Azure Information Protection](https://learn.microsoft.com/azure/information-protection/)

## Maintenance

The integration is self-contained and requires minimal maintenance:
- Label policies are cached for 2 hours (configurable)
- Access tokens are automatically refreshed
- Failed operations log warnings but don't break the app
- All operations are async and non-blocking

---

**Author**: GitHub Copilot  
**Date**: December 2024  
**Version**: 1.0  
**Status**: Complete and tested
