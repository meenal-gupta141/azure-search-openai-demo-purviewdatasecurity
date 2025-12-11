"""
Example: Integrating Microsoft Entra Information Protection Service

This file demonstrates how to integrate the InformationProtectionClient
with the existing RAG chat application to provide enhanced data security.

Usage:
    1. Copy the relevant code snippets to your app.py or approaches
    2. Configure environment variables as described in docs/entra_information_protection.md
    3. Enable the feature by setting AZURE_ENABLE_INFORMATION_PROTECTION=true
"""

import os
import logging
from typing import Optional, List, Dict, Any
from core.information_protection import InformationProtectionClient
from core.labelhelper import LabelHelper, DocumentLabel, SensitivityLabel


# ============================================================================
# Example 1: Initialize IP Client in app.py
# ============================================================================

async def setup_information_protection_client(
    azure_credential,
    azure_auth_tenant_id: str,
    label_helper: LabelHelper
) -> Optional[InformationProtectionClient]:
    """
    Initialize the Information Protection client and load label policies.
    
    Add this function call in app.py's setup_clients() function.
    
    Args:
        azure_credential: Azure credential instance
        azure_auth_tenant_id: Tenant ID for authentication
        label_helper: Existing LabelHelper instance
        
    Returns:
        Configured InformationProtectionClient or None if disabled
    """
    # Check if Information Protection integration is enabled
    if os.getenv("AZURE_ENABLE_INFORMATION_PROTECTION", "").lower() != "true":
        logging.info("Information Protection integration is disabled")
        return None
    
    logging.info("Initializing Information Protection client")
    
    try:
        # Create the IP client
        ip_endpoint = os.getenv("AZURE_INFORMATION_PROTECTION_ENDPOINT")
        ip_client = InformationProtectionClient(
            tenant_id=azure_auth_tenant_id,
            credential=azure_credential,
            endpoint=ip_endpoint
        )
        
        # Load and cache label policies
        policies = await label_helper.get_active_policies(ip_client)
        logging.info("Loaded %d active protection policies", len(policies))
        
        # Log the labels that were cached
        for policy in policies:
            policy_name = policy.get("name", "Unknown")
            label_count = len(policy.get("labels", []))
            logging.info(
                "Policy '%s' contains %d labels",
                policy_name,
                label_count
            )
        
        return ip_client
        
    except Exception as e:
        logging.exception("Failed to initialize Information Protection client: %s", e)
        return None


# ============================================================================
# Example 2: Apply Protection to Chat Responses
# ============================================================================

async def apply_response_protection(
    response_content: str,
    document_labels: List[DocumentLabel],
    user_email: str,
    ip_client: Optional[InformationProtectionClient]
) -> Dict[str, Any]:
    """
    Apply appropriate protection to a chat response based on source documents.
    
    Add this to your approach classes (e.g., ChatReadRetrieveReadApproach)
    to protect AI-generated responses.
    
    Args:
        response_content: Generated chat response text
        document_labels: Labels from source documents used in the response
        user_email: Email of the requesting user
        ip_client: Information Protection client instance
        
    Returns:
        Protection metadata including label info and protection status
    """
    if not ip_client or not document_labels:
        return {}
    
    # Determine the highest priority label from source documents
    highest_priority_label = max(
        document_labels,
        key=lambda dl: dl.label.priority
    ).label
    
    logging.info(
        "Applying protection with label: %s (priority: %d)",
        highest_priority_label.display_name,
        highest_priority_label.priority
    )
    
    # Apply protection using the IP client
    protection_info = await ip_client.apply_protection(
        content=response_content,
        label_id=highest_priority_label.id,
        owner_email=user_email,
        metadata=[
            {"name": "source", "value": "ai-chat"},
            {"name": "generatedBy", "value": "azure-search-openai-demo"}
        ]
    )
    
    # Return metadata about the protection
    return {
        "labelId": highest_priority_label.id,
        "labelName": highest_priority_label.display_name or highest_priority_label.name,
        "labelColor": highest_priority_label.color,
        "labelPriority": highest_priority_label.priority,
        "protectionApplied": bool(protection_info),
        "protectionInfo": protection_info
    }


# ============================================================================
# Example 3: Automatic Content Classification
# ============================================================================

async def classify_chat_response(
    response_text: str,
    ip_client: InformationProtectionClient,
    label_helper: LabelHelper
) -> Optional[SensitivityLabel]:
    """
    Automatically classify chat response content and recommend a label.
    
    Use this when generating responses that don't have source documents,
    or to validate/upgrade labels on AI-generated content.
    
    Args:
        response_text: Text content to classify
        ip_client: Information Protection client
        label_helper: LabelHelper for label resolution
        
    Returns:
        Recommended SensitivityLabel or None
    """
    # Check if content inspection is enabled
    if os.getenv("AZURE_ENABLE_CONTENT_INSPECTION", "").lower() != "true":
        return None
    
    # Evaluate the content for automatic classification
    evaluation = await ip_client.evaluate_application(
        content=response_text,
        content_format="text/plain",
        context={
            "identifier": "chat-response",
            "metadata": [
                {"name": "source", "value": "ai-chat"},
                {"name": "type", "value": "generated"}
            ]
        }
    )
    
    if not evaluation:
        logging.debug("No label recommendation from content evaluation")
        return None
    
    # Extract the recommended label
    recommended_label_info = evaluation.get("recommendedLabel", {})
    label_id = recommended_label_info.get("labelId")
    confidence = recommended_label_info.get("confidence", 0)
    
    if not label_id:
        return None
    
    logging.info(
        "Auto-classification recommended label: %s (confidence: %.2f)",
        label_id,
        confidence
    )
    
    # Resolve the full label details
    label = await label_helper.resolve_label_with_ip_client(label_id, ip_client)
    return label


# ============================================================================
# Example 4: Testing the Integration
# ============================================================================

async def test_information_protection_integration():
    """
    Simple test function to verify IP integration is working.
    
    Run this in a development/test environment to validate setup.
    """
    from azure.identity.aio import DefaultAzureCredential
    
    # Get configuration
    tenant_id = os.getenv("AZURE_AUTH_TENANT_ID")
    if not tenant_id:
        print("ERROR: AZURE_AUTH_TENANT_ID not set")
        return False
    
    # Initialize credential
    credential = DefaultAzureCredential()
    
    # Create IP client
    ip_client = InformationProtectionClient(
        tenant_id=tenant_id,
        credential=credential
    )
    
    try:
        # Test 1: Get label policies
        print("Test 1: Retrieving label policies...")
        policies = await ip_client.get_label_policies()
        print(f"✓ Retrieved {len(policies)} policies")
        
        if policies:
            # Test 2: Get a specific label
            first_policy = policies[0]
            labels = first_policy.get("labels", [])
            if labels:
                label_id = labels[0].get("id")
                print(f"\nTest 2: Retrieving label {label_id}...")
                label = await ip_client.get_label_by_id(label_id)
                if label:
                    print(f"✓ Retrieved label: {label.get('displayName')}")
                else:
                    print("✗ Failed to retrieve label")
        
        # Test 3: Content evaluation
        print("\nTest 3: Testing content evaluation...")
        test_content = "This is a test message containing sensitive information."
        evaluation = await ip_client.evaluate_application(
            content=test_content,
            content_format="text/plain"
        )
        if evaluation:
            print(f"✓ Content evaluation successful")
            recommended = evaluation.get("recommendedLabel", {})
            if recommended:
                print(f"  Recommended label: {recommended.get('labelId')}")
        else:
            print("✓ Content evaluation completed (no recommendations)")
        
        print("\n✓ All tests completed successfully!")
        return True
        
    except Exception as e:
        print(f"\n✗ Test failed with error: {e}")
        return False
    finally:
        await ip_client.close()
        await credential.close()


if __name__ == "__main__":
    """
    Run tests when executed directly.
    
    Usage:
        python app/backend/examples/entra_is_integration_examples.py
    """
    import asyncio
    asyncio.run(test_information_protection_integration())
