metadata description = 'Creates a role assignment for a service principal on a storage account.'

param storageAccountName string
param principalId string

@allowed([
  'Device'
  'ForeignGroup'
  'Group'
  'ServicePrincipal'
  'User'
])
param principalType string = 'ServicePrincipal'
param roleDefinitionId string

// Skip role assignment if principalId is empty (used when role is pre-configured)
param skipRoleAssignment bool = false

resource storageAccount 'Microsoft.Storage/storageAccounts@2024-01-01' existing = {
  name: storageAccountName
}

resource role 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!skipRoleAssignment && !empty(principalId)) {
  name: guid(storageAccount.id, principalId, roleDefinitionId)
  scope: storageAccount
  properties: {
    principalId: principalId
    principalType: principalType
    roleDefinitionId: resourceId('Microsoft.Authorization/roleDefinitions', roleDefinitionId)
  }
}
