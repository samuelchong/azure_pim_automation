### *** https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-resource-roles-assign-roles
### using rest api https://learn.microsoft.com/en-us/rest/api/authorization/role-management-policies?view=rest-authorization-2020-10-01
### https://learn.microsoft.com/en-us/graph/api/resources/privilegedidentitymanagementv3-overview?view=graph-rest-1.0
### https://www.yoloit.no/Azure-PIM/
### https://learn.microsoft.com/en-us/rest/api/authorization/role-management-policies?view=rest-authorization-2020-10-01
### https://learn.microsoft.com/en-us/powershell/microsoftgraph/tutorial-pim?view=graph-powershell-1.0
### enable PIM roles with Justification and Ticketing information https://learn.microsoft.com/en-us/answers/questions/1573281/using-rest-api-how-can-we-enable-pim-roles-with-ju
### https://gist.github.com/JanVidarElven/2cd283d4a1e82cdec7d40313bcd0e311
### assign ad group to PIM role https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-add-role-to-user#assign-a-role-using-microsoft-graph-api

#############
# Parameters
#############
# param (
#     [string]$sub,
#     [string]$rg
# )

[CmdletBinding()]
param (
      [Parameter(Mandatory)] 
      $sub,
      [Parameter(Mandatory)] 
      $rg,
      [Parameter(Mandatory)] 
      $role,
      [Parameter(Mandatory)] 
      $environment,
      [Parameter(Mandatory)]
      $adgroupName
)

write-host "Subscription: $sub"
write-host "Resource Group: $rg"

# set variables
$global:rmcScope = $null
$global:headers = $null
$global:rmcRequestResults = $null
$global:rmcPolicyName = $null
$global:headersGraphApi = $null

##################
# sign in to Azure
##################
function login {
      Clear-AzContext -Force
      # Connect-AzAccount -te # sign-in
      Add-AzAccount -Tenant "xxx.network" # if you are working with multiple tenants, this one is handy
      $context = Set-AzContext -SubscriptionName  $sub

      # define the scope of the configuration in this case, subscription
      $global:rmcScope = "subscriptions/$($context.Subscription.Id)/resourceGroups/$($rg)"

      # Use powershell to get an accestoken based on the currently signed in account/service principal
      # build a headers hash table
      $global:accessToken = Get-AzAccessToken -ResourceUrl "https://management.azure.com"
      $global:headers = @{
            Authorization = "$($accessToken.type) $($accessToken.Token)"
      }

      # # Use PowerShell to get an access token for Microsoft Graph API
      # $accessTokenGraphApi = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
      # $global:headersGraphApi = @{
      #       Authorization  = "Bearer $accessTokenGraphApi"
      #       "Content-Type" = "application/json"
      # }
}



########################
# Owner Role
########################
function GetRole { 
      ### Find the Details for the Role Definition you want to configure
      # $role = "Owner"
      $roleId = Get-AzRoleDefinition -Name $role
   
      # Get the details for your role manageemnt policy
      $rmcRequest = @{
            headers = $global:headers
            uri     = "https://management.azure.com/$global:rmcScope/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01&" + '$' + "filter=roleDefinitionId+eq+'$rmcScope/providers/Microsoft.Authorization/roleDefinitions/$($roleId.id)'"
            method  = "GET"
      }
      $global:rmcRequestResults = (invoke-RestMethod @rmcRequest).value
   
      # Download policy - export the results to file for comparing. This step is only needed for tuning the settings
      $global:rmcRequestResults | ConvertTo-Json -Depth 100 | Out-File -FilePath ".\x_pim_settings_$role.json"
}



### Extract PIM Settings
function SetPIMSettings {
  
      # we need to extract some details. I like having them as separate variables
      $global:rmcPolicyName = $global:rmcRequestResults.Name
      $rmcPolicyId = $global:rmcRequestResults.id
      $rmcPolicyProperties = $global:rmcRequestResults.properties

      # update Notification settings in the variable (assuming there are equal number of effective rules as rules)
      for ($p = 0; $p -lt ($rmcPolicyProperties.rules).Length; $p++) {
            switch -Exact ($rmcPolicyProperties.rules[$p].id) {
                  "Expiration_Admin_Eligibility" {
                        $rmcPolicyProperties.rules[$p].isExpirationRequired = $false
                        $rmcPolicyProperties.effectiveRules[$p].isExpirationRequired = $false
                  } # permanent eligebility
                  
                  "Enablement_EndUser_Assignment" {
                        if (($environment -eq "prod") -or ($role -eq "Owner")) {
                              $rmcPolicyProperties.rules[$p].enabledRules = @("MultiFactorAuthentication", "Justification", "Ticketing")
                        }
                        else {
                              $rmcPolicyProperties.rules[$p].enabledRules = @("Justification")
                        }
                  } # requires MFA and Justification text


                  "Expiration_EndUser_Assignment" {

                        if ($role -eq "Owner") {
                              $rmcPolicyProperties.rules[$p].maximumDuration = "PT4H"
                        }
                        else {
                              $rmcPolicyProperties.rules[$p].maximumDuration = "PT8H"
                        }
                  } # 4 hours of max activation time allowed

                  "Notification_Requestor_EndUser_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  } # Notification to activated user (requestor)

                  "Notification_Admin_Admin_Eligibility" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Admin_EndUser_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Admin_Admin_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Requestor_Admin_Eligibility" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Requestor_Admin_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Approver_EndUser_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Approver_Admin_Assignment" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }

                  "Notification_Approver_Admin_Eligibility" {
                        $rmcPolicyProperties.rules[$p].isDefaultRecipientsEnabled = $true
                        $rmcPolicyProperties.effectiveRules[$p].isDefaultRecipientsEnabled = $true
                  }
                  "Approval_EndUser_Assignment" {
                        if (@('prod', 'uat') -contains $environment -and ( @('Owner', 'Contributor', 'Key Vault Secrets Officer') -contains $role )) {        
                              $rmcPolicyProperties.rules[$p].setting.isApprovalRequired = $true
                              # Define the primary approvers

                              $primaryApprovers = @(
                                    [PSCustomObject]@{
                                          id          = "xxx-xxxx-xxx"
                                          description = "Azure PIM Approvers"
                                          isBackup    = $false
                                          userType    = "Group"
                                    }
                              )
                        
  
                              # Ensure the approvalStages property exists
                              if (-not $rmcPolicyProperties.rules[$p].setting.approvalStages[0].primaryApprovers) {
                                    $rmcPolicyProperties.rules[$p].setting.approvalStages[0] | Add-Member -MemberType NoteProperty -Name primaryApprovers -Value []
                              }
                              if (-not $rmcPolicyProperties.effectiveRules[$p].setting.approvalStages[0].primaryApprovers) {
                                    $rmcPolicyProperties.effectiveRules[$p].setting.approvalStages[0] | Add-Member -MemberType NoteProperty -Name primaryApprovers -Value []
                              }
  
                              # Add the primary approvers to the approvalStages
                              $rmcPolicyProperties.rules[$p].setting.isApprovalRequired = $true
                              $rmcPolicyProperties.rules[$p].setting.approvalStages[0].primaryApprovers = $primaryApprovers
            

                              $rmcPolicyProperties.effectiveRules[$p].setting.isApprovalRequired = $true
                              $rmcPolicyProperties.effectiveRules[$p].setting.approvalStages[0].primaryApprovers = $primaryApprovers
    
                              # Output the updated setting for verification
                              Write-Host "Updated approver setting:" (ConvertTo-Json $rmcPolicyProperties.effectiveRules[$p].setting -Depth 10)
                        }
                  }
           
                  Default { }
            }
      }


      # Update role management policy
      $body = @{
            properties = @{
                  rules          = $rmcPolicyProperties.rules
                  effectiveRules = $rmcPolicyProperties.effectiveRules
            }
      } | ConvertTo-Json -Depth 20

      $rmcUpdateRequest = @{
            headers     = $global:headers
            uri         = "https://management.azure.com/$global:rmcScope/providers/Microsoft.Authorization/roleManagementPolicies/$($rmcPolicyName)?api-version=2020-10-01"
            method      = "PATCH"
            body        = $body
            ContentType = 'application/json'
      }
      # make the update
      $rmcUpdateRequestResults = invoke-RestMethod @rmcUpdateRequest


}

# Function to get the groupId by group name
function Get-GroupIdByName {
      param (
            [Parameter(Mandatory)]
            [string]$adgroupName
      )
  
      $group = Get-AzADGroup -DisplayName $adgroupName
      
      return $group.Id
}

# Function to assign the Reader 

# function SetAssignReaderRole {
#       # Use PowerShell to get an access token for Microsoft Graph API
#       $accessTokenGraphApi = (Get-AzAccessToken -ResourceUrl "https://graph.microsoft.com").Token
#       $global:headersGraphApi = @{
#             Authorization  = "Bearer $accessTokenGraphApi"
#             "Content-Type" = "application/json"
#       }
            
#       # Get the groupId by group name
#       $principalId = Get-GroupIdByName -adgroupName $adgroupName
  
#       # Define the parameters
#       $action = "adminAssign"
#       $justification = "Permanently assign the Global Reader to the auditor"
#       $roleDefinitionId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"
#       $directoryScopeId = "/" # Use "/" for tenant scope or specify a group/admin unit object ID
#       $startDateTime = "2022-04-10T00:00:00Z"
  
#       # Define the body of the request
#       $body = @{
#             action           = $action
#             justification    = $justification
#             roleDefinitionId = $roleDefinitionId
#             directoryScopeId = $directoryScopeId
#             principalId      = $principalId
#             scheduleInfo     = @{
#                   startDateTime = $startDateTime
#                   expiration    = @{
#                         type = "noExpiration"
#                   }
#             }
#       } | ConvertTo-Json -Depth 10
  
#       # Define the URI
#       $uri = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleRequests"
  
#       # Make the POST request
#       $response = Invoke-RestMethod -Uri $uri -Method Post -Headers $global:headersGraphApi -Body $body
  
#       # Output the response
#       Write-Host $response
# }

# Perm elibility
# https://learn.microsoft.com/en-us/graph/api/rbacapplication-post-roleeligibilityschedulerequests?view=graph-rest-1.0&tabs=http



############
# main flow
############
login
GetRole
SetPIMSettings
# SetAssignReaderRole