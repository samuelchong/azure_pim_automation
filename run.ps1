param (
    [Parameter(Mandatory)]
    [string]$sub,

    [Parameter(Mandatory)]
    [string]$rg,

    
    [Parameter(Mandatory)]
    [string]$environment
)

# Owner
./configure_pim_role.ps1 -sub $sub -rg $rg -role "Owner" -environment $environment -adGroupName "xxx rg $rg Owner"

# Contributor
./configure_pim_role.ps1 -sub $sub -rg $rg -role "Contributor" -environment $environment -adGroupName "xxx rg $rg Contributor"

# Key Vault Secret Officer
./configure_pim_role.ps1 -sub $sub -rg $rg -role "Key Vault Secrets Officer" -environment $environment -adGroupName "xxx rg $rg KvSecretsOfficer"