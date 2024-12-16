'''
# Owner
./configure_pim_role -sub "tss-sfa-uat-sub" -rg "xxx-rg-rg" -role "Owner" -environment "uat" -adGroupName "xxx-rg Owner"


# Contributor
./configure_pim_role -sub "tss-sfa-uat-sub" -rg "xxx-rg-rg" -role "Contributor" -environment "uat" -adGroupName "xxx-rg Contributor"

# Key Vault Secret Officer
./configure_pim_role -sub "tss-sfa-uat-sub" -rg "xxx-rg-rg" -role "Key Vault Secrets Officer" -environment "uat" -adGroupName "xxx-rg KvSecretsOfficer"
'''