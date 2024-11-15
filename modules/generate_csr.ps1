#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

#Requires -Version 2.0

$ErrorActionPreference = "Stop"

$params  = Parse-Args -arguments $args -supports_check_mode $true
$csrpath      = Get-AnsibleParam -obj $params -name "csrpath"      -type "str" -failifempty $true
$cn           = Get-AnsibleParam -obj $params -name "cn"           -type "str" -failifempty $true
$organisation = Get-AnsibleParam -obj $params -name "organisation" -type "str" -failifempty $true
$department   = Get-AnsibleParam -obj $params -name "department"   -type "str" -failifempty $true
$city         = Get-AnsibleParam -obj $params -name "city"         -type "str" -failifempty $true
$state        = Get-AnsibleParam -obj $params -name "state"        -type "str" -failifempty $true
$country      = Get-AnsibleParam -obj $params -name "country"      -type "str" -failifempty $true

$set_args = @{
    ErrorAction = "Stop"
    csrpath      = $csrpath
    cn           = $cn
    organisation = $organisation
    department   = $department
    city         = $city
    state        = $state
    country      = $country
}

function generate_csr {
  [CmdletBinding()]
  param(
    [string]$csrpath,
    [string]$cn,
    [string]$organisation,
    [string]$department,
    [string]$city,
    [string]$state,
    [string]$country
  )

  ######################################
  # START
  ######################################

  $hashtable = @{}
  $result    = @{}   

  try {
    
    $inf = @"
[Version]
Signature = "`$Windows NT$"

[NewRequest]
Subject = "CN=$($cn), O=$($organisation), OU=$($department), L=$($city), S=$($state), C=$($country)"

KeySpec = 1
KeyLength = 2048
Exportable = TRUE
MachineKeySet = TRUE
SMIME = False
PrivateKeyArchive = FALSE
UserProtected = FALSE
UseExistingKeySet = FALSE
ProviderName = "Microsoft RSA SChannel Cryptographic Provider"
ProviderType = 12
RequestType = PKCS10
KeyUsage = 0xa0
HashAlgorithm = SHA256

[EnhancedKeyUsageExtension]

OID=1.3.6.1.5.5.7.3.1 ; this is for Server Authentication / Token Signing

"@
    
    $csrdir = Split-Path -Path $csrpath
    if(-Not(Test-Path $csrdir)){
      # Create output directory
      New-Item -ItemType Directory -Force -Path $csrdir | Out-Null
    }

    # Export INF Contents to File
    $infpath = "$($csrdir)\request.inf"
    $inf | Out-File -FilePath $infpath -Force | Out-Null

    # Create Certificate Request
    certreq -new -f $infpath $csrpath | Out-Null

    # Confirm Certificate Request File
    if(Test-Path $csrpath){
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '1';
        'Message'    = "Certificate Request File Created Successfully";
        'File'       = "$($csrpath)"
      }
      $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
      return $hashtable
    }
    else{
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '-1';
        'Message'    = "Certificate Request File Failed to Create";
      }
      $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
      return $hashtable
    }
  }
  catch {
    [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
      'ReturnCode'='-1';
      'Message'="$error";
    }
    $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
    return $hashtable
  }
}

$result = generate_csr @set_args
Exit-Json -obj $result
