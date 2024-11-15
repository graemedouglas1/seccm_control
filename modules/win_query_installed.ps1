#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

#Requires -Version 2.0

$ErrorActionPreference = "Stop"

$params  = Parse-Args -arguments $args -supports_check_mode $true
$product = Get-AnsibleParam -obj $params -name "product"   -type "str" -failifempty $true

$set_args = @{
    ErrorAction = "Stop"
    product     = $product
}

function win_query_installed {
  [CmdletBinding()]
  param(
    [string]$product
  )

  ######################################
  # START
  ######################################

  $hashtable = @{}
  $result    = @{}   

  try {
    $val = Get-WmiObject -Class Win32_Product | Where-Object {$_.Name -eq "$($product)" }
        
    if(-Not([string]::IsNullOrEmpty($val))){
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'Caption'    = "$($val.Caption)";
        'Name'       = "$($val.Name)";
        'Vendor'     = "$($val.Vendor)";
        'Version'    = "$($val.Version)";
        'ReturnCode' = '1';
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
    else {
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'Message'    = 'Package not found';
        'ReturnCode' = '-1';
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
  }
  catch {
    [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
      'ReturnCode' = '-1';
      'Message'    = "$error";
    }
    $return.psobject.properties | foreach {
      $hashtable[$_.Name] = $_.Value
    }
    return $hashtable
  }
}

$result = win_query_installed @set_args
Exit-Json -obj $result