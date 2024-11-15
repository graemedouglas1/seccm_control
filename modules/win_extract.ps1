#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

#Requires -Version 2.0

$ErrorActionPreference = "Stop"

$params = Parse-Args -arguments $args -supports_check_mode $true
$path   = Get-AnsibleParam -obj $params -name "path"   -type "str" -failifempty $true
$regexp = Get-AnsibleParam -obj $params -name "regexp" -type "str" -failifempty $true

$set_args = @{
    ErrorAction = "Stop"
    path        = $path
    regexp      = $regexp
}

function win_extract {
  [CmdletBinding()]
  param(
    [string]$path,
    [string]$regexp
  )

  ######################################
  # START
  ######################################

  $hashtable = @{}
  $result    = @{}   

  try {
    $cnt = Get-Content "$($path)"
    $val = [regex]::Match($cnt, $regexp).Groups[1].value
        
    if(-Not([string]::IsNullOrEmpty($val))){
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode'='1';
        'Message'='Value found';
        'Value'=$val;
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
    else {
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode'='-1';
        'Message'='Value not found'; 
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
  }
  catch {
    [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
      'ReturnCode'='-1';
      'Message'="$error";
    }
    $return.psobject.properties | foreach {
      $hashtable[$_.Name] = $_.Value
    }
    return $hashtable
  }
}

$result = win_extract @set_args
Exit-Json -obj $result
