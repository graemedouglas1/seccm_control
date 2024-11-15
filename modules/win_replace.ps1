#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

#Requires -Version 2.0

$ErrorActionPreference = "Stop"

$params  = Parse-Args -arguments $args -supports_check_mode $true
$path    = Get-AnsibleParam -obj $params -name "path"    -type "str" -failifempty $true
$regexp  = Get-AnsibleParam -obj $params -name "regexp"  -type "str" -failifempty $true
$newtext = Get-AnsibleParam -obj $params -name "newtext" -type "str" -failifempty $true
$backup  = Get-AnsibleParam -obj $params -name "backup"  -type "str" -failifempty $false -default $true

$set_args = @{
    ErrorAction = "Stop"
    path    = $path
    regexp  = $regexp
    newtext = $newtext
    backup  = $backup
}

function win_replace {
  [CmdletBinding()]
  param(
    [string]$path,
    [string]$regexp,
    [string]$newtext,
    [string]$backup
  )

  ######################################
  # START
  ######################################

  $hashtable = @{}
  $result    = @{}   

  try {
    if(Test-Path $path) {
      
      $ccontent = (Get-Content -path $path -Raw)

      if($ccontent.contains($newText)) {
        [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
          'ReturnCode' = '0';
          'Message'    = "No Changes Made, Text Already Found in File";
          'File'       = "$($path)";
          'changed'    = $false;
        }
        $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
        return $hashtable
      }
      else {

        if ($backup){
          $foldername = Split-Path "$($path)" -Parent
          $filename   = Split-Path "$($path)" -Leaf
          $dt         = Get-Date -uformat %d%m%Y%H%M%S
          Copy-Item "$($path)" "$($foldername)\$($filename).$($dt)"
        }

        # Replace Contents of File
        (Get-Content -path $path -Raw) -replace $regexp, $newText | Set-Content -Path $path
    
        # Gather New Contents of File
        $ncontent = (Get-Content -path $path -Raw)

        # Confirm File Updated
        if($ncontent.Contains($newText)){
          [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
            'ReturnCode' = '1';
            'Message'    = "Content Updated Successfully";
            'File'       = "$($path)";
            'changed'    = $true;
          }
          $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
          return $hashtable
        }
        else{
          [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
            'ReturnCode' = '-1';
            'Message'    = "Failed to Confirm Changes";
            'File'       = "$($path)";
            'changed'    = $false;
          }
          $return.psobject.properties | foreach { $hashtable[$_.Name] = $_.Value }
          return $hashtable
        }
      }
    }
    else {
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '-1';
        'Message'    = "Failed to Find File";
        'File'       = "$($path)";
        'changed'    = $false;
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

$result = win_replace @set_args
Exit-Json -obj $result
