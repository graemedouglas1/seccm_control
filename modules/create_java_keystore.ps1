#!powershell

#Requires -Module Ansible.ModuleUtils.Legacy

#Requires -Version 2.0

$ErrorActionPreference = "Stop"

$params  = Parse-Args -arguments $args -supports_check_mode $true
$pkcs12_filename   = Get-AnsibleParam -obj $params -name "pkcs12_filename"   -type "str" -failifempty $true
$keystore_filename = Get-AnsibleParam -obj $params -name "keystore_filename" -type "str" -failifempty $true
$keystore_password = Get-AnsibleParam -obj $params -name "keystore_password" -type "str" -failifempty $true

$set_args = @{
    ErrorAction = "Stop"
    pkcs12_filename   = $pkcs12_filename
    keystore_filename = $keystore_filename
    keystore_password = $keystore_password
}

function create_java_keystore {
  [CmdletBinding()]
  param(
    $pkcs12_filename,
    $keystore_filename,
    $keystore_password
  )


  ######################################
  # FUNCTIONS
  ######################################

  function get_packagePath {
    [CmdletBinding()]
    param(
      $productName
    )

    $hashtable = @{}
    $result    = @{} 
    
    try{
      $productGuid = (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$($productName)" } | Sort-Object -Property Name, Descending | Select-Object -first 1).IdentifyingNumber
      if ($productGuid){
        $product_install = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\$($productGuid)" | Select-Object InstallLocation -ExpandProperty InstallLocation)
    
        if(Test-Path "$product_install"){
          return "$product_install"
        }
        else {
          [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
            'ReturnCode' = '-1';
            'Message'    = 'Unable to find installation path';
            'changed'    = $false;
          }
          $return.psobject.properties | foreach {
            $hashtable[$_.Name] = $_.Value
          }
          Exit-Json -obj $hashtable
        }
      }
    }
    catch{
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '-1';
        'Message'    = "$error";
        'changed'    = $false;
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      Exit-Json -obj $hashtable
    }
  }

  ######################################
  # START
  ######################################
  
  $ErrorActionPreference = "SilentlyContinue"
  
  $hashtable = @{}
  $result    = @{}   

  $error.Clear()
  $errout = $null

  # Remove old keystore
  if(Test-Path $keystore_filename){
    Remove-Item -Path "$($keystore_filename)" -Force
  }
  
  $product_path = get_packagePath -productName 'java'
  $keytool_path = $($product_path) + 'bin' + '\keytool.exe'
  $keytool_command = "&`"$($keytool_path)`" -importkeystore -noprompt -srckeystore $($pkcs12_filename) -srcstoretype PKCS12 -srcstorepass $($keystore_password) -destkeystore $($keystore_filename) -deststoretype jks -deststorepass $($keystore_password)"

  ($res = Invoke-Expression -Command $keytool_command -ErrorVariable errout -OutVariable stdout) 2>&1 | Out-Null
  
  if([string]::IsNullOrEmpty($errout) -or $errout -match '0 entries failed or cancelled') {

    if(Test-Path $keystore_filename){
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '1';
        'Message'    = 'JKS File Created';
        'Filepath'   = "$($keystore_filename)";
        'changed'    = $true;
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
    else {
      [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
        'ReturnCode' = '-1';
        'Message'    = 'JKS File Not Created';
        'changed'    = $false;
      }
      $return.psobject.properties | foreach {
        $hashtable[$_.Name] = $_.Value
      }
      return $hashtable
    }
  }
  else {
    [psobject]$return = New-Object -TypeName 'PSObject' -Property @{
      'ReturnCode' = '-1';
      'Message'    = "$errout";
      'changed'    = $false;
    }
    $return.psobject.properties | foreach {
      $hashtable[$_.Name] = $_.Value
    }
    return $hashtable
  }
}

$result = create_java_keystore @set_args
Exit-Json -obj $result
