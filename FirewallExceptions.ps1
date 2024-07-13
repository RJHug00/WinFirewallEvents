<#
  This script captures details of firewall allow and block activity as detected by
  Windows Filtering Platform and produces tabular reductions of the results.
#>

$tmpDir = 'C:\Windows\Temp\Firewall'

# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml:
$protoNames = [System.Collections.HashTable] @{ 1="ICMP"; 2="IGMP"; 4="IPv4"; 6="TCP"; 9="IGP"; 17="UDP" }

# https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
$portNames = [System.Collections.HashTable] @{ 
  53="DNS"; 67="DHCP"; 68="DHCP"; 80="HTTP"; 123="NTP"; 137="NetB"; 161="SNMP"; 443="HTTPS"; 5353="mDNS"; 5355="LLMNR" }

$opNames = [System.Collections.HashTable] @{ "Allow"="A"; "Block"="B"; "Deny"="D"; "ABind"="Y"; "BBind"="X" }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
          [Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  throw [System.ApplicationException]::New('Script must be run as Adminstrator')
}

# Format-Table mis-behaves and truncates lots of info without predefined views for our PSCustomObject
Update-FormatData -AppendPath .\myWFPEventEntry.types.ps1xml

# create the tmp folder as necessary
New-Item -Path (Split-Path $tmpDir -Parent) -Name (Split-Path $tmpDir -Leaf) -ItemType 'Directory' *>$null

$myIPAddress = (Get-NetIPAddress -InterfaceAlias 'Wi-Fi').IPAddress   # note the hardcoded inferface
$myIPAddress -match '(.*[.])[0-9]*' *>$null
$myLan = $matches[1]

New-Variable -Name filtersXml
$cachedLookups = [System.Collections.HashTable] @{ }  # ARIN Reverse-IP lookups

#  -------------------- Turn on audit events in Windows Security event log -------------------------
<# https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging

 Subcategory                      EventIDs
 -------------------------------- -----------------------------------------
 Filtering Platform Policy Change 5440 Persistent callout added
                                  5441 Boot-time or persistent filter added
                                  5442 Persistent provider added
                                  5443 Persistent provider context added
                                  5444 Persistent sub-layer added5446 Run-time callout added or removed
                            !!    5447 Run-time filter added or removed
                                  5448 Run-time provider added or removed
                                  5449 Run-time provider context added or removed
                                  5450 Run-time sub-layer added or removed
 Filtering Platform Packet Drop  *5152 Packet Dropped
                                  5153 Packet Vetoed
 Filtering Platform Connection    5154 Listen Allowed
                                  5155 Listen Blocked
                                 *5156 Connection Allowed
                                 *5157 Connection Blocked
                                 *5158 Bind Allowed
                                 *5159 Bind Blocked
#>

$beginTime = Get-Date   # when auditing was turned on

try {
  auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:enable /failure:enable 1>$null
  auditpol /set /subcategory:"Filtering Platform Connection"  /success:enable /failure:enable 1>$null

  Test-Connection -IPv4 -TargetName 192.168.1.1 -Count 1 -Quiet *>$null   # diagnostics pending elimination

  Read-Host Press ENTER after network operations of interest are finished

  Write-Host Patience - this can take a few minutes for lengthy or complex capture sessions

  Test-Connection -IPv4 -TargetName 192.168.1.1 -Count 1 -Quiet *>$null   # diagnostics pending elimination
}
finally {
  auditpol /set /subcategory:"Filtering Platform Connection"  /success:disable /failure:disable 1>$null
  auditpol /set /subcategory:"Filtering Platform Packet Drop" /success:disable /failure:disable 1>$null
}

#  -------------------- Acquire the active Windows Firewall rules -----------

try {
  Push-Location $tmpDir
  Remove-Item 'wfpstate.xml' *>$null

  netsh wfp show state 1>$null  # dump active [enabled] firewall filters

  $filtersTxt = Get-Content -Raw "wfpstate.xml"
  $filtersXml = [xml]$filtersTxt.substring(0,$filtersTxt.IndexOf('<firewallState>'))  # 1st XML root element
}
finally {
  Pop-Location
}

#  -------------------- Pipeline filtering functions ------------------------------
function remove_noise_items {   # optional [hardcoded] pipeline component

  <# Remember that I'm only calling this to tidy up ALLOWed traffic;
     I'm not trying to remove 'noise' from stuff already BLOCKed    #>

  Process { $o = $_
    switch ($o.Proto) {   #its easier to remember rationales for exceptions this way
      'UDP' {
        if ($o.Dir -eq 'O') {
          if ($o.Dst -eq '1.1.1.1') {   # the only legal DNS server here; outbound by definition
            # lots of browser DNS lookups are expected and can be ignored
            if ($o.App -eq 'chrome') {return}
            if ($o.App -eq 'msedge') {return}
            if ($o.App -eq 'msedge2') {return}
            if ($o.App -eq 'firefox') {return}
            # dnscache queries are also legitimate DNS lookups
            if ($o.App -eq 'svchost' -and $o.Filter -like 'Core Networking - DNS*') {return}
          }
          # allow the spooler to talk to the Canon printer
         if ($o.App -eq 'spoolsv' -and $o.Dst -eq 'LAN.250') {return}
        }
       elseif ($o.Dir -eq 'I') {
         # Cloudflare DNS keeps trying to udp me that gets blocked (through the router???)
         #if ($o.Src -eq '1.1.1.1' -and $o.Dst -eq 'me') {return}
         # The router broadcasts periodically [and is blocked]
         #if ($o.Src -eq 'LAN.1' -and $o.Dst -eq '255.255.255.255') {return}
         # The Canon printer on port 5353 (multicast DNS)
         if ($o.Src -eq 'LAN.250' -and $o.Dst -eq '224.0.0.251' -and $o.DPort -eq 'mDNS') {return}
         # there's a 0.0.0.0 -> 255.255.255.255 DHCP that is probably noise, but I want to remember it for now
       }
      }
      'IGMP' { 
        if ($o.Dir -eq 'O') {
          # Windows routinely probes the LAN via 224.*
          if ($o.App -eq 'system' -and $o.Dst -like '224.0.0.*') {return}
        }
        elseif ($o.Dir -eq 'I') { # observe LAN hosts being nosy
          if ($o.Src -eq 'LAN.1')   {return} # router
          if ($o.Src -eq 'LAN.254') {return} # extender
        }
      }
      'TCP' {
        #if ($o.Dir -eq 'O') { }
        #elseif ($o.Dir -eq 'I') { }
        # let Edge do this In or Out; we don't know what it is doing
        if ($o.App -eq 'msedge' -and $o.Dst -eq '127.0.0.1') {return}
      }
      'ICMP' {
        if ($o.Dir -eq 'O') {
          # conceal pings I do in this script; reveal all others
          if ($o.App -eq 'system' -and $o.Dst -eq 'LAN.1') {return}
        }
       #elseif ($o.Dir -eq 'I') { }
      }
    }
    $o
} }

function remove_repeated_items {  # optional pipeline component compares [almost] entire object
  Process {
    foreach ($li in $UniqueList) { # ignore $_.Op (BLOCK,DENY are similar enough)
      if ($_.Dir -eq $li.Dir -and $_.Proto -eq $li.Proto -and $_.Filter -eq $li.Filter -and
          $_.Src -eq $li.Src -and $_.Dst -eq $li.Dst     -and $_.DPort  -eq $li.DPort  -and $_.SPort -eq $li.SPort -and
          $_.PID -eq $li.PID -and $_.App -eq $li.App     -and $_.Folder -eq $li.Folder) { return }
    }
    $UniqueList.add($_); $_
} }

function domain_from_IP {
  param ( [bool] $source = $false )
  Process { $o = $_; $p1 = $source ? $o.src : $o.dst
    $o.dstNm = $p1  # fallback for the 'known' LAN addresses
    switch -wildcard ($p1) {
      '0.0.0.0' {}  # I don't know why we see this, but don't look it up
      '1.1.1.1' {}  # DNS for my site - don't look it up (Cloudflare)
      '127.*'   {}  # Loopback (whatever that is)
      'LAN.*'   {}  # In actuality, 192.168.1.*
      '224.0.0.251' { $answer = "Multicast DNS" }
      '224.0.0.252' { $answer = "Multicast LLMNR" }
      '224.*'   {}  # Anything 224 through 239 is IPv4 Multicast but NOT EXCLUSIVELY local LAN!
      '225.*'   {}  # Reserved
      '232.*'   {}  # 'Source-specific multicast'
      '233.*'   {}  # 'GLOP and AD-HOC
      '234.*'   {}  # 'Unicast-prefix-based'
      '235.*'   {}  # Reserved
      '239.*'   {}  # 'Administratively-scoped' Multicast
      'Broad*'  {}  # Broadcast (like super-multicast for the LAN) - 255.255.255.255
      '::1'     {}  # I think its IPv6 loopback
      'me'      {}  # In actuality, 192.168.1.172 fixed-ip
      Default {     # only query ARIN for stuff we don't recognize
        $answer = $cachedLookups.$p1
        if ($answer.length -eq 0) {
          try {
            Start-Sleep -Seconds 2	# don't flood ARIN 
            $uri = 'https://rdap-bootstrap.arin.net/bootstrap/ip/' + $p1
              # occasionally, this 'throws' for socket access forbidden by its permissions
              # The @_pwsh2 firewall rule likely needs editing to allow an additional RDAP web host.
            $arin = Invoke-WebRequest -URI $uri -SkipHeaderValidation
            $info = [System.Text.Encoding]::UTF8.GetString($arin.Content) | ConvertFrom-Json
            $vcard = ''
            try   { $vCard = $info.entities.vCardArray[1][1][3] } # no confidence this is always populated
            catch { $vCard = '???' }
            $answer = $info.Name; if ($answer.Length -gt 20) { $answer = $answer.Substring(0,19) }
            $answer = -join($answer,'(',$vCard,')')
            $cachedLookups[$p1] = $answer
          } catch {            # [Microsoft.PowerShell.Commands.HttpResponseException] 
                               # [System.Net.Http.HttpRequestException]
            Write-Host $uri $_.Exception.Message   # $_.Exception.Response (?)
        } }
        if ($source) { $o.src = $answer } else { $o.dstNm = $answer }
    } }
    $o
} }

#  -------------------- Primary pipeline processor for Get-WinEvent objects ------------------
function process_evt_item {
  Process {

    function system_selector { [OutputType([System.Diagnostics.Eventing.Reader.EventLogPropertySelector])]
      param ([string]$name)
      return [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new(
             [string[]]@('Event/System/' + $name)) 
    }
    function selector { [OutputType([System.Diagnostics.Eventing.Reader.EventLogPropertySelector])]
      param ([string]$name)
      return [System.Diagnostics.Eventing.Reader.EventLogPropertySelector]::new(
             [string[]]@('Event/EventData/Data[@Name="' + $name + '"]')) 
    }

    $eventRecord = [string]$_.GetPropertyValues((system_selector 'EventRecordID'))

    $processID = [string]$_.GetPropertyValues((selector 'ProcessId'))
    $src =       [string]$_.GetPropertyValues((selector 'SourceAddress'))
    $srcPort =   [string]$_.GetPropertyValues((selector 'SourcePort'))
    $dst =       [string]$_.GetPropertyValues((selector 'DestAddress'))
    $filterID =  [string]$_.GetPropertyValues((selector 'FilterRTID'))
    $layerID =   [string]$_.GetPropertyValues((selector 'LayerRTID'))

    $appFile =   [string]$_.GetPropertyValues((selector 'Application'))
    $i = $appFile.LastIndexOf('\')
    $appFldr = $i -gt 0 ? $appFile.ToLower().substring(0,$i).replace('\device\harddiskvolume3\','') : ''
    $appName = $i -gt 0 ? $appFile.substring($i+1) : $appFile
    $appName = $appName.ToLower().Replace('.exe','')
    Switch ( $appName ) {                            # there *may* be other apps needing extended handling
      'svchost' {
         $cmd = Get-Process -ID $processID 2>$null
         if ($cmd -ne $null ) {
           $cmd = $cmd.CommandLine.ToLower().Replace("c:\windows\system32\svchost.exe","svchost")
           $appWithPid = $cmd + '(' + $processId + ')'
         } else { $appWithPid = 'svchost(phantom)' }   # it started and stopped
      }
      Default {
        $appWithPid = $appName + '(' + $processId + ')'
    } }

    Switch (     [string]$_.GetPropertyValues((selector 'Direction'))) {
      '%%14592' { $direction = 'I' } # inbound
      '%%14593' { $direction = 'O' } # outbound
    }

    Switch ($_.Id) {
      5152 { $op = $opNames.'Block' } # Firewall Blocked a packet
      5156 { $op = $opNames.'Allow' } # Firewall Allowed a Connection
      5157 { $op = $opNames.'Deny' }  # Firewall Blocked a Connection
      5158 { $op = $opNames.'ABind' } # Firewall Allowed a Port Bind
      5159 { $op = $opNames.'BBind' } # Firewall Blocked a Port Bind
    }

    $dPort = [string]$_.GetPropertyValues((selector 'DestPort'))
    $dstPort = $portNames.[int]$dPort
    if ($dstPort -eq $null) {$dstPort = $dPort}

    $proto =     [string]$_.GetPropertyValues((selector 'Protocol'))
    $protoName = $protoNames.[int]$proto
    if ($protoName -eq $null) { $protoName = $proto }

    $src = $src.Replace($myIPAddress, 'me'); $src = $src.Replace($myLan, 'LAN.')
    $dst = $dst.Replace($myIPAddress, 'me'); $dst = $dst.Replace($myLan, 'LAN.')
    $dst = $dst.Replace('255.255.255.255', 'Broadcast')

    # Refer to the WFPSTATE Dump for active 'hidden' filters the Firewall GUI cannot see
    try {
      $filtersXml.wfpstate.layers.item | foreach { $layerItem = $_
        if ($layerItem.layer.layerId -eq $layerID) {              # might be overkill checking
          $layerItem.filters.item | foreach { $filterItem = $_
            if ($filterItem.filterId -ne '') {
              if ($filterItem.filterId -eq $filterID) {     # found the filter identified in event
                $filterID = $filterItem.displayData.name    # replace ID with its name
                if ($filterID.Length -gt 40) {$filterID = $filterID.Substring(0,39) }
     	        throw [System.ApplicationException]::New('break all foreach')
    } } } } } } 
    catch [System.ApplicationException] { } # can't use statement label 'break' to escape nesting

    $pco = [PsCustomObject]@{ # the return object
      Op = $op
      Dir = $direction
      Proto = $protoName
      Src = $src
      Dst = $dst
      DstNm = ''
      SPort = $srcPort
      DPort = $dstPort
      Filter = $filterID
      PID = $processID
      App = $appName
      AppPID = $appWithPid
      Folder = $appFldr
    }
    $pco.psobject.typenames.insert(0, "myWFPEventEntry")
    $pco
} }

#  -------------------- Dump WFPSTATE to reveal all active 'Allow' rules ------------------
#           This sees only rules for the active network profile (e.g. Private)
#           But most importantly reveals ALLOW rules secretly/dynamically added.
#           Its too much data to output to the console, so a file is written.

$fname = ($tmpDir + '\WFPstate_Allows.JSON')
Write-Output '{' >$fname
$filtersXml.wfpstate.layers.item | foreach { $layerItem = $_
  Write-Output ('"'+$layerItem.layer.layerKey+'":[') >>$fname
  $layerItem.filters.item | foreach { $filterItem = $_
      if ($filterItem.action.type -eq 'FWP_ACTION_PERMIT') {    # ** NOTE: I'm not dumping BLOCK actions ***
        Write-Output ('  "'+$filterItem.filterId+'":{') >>$fname
        Write-Output ('    "Name":"'+$filterItem.displayData.name+'","Desc":"'+$filterItem.displayData.description+'",') >>$fname
        Write-Output '    "Conds":[' >>$fname
        $filterItem.filterCondition.item | foreach { $filterCond = $_
          $condition_value_type = $filterCond.conditionValue.type.Replace('FWP_','')
          switch ($filterCond.fieldKey) {
           'FWPM_CONDITION_ALE_APP_ID' { 
              $v = $filterCond.conditionValue.byteBlob.asString.ToLower().Replace('\device\harddiskvolume3\','') }
           'FWPM_CONDITION_ALE_PACKAGE_ID' { $v = $filterCond.conditionValue.sid }
           'FWPM_CONDITION_ALE_SIO_FIREWALL_SYSTEM_PORT' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_ALE_USER_ID' { $v = $filterCond.conditionValue.sd }
           'FWPM_CONDITION_ARRIVAL_INTERFACE_TYPE' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_ARRIVAL_TUNNEL_TYPE' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_CURRENT_PROFILE_ID' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_FLAGS' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_INTERFACE_QUARANTINE_EPOCH' { $v = $filterCond.conditionValue.uint64 }
           'FWPM_CONDITION_IP_ARRIVAL_INTERFACE' { $v = $filterCond.conditionValue.uint64 }
           'FWPM_CONDITION_IP_LOCAL_ADDRESS_TYPE' { $v = $filterCond.conditionValue.uint8 }
           'FWPM_CONDITION_IP_LOCAL_PORT' { $v = $filterCond.conditionValue.uint16 }
           'FWPM_CONDITION_IP_NEXTHOP_INTERFACE' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_IP_PROTOCOL' { $v = $filterCond.conditionValue.uint8; $v = ($v+'('+$protoNames.[int]$v+')') }
           'FWPM_CONDITION_IP_REMOTE_PORT' { $v = $filterCond.conditionValue.uint16 }
           'FWPM_CONDITION_NEXTHOP_INTERFACE_PROFILE_ID' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_NEXTHOP_INTERFACE_TYPE' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_NEXTHOP_TUNNEL_TYPE' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_ORIGINAL_ICMP_TYPE' { $v = $filterCond.conditionValue.uint16 }
           'FWPM_CONDITION_ORIGINAL_PROFILE_ID' { $v = $filterCond.conditionValue.uint32 }
           'FWPM_CONDITION_IP_REMOTE_ADDRESS' {
              switch ($filterCond.matchType) {
                'FWP_MATCH_RANGE' {
                   switch ($filterCond.conditionValue.rangeValue.valueLow.type) {
                     'FWP_BYTE_ARRAY16_TYPE' {
                        $v = $filterCond.conditionValue.rangeValue.valueLow.byteArray16 + ":" + `
                             $filterCond.conditionValue.rangeValue.valueHigh.byteArray16 }
                     'FWP_UINT32' {
                        $v = $filterCond.conditionValue.rangeValue.valueLow.uint32 + ":" + `
                             $filterCond.conditionValue.rangeValue.valueHigh.uint32 }
                      Default { Write-Host WTF1 $filterCond.conditionValue.rangeValue.valueLow.type } # debug
                 } }
                'FWP_MATCH_EQUAL' { $v = $filterCond.conditionValue.uint32 }
                Default { Write-Host WTF2 $filterCond.matchType }                                     # debug
            } }
           Default { Write-Host WTF3 $filterCond.fieldKey }                                           # debug
          }
          Write-Output ('      "'+$filterCond.fieldKey+'":"'+$v+'",') >>$fname
        }
        Write-Output  '    ]},' >>$fname
    } }
  Write-output '],' >>$fname
}
Write-Output '}' >>$fname
Write-Host Active Windows Filtering Platform ALLOW rules dumped to $fname

#  -------------------- Get Windows Security Event Log [Audit] Events ------------------
$evtFilter = @{ LogName='Security'; ID=5152,5156,5157,5158,5159; StartTime=$beginTime }

$evts = Get-WinEvent -FilterHashTable $evtFilter -Oldest | process_evt_item

  ###  With an operating philosophy of 'block everything except', we're looking for  ###
  ###  verification that our 'allow' rules are working as intended, and that there   ###
  ###  isn't any traffic we want blocked leaking in via 'secretly-added' M$ rules.   ###
  ###  To that end, the output of this script is presented in most-valuable last,    ###
  ###  allowing less didactic material to scroll off the top of the window.          ###

  # Not sure what we'll do with these, but some apps like Chromium bind to ports
  # for mysterious purposes yet to be revealed. Some built-in rules are blocking
  # connection attempts when nobody is listening, but in these cases, some other
  # INBOUND rule has to be blocking anything getting to the listened-to port.

Write-Host "`nBlocked Port Bindings:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'BBind' } `
      | remove_repeated_items `
      | Format-Table -View BindView

Write-Host "`nAllowed Port Bindings:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'ABind' } `
      | remove_repeated_items `
      | Format-Table -View BindView

  # Blocked Inbounds is useful for diagnosing the *absence* of an expected behavior;
  # Seeing successful blocking of intrusive attempts is predominately 'noise reporting'.
  # Since all 'blocked' traffic can be 'noise', don't employ 'remove_noise_items'.
  # Don't hit ARIN for all the internet IPs - inconsiderate and takes time.

Write-Host "`nBlocked Inbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'I' -and ($_.Op -eq $opNames.'Block' -or $_.Op -eq $opNames.'Deny') } `
   <# | remove_noise_items #> | remove_repeated_items <# | domain_from_IP($true) #> `
      | Format-Table -View BlockInView    # | Out-String -Width 256

  # Blocked Outbounds helps diagnose dysfunction of a desired behavior - to find a rule
  # that is [inadvertantly] precluding communication needed by some software facility.
  # Our 'block everthing except' philosophy is challenging for web browsing.
  # We give browsers the freedom to 'go [almost] anywhere' on port 443 with additional
  # higher-priority rules to block access to selected domains like Google, FB, etc.
  # Again, visualizing successfully blocked malignant behavior is 'noise reporting'.
  # Don't hit ARIN for all the internet IPs - inconsiderate and takes time.

Write-Host "Blocked Outbounds:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'O' -and ($_.Op -eq $opNames.'Block' -or $_.Op -eq $opNames.'Deny') } `
      | remove_repeated_items <# | domain_from_IP #> `
      | Format-Table -View BlockOutView   # | Out-String -Width 256

  # Allowed Inbounds is mostly for identifying ALLOW rules secretly added and invisible to the GUI.
  # We overtly allow almost nothing inbound, but M$ crap generally adds some relatively low risk inbounds.

Write-Host "Allowed Inbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'I' -and $_.Op -eq $opNames.'Allow' } `
      | remove_noise_items | remove_repeated_items | domain_from_IP($true) `
      | Format-Table -View AllowInView    # | Out-String -Width 256

  # Allowed Outbounds is to look for privacy threats - software silently 'phoning home' and
  # getting past 'block everything' by secretly adding ALLOW rules the GUI cannot see.

Write-Host "Allowed Outbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'O' -and $_.Op -eq $opNames.'Allow' } `
      | remove_noise_items | remove_repeated_items | domain_from_IP `
      | Format-Table -View AllowOutView    # | Out-String -Width 1024
