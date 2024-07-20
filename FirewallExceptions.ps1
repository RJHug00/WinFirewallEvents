<#
  This script captures details of firewall ALLOW and BLOCK activity as detected by
  Windows Filtering Platform and produces tabular reductions of the results.
  
  I caution anyone from firing this up and letting it run for long periods of time
  with no particular idea what activity they are looking for. Even the reductions
  done by this script can produce voluminous outputs requiring study.  Additionally,
  a long run can fill the Windows Security log such that it wraps around.

  NOTE the fundamental flaw with associating a hostname with an IP - webserver hosts
  can serve HTTP[s] for multiple domains, and we might point to the wrong domain.
#>

  param( [switch]$noBrowser )  # suppress normal launch of $browser

$netIF = 'Wi-Fi'   # network interface being scrutinized for Get-NetIPAddress()

if (-not $noBrowser) {
 #$browser = 'C:\Program Files (x86)\Chromium_119.0.6045.123-1.1\chrome.exe'
  $browser = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'

  $bProcNm = Split-Path $browser -Leaf; $bProcNm -match '([^.]*)' >$null; $bProcNm = $matches[1]
  $bs = Get-Process $bProcNm 2>$null
  if ($bs.length -gt 0) { throw [System.ApplicationException]::New('Terminate your web browser and try again') }
} else { $bProcNm = 'None' }

$tmpDir = 'C:\Windows\Temp\Firewall'; $netLogF = $tmpDir + '\netLog-' + $bProcNm + '.JSON'

$hostAliasDelimiter = ';'

# https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
$protoNames = [System.Collections.HashTable] @{ 1="ICMP"; 2="IGMP"; 4="IPv4"; 6="TCP"; 9="IGP"; 17="UDP" }

# https://en.wikipedia.org/wiki/List_of_TCP_and_UDP_port_numbers
$portNames = [System.Collections.HashTable] @{ 53="DNS";   67="DHCP";  68="DHCP";    80="HTTP";  123="NTP";
                                              137="NetB"; 161="SNMP"; 443="HTTPS"; 5353="mDNS"; 5355="LLMNR" }

$opNames = [System.Collections.HashTable] @{ "Allow"="A"; "Block"="B"; "Deny"="D";    "Veto"="V";   "Rule"="R";
                                             "ABind"="Y"; "DBind"="X"; "AListen"="L"; "DListen"="M" }

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
          [Security.Principal.WindowsBuiltInRole] 'Administrator')) {
  throw [System.ApplicationException]::New('Script must be run as Adminstrator') }

$rdap = 'https://rdap.db.ripe.net/ip/'                         # Seems to behave well as an RDAP bootstrapper
#$rdap = 'https://rdap-bootstrap.arin.net/bootstrap/ip/'       # Works, but I choose to avoid using it
#$rdap = 'https://rdap.cloud/api/v1/' 'https://www.rdap.net/'  # alternative 'brand X' bootstrappers

# Format-Table truncates lots of info without predefined views for our PSCustomObject
Update-FormatData -AppendPath .\myWFPEventEntry.types.ps1xml

New-Item -Path (Split-Path $tmpDir -Parent) -Name (Split-Path $tmpDir -Leaf) -ItemType 'Directory' *>$null

$myIPAddress = (Get-NetIPAddress -InterfaceAlias $netIF).IPAddress
$myIPAddress -match '(.*[.])[0-9]*' *>$null
$myLan = $matches[1]

$IPdict        = [System.Collections.HashTable] @{ } # IP-to-hostname lookups from browser's netLog
$cachedLookups = [System.Collections.HashTable] @{ } # IP-to-owner lookups from RDAP

#  -------------------- Turn on audit events in Windows Security event log -------------------------
<# https://learn.microsoft.com/en-us/windows/win32/fwp/auditing-and-logging

 Subcategory                      EventIDs (* means we process that ID)
 -------------------------------- -----------------------------------------
 Filtering Platform Policy Change 5440 Persistent callout added
                                  5441 Boot-time or persistent filter added
                                  5442 Persistent provider added
                                  5443 Persistent provider context added
                                  5444 Persistent sub-layer added
                                  5446 Run-time callout added or removed
                                 *5447 Run-time filter added or removed
                                  5448 Run-time provider added or removed
                                  5449 Run-time provider context added or removed
                                  5450 Run-time sub-layer added or removed
 Filtering Platform Packet Drop  *5152 Packet Dropped
                                 *5153 Packet Vetoed - have yet to see one of these
 Filtering Platform Connection   *5154 Listen Allowed
                                 *5155 Listen Blocked
                                 *5156 Connection Allowed
                                 *5157 Connection Blocked
                                  5158 Bind Allowed - copious events that are essentially useless
                                  5159 Bind Blocked - have yet to see one of these
#>

$beginTime = Get-Date   # when we turned auditing on

$evtFilter = @{ LogName='Security'; ID=5152,5153,5154,5155,5156,5157,5447; StartTime=$beginTime }

try {
  auditpol /set /subcategory:"Filtering Platform Packet Drop"   /success:enable /failure:enable 1>$null
  auditpol /set /subcategory:"Filtering Platform Connection"    /success:enable /failure:enable 1>$null
  auditpol /set /subcategory:"Filtering Platform Policy Change" /success:enable /failure:enable 1>$null

  #Test-Connection -IPv4 -TargetName 192.168.1.1 -Count 1 -Quiet *>$null   # diagnostic landmark

  if (-not $noBrowser) {
    $argList = @(('--log-net-log='+$netLogF))  # ,'-incognito')
    $proc = Start-Process -FilePath $browser -ArgumentList @argList
                        # -Passthru --user-data-dir=($tmpDir+'chrome')
  }

  Read-Host Press ENTER after network operations of interest are finished

  Write-Host "Patience - this can take a few minutes for lengthy or complex capture sessions"

  if (-not $noBrowser) {
    $mainPID = 0
    foreach ($p in Get-Process $bProcNm) {
      $q = Get-Process -Id $p.Parent.Id
      if ($q.Name -ne $p.Name) {
         $mainPID = $p.Id  # Write-Host Parent of $p.Id is $q.Name
         $p.CloseMainWindow() >$null
    } }
    if ($mainPID -ne 0) {  # sleeping so the netlog file gets flushed; occasionally still causes trouble
      Sleep 3; Stop-Process -Id $mainPID 2>$null
      while ((Get-Process -Id $mainPID 2>$null) -ne $null) {Sleep 1}  # TODO this could use a runaway counter
  } }

  Write-Host "`nAudit events captured between" $beginTime "and" (Get-Date)

  #Test-Connection -IPv4 -TargetName 192.168.1.1 -Count 1 -Quiet *>$null   # diagnostic landmark
}
finally {
  auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable 1>$null
  auditpol /set /subcategory:"Filtering Platform Connection"    /success:disable /failure:disable 1>$null
  auditpol /set /subcategory:"Filtering Platform Packet Drop"   /success:disable /failure:disable 1>$null
}

#  -------------------- Acquire the active Windows Firewall rules ----------------------------------
       # This sees only rules for the active network profile (e.g. Private)
       # but most importantly reveals ALLOW rules secretly/dynamically added.
       # Its too much data to output to the console, so a file is written.

New-Variable -Name filtersXml
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
Write-Host "`nActive Windows Filtering Platform ALLOW rules dumped to" $fname

#  -------------------- Acquire [Chromium-based] browser's net-log for DNS requests ----------------

if (-not $noBrowser) {

  $sourceLinkages = [System.Collections.HashTable] @{ }

  # Note - this throws if the browser wasn't given sufficient time to close the file before our read.
  $netLog = Get-Content -Raw $netLogF | ConvertFrom-Json
  foreach ($e in $netLog.events)
  {
     # For MSEDGE and Chromium, TYPE 18 PHASE 2 [almost] always gives the pairs of hostname/IP that i want.
     # The balance come from TYPE 9 / TYPE 17 pairs. Type 5 looks tempting, but is actually redundant.
     # MSEdge has a tiny set of M$ IPs it uses internally that don't show up in the net-log.

     if ($e.type -eq 18) {
       if ($e.phase -eq 2) {
         foreach ($ipe in $e.params.results.ip_endpoints) { $ip = $ipe.endpoint_address
           $aliases = $IPDict.$ip
           if ($aliases -eq $null) { $aliases = ''  # if it didn't exist in IPDict, initialize
             foreach ($a in $e.params.results.aliases) { $aliases = ($hostAliasDelimiter + $a + $aliases) }
             if ($aliases -ne '') {
               $IPDict[$ip] = $aliases.substring(1)
             } else {
               Write-Host PATHOLOGICAL TYPE 18 produced empty alias string
     } } } } }
     elseif ($e.type -eq 9) {   # really just capturing hostname for subsequent TYPE 17
       if ($e.phase -eq 1) {
         $sid = $e.source.id
         if ($sourceLinkages.$sid -ne $null) {
           Write-Host TYPE 9 already had a sourceLinkage for ID $sid DEBUG - should not see this
         } else {
           if ($e.params.host -ne '') {
             $sourceLinkages[$sid] = $e.params.host
           } else {
             Write-Host PATHOLOGICAL - TYPE 9 host was an empty string
     } } } }
     elseif ($e.type -eq 17) {  # there arent many of these, but they provide unique IPs
       foreach ($ipe in $e.params.address_list) {
         $ipe -match '(.*):' >$null; $ip = $matches[1]
         if ($IPDict.$ip -eq $null) {
           $sid = $e.source.id; $h = $sourceLinkages.$sid   # TYPE 9 ensured sourceLinkages doesn't contain any blanks
           $IPDict[$ip] = $h
  }  } } }

  # Prune excessively long hostnames in IPDict

  foreach ($k in $($IPDict.Keys)) {
    $aliases = $IPDict.$k; $ary = $aliases -split $hostAliasDelimiter; $aliases = ''
    foreach ($a in $ary) {
      if ($a.length -gt 32) {  # hostnames are often stupidly long w/o helpful hints
        $nodes = $a -split '\.'; $numNodes = $nodes.length
        if ($numNodes -gt 3) { $numNodes--; $a = $nodes[0] + '...' + $nodes[$numNodes-1] + '.' + $nodes[$numNodes] }
      }
      $aliases = ($hostAliasDelimiter + $a + $aliases)
    }
    $IPDict[$k] = $aliases.substring(1)
  }
}
#  -------------------- Pipeline filtering functions ------------------------------
function remove_noise_items {   # optional [hardcoded] pipeline component
                                # I suggest removing it from pipelines and see your own 'noise'
  Process { $o = $_
    switch ($o.Proto) {   # its easier to remember rationales for exceptions this way
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
          # LAN peers incessantly asking for name resolutions
          if ($o.Dst -eq '224.0.0.252' -and $o.Src -like 'LAN.*') {return}
          # allow the spooler to talk to the Canon printer
         if ($o.App -eq 'spoolsv' -and $o.Dst -eq 'LAN.250') {return}
        }
        elseif ($o.Dir -eq 'I') {
         # Cloudflare DNS keeps trying to udp me that gets blocked (got through the router???)
         #if ($o.Src -eq '1.1.1.1' -and $o.Dst -eq 'me') {return}
         # The router broadcasts periodically [and is blocked]
          if ($o.Src -eq 'LAN.1' -and $o.Dst -eq '255.255.255.255') {return}
         # The Canon printer on port 5353 (multicast DNS)
          if ($o.Src -eq 'LAN.250' -and $o.Dst -eq '224.0.0.251' -and $o.DPort -eq 'mDNS') {return}
         # there's a 0.0.0.0 -> 255.255.255.255 DHCP that is probably noise, but I want to see it for now
      } }
      'IGMP' {
        if ($o.Dir -eq 'O') {
          # Windows routinely probes the LAN via 224.*
          if ($o.App -eq 'system' -and $o.Dst -like '224.0.0.*') {return}
        }
        elseif ($o.Dir -eq 'I') { # observe LAN hosts being nosy
          if ($o.Src -eq 'LAN.1')   {return} # router
          if ($o.Src -eq 'LAN.254') {return} # extender
      } }
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
    } }
    $o
} }

function remove_repeated_items {  # optional pipeline component compares [almost] entire object
  Process {
    foreach ($li in $UniqueList) { # ignore $_.Op (BLOCK,DENY are similar enough)
      if ($_.Dir -eq $li.Dir -and $_.Proto -eq $li.Proto -and $_.Filter -eq $li.Filter -and
          $_.Src -eq $li.Src -and $_.Dst   -eq $li.Dst   -and $_.DPort  -eq $li.DPort  -and
          $_.PID -eq $li.PID -and $_.App   -eq $li.App   -and $_.Folder -eq $li.Folder) { return }
    }
    $UniqueList.add($_); $_
} }

  # In the face of 'cloud computing' A bad actor's IP becomes the name of
  # a cloud purvor that is a forest of good and bad actors mixed together.
  # Knowing who *owns* the IP often/usually doesn't help.

function owner_from_IP {           # Use RDAP to identify CIDR owner
  param ( [bool] $source = $false )
  Process { $o = $_; $p1 = $source ? $o.src : $o.dst
    $o.dstNm = $p1  # fallback answer if all else fails is the original IP
    switch -wildcard ($p1) {
      'me'      {}  # current host
      '0.0.0.0' {}  # I don't know why we see this, but don't look it up
      '1.1.1.1' {}  # DNS for my site (Cloudflare) - don't look it up
      '127.*'   {}  # Loopback
      'LAN.*'   {}  # local network
      '224.0.0.251' { $answer = "mDNS" }
      '224.0.0.252' { $answer = "mLLMNR" }
      '224.*'   {}  # 224 through 239 are multicast but NOT EXCLUSIVELY LAN!
      '225.*'   {}  # Reserved and shouldn't be seen
      '232.*'   {}  # 'Source-specific multicast'
      '233.*'   {}  # GLOP and AD-HOC
      '234.*'   {}  # 'Unicast-prefix-based'
      '235.*'   {}  # shouldn't see this
      '236.*'   {}  # shouldn't see this
      '237.*'   {}  # shouldn't see this
      '238.*'   {}  # shouldn't see this
      '239.*'   {}  # 'Administratively-scoped' Multicast
      'Broad*'  {}  # Broadcast - 255.255.255.255
      '::1'     {}  # I think its loopback

      Default {     # only query RDAP for stuff we don't recognize
        $answer = $cachedLookups.$p1
        $retries = 10
        while ($answer.length -eq 0 -and $retries -gt 0) {
          Start-Sleep -Seconds 2  # don't flood RDAP with queries
          $uri = $rdap + $p1
          try {
            $rir = Invoke-WebRequest -SkipCertificateCheck -SkipHeaderValidation -URI $uri # -Headers @{"a"="b"}

            if ($rir -eq $null) {         throw [System.ApplicationException]::New('no response') }
            if ($rir.Content -eq $null) { throw [System.ApplicationException]::New('no response content') }
            $infoS = [System.Text.Encoding]::UTF8.GetString($rir.Content)
            $info = $infoS | ConvertFrom-Json
            if ($info -eq $null) {        throw [System.ApplicationException]::New('no JSON object') }
            $answer = $info.Name
          }
          catch { Write-Host $uri $_.Exception.Message
            $retries--
            if ($retries -eq 0) { $answer = $p1 } #last ditch fallback
        } }
	if ($answer.Length -gt 20) { $answer = $answer.Substring(0,19) }
        $vcard = '?'
        try { $vCard = $info.entities.vCardArray[1][1][3] } # hopefully populated
        catch {}
        $answer = -join($answer,'(',$vCard,')')
        $cachedLookups[$p1] = $answer

        if ($source) { $o.src = $answer } else { $o.dstNm = $answer }
    } }
    $o
} }

  # Limited to web browser traffic only, we use the browser's net-log to see the
  # hostnames it is trying to resolve for the web-page. It doesn't help determine
  # what svchost or other detached processes are doing.

function name_from_IP {             # Use Chromium (Chrome, Edge, Chromium) net-log for reverse IP
  param ( [bool] $source = $false )
  Process { $o = $_; $p1 = $source ? $o.src : $o.dst
    $o.dstNm = $p1  # fallback answer if all else fails is the original IP
    switch -wildcard ($p1) {
      'me'      {}  # current host
      '0.0.0.0' {}  # I don't know why we see this, but don't look it up
      '1.1.1.1' {}  # DNS for my site (Cloudflare) - don't look it up
      '127.*'   {}  # Loopback
      'LAN.*'   {}  # local network
      '224.0.0.251' { $answer = "mDNS" }
      '224.0.0.252' { $answer = "mLLMNR" }
      '224.*'   {}  # 224 through 239 are multicast but NOT EXCLUSIVELY LAN!
      '225.*'   {}  # Reserved and shouldn't be seen
      '232.*'   {}  # 'Source-specific multicast'
      '233.*'   {}  # GLOP and AD-HOC
      '234.*'   {}  # 'Unicast-prefix-based'
      '235.*'   {}  # shouldn't see this
      '236.*'   {}  # shouldn't see this
      '237.*'   {}  # shouldn't see this
      '238.*'   {}  # shouldn't see this
      '239.*'   {}  # 'Administratively-scoped' Multicast
      'Broad*'  {}  # Broadcast - 255.255.255.255
      '::1'     {}  # I think its loopback

      Default {
        $answer = $IPDict.$p1
        if ($answer.length -gt 0) {
          if ($source) { $o.src = $answer } else { $o.dstNm = $answer }
        }
        else {
          # remember that not all DNS lookups come from browser activity,
          # that limited applications employ the dnscache service,
          # and that the era of secure DNS is increasingly hiding other lookups -
          # there will be IP addresses we have no name for
          # and must fallback to just getting the owner of the IP address.
          #Write-Host IP that wasnt in net-log
          $x = $o | owner_from_IP
          $answer = $x.dstNm
          if ($source) { $o.src = $answer } else { $o.dstNm = $answer }
    } } }
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

    # diagnostic - I suspect this event's JSON has different members than what we look for.
    # I want to know a lot about which rule is being deleted or what the added rule is doing.
    if ($_.Op -eq 5447) { $_ | Format-List >>($tmpDir+'\RuleChange.json') }

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
           $cmd = $cmd.CommandLine   #.ToLower().Replace("c:\windows\system32\svchost.exe","svchost")
           $cmd -match '.*-[Ss] (.*)' >$null
           $appWithPid = 'svchost ' + $matches[1] + '(' + $processId + ')'
         } else { $appWithPid = 'svchost(phantom)' }   # it started and stopped
      }
      Default {
        $appWithPid = $appName + '(' + $processId + ')'
    } }

    Switch (     [string]$_.GetPropertyValues((selector 'Direction'))) {
      '%%14592' { $direction = 'I' }
      '%%14593' { $direction = 'O' }
    }

    Switch ($_.Id) {
      5152 { $op = $opNames.'Block' }   # Firewall Blocked a packet
      5154 { $op = $opNames.'AListen' } # Allowed Listen
      5155 { $op = $opNames.'DListen' } # Blocked Listen
      5156 { $op = $opNames.'Allow' }   # Firewall Allowed a Connection
      5157 { $op = $opNames.'Deny' }    # Firewall Blocked a Connection
      5158 { $op = $opNames.'ABind' }   # Firewall Allowed a Port Bind (copious)
      5159 { $op = $opNames.'DBind' }   # Firewall Blocked a Port Bind (very rare)
      5153 { $op = $opNames.'Veto'; Write-Host Got A VETO }  # Firewall Blocked a packet [via more restrictive rule?]
      5447 { $op = $opNames.'Rule' }    # Firewall rule dynamically added or removed
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
     #Serial = ++$objSerialNum
    }
    $pco.psobject.typenames.insert(0, "myWFPEventEntry")  # support named views with Format-Table
    $pco
} }

#  -------------------- Get Windows Security Event Log [Audit] Events ------------------

$evts = Get-WinEvent -FilterHashTable $evtFilter -Oldest | process_evt_item

# capture a raw dump for reference when our tabular displays lose information.

$evts | Format-List >($tmpDir+'\eventDump.txt')

  ###  With an operating philosophy of 'block everything except', we're looking for  ###
  ###  verification that our 'allow' rules are working as intended, and that there   ###
  ###  isn't any traffic we want blocked leaking in via dynamically-added' rules.    ###
  ###  To that end, the output of this script is presented in most-valuable last,    ###
  ###  allowing less didactic material to scroll off the top of the window.          ###

  # Port Binds, allowed being numerous and blocked virtually non-existent, have
  # shown to be somewhat low-value. There are built-in rules blocking inbounds to
  # ports that have no listener, but we're concerned with appplications trying
  # to establish alternate communications channels (like CHROME and MSEDGE)

    <#
Write-Host "`nBlocked Port Bindings:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'DBind' } `
      | remove_repeated_items | Format-Table -View BindView

Write-Host "`nAllowed Port Bindings:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'ABind' } `
      | remove_repeated_items | Format-Table -View BindView
    #>

  # Blocked Port Listens have thus-far been almost non-existent.
  # Chromium and Edge bind and listen for reasons unknown.

Write-Host "`nBlocked Port Listens:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'DListen' } `
      | remove_repeated_items | Format-Table -View BindView

Write-Host "Allowed Port Listens:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'AListen' } `
      | remove_repeated_items | Format-Table -View BindView

  # Rule Changes is new, being researched, and not debugged.
  # We don't want things secretly circumventing our firewall policies.

Write-Host "Dynamic Filter (Firewall rule) Changes:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Op -eq $opNames.'Rule' } `
   <# | remove_repeated_items #> | Format-Table -View AllowOutView

  # Blocked Inbounds is useful for diagnosing the *absence* of an expected behavior;
  # Seeing successful blocking of intrusive attempts is predominately 'noise reporting'.
  # Since all 'blocked' traffic can be 'noise', don't employ 'remove_noise_items'.
  # Don't hit RDAP for all the internet IPs - inconsiderate and takes time.

Write-Host "`nBlocked Inbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'I' -and
                      ($_.Op -eq $opNames.'Block' -or $_.Op -eq $opNames.'Deny'-or $_.Op -eq $opNames.'Veto') } `
    <#| remove_noise_items #> | remove_repeated_items <# | name_from_IP($true) #> `
      | Format-Table -View BlockInView    # | Out-String -Width 256

  # Blocked Outbounds helps diagnose dysfunction of a desired behavior - to find a rule
  # that is [inadvertantly] precluding communication needed by some software facility.
  # Our 'block everthing except' philosophy is challenging for web browsing.
  # We give browsers the freedom to 'go [almost] anywhere' on port 443 with additional
  # higher-priority rules to block access to selected domains like Google, FB, etc.
  # Again, visualizing successfully blocked malignant behavior is 'noise reporting'.
  # Don't hit RDAP for all the internet IPs - inconsiderate and takes time.

Write-Host "Blocked Outbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'O' -and
                      ($_.Op -eq $opNames.'Block' -or $_.Op -eq $opNames.'Deny'-or $_.Op -eq $opNames.'Veto') } `
      | remove_noise_items | remove_repeated_items <# | name_from_IP #> `
      | Format-Table -View BlockOutView   # | Out-String -Width 256

  # Allowed Inbounds is mostly for identifying ALLOW rules secretly added and invisible to the GUI.
  # We overtly allow almost nothing inbound, but M$ crap generally adds some relatively low risk inbounds.

Write-Host "Allowed Inbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'I' -and $_.Op -eq $opNames.'Allow' } `
      | remove_noise_items | remove_repeated_items | name_from_IP($true) `
      | Format-Table -View AllowInView    # | Out-String -Width 256

  # Allowed Outbounds is to look for privacy threats - software silently 'phoning home' and
  # getting past 'block everything' by secretly adding ALLOW rules the GUI cannot see.

Write-Host "`nAllowed Outbound Connections:"
$UniqueList = [System.Collections.Generic.list[object]]::new()
$evts | Where-Object { $_.Dir -eq 'O' -and $_.Op -eq $opNames.'Allow' } `
      | remove_noise_items | remove_repeated_items | name_from_IP `
      | Format-Table -View AllowOutView    # | Out-String -Width 1024

<#
  HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters   EnableAutoDoh  Dword: 2
  MSEDGE can be told via settings to use DNSCACHE
#>
<#
  Some diagnostic reverse-engineering logic I'm not ready to discard yet

  if ($e.params -ne $null) {
    $rslts = $e.params.results
    $a = ''; $b = ''; $c = ''; $d = ''; $f = ''; $g = ''
    if ($rslts -ne $null) {
      if ($rslts.aliases -ne $null) { $a = 'ALIASES:[' + $rslts.aliases + ']' }
      if ($rslts.addresses -ne $null) { $b = 'ADDRESSES:[' + $rslts.addresses + ']' }
      if ($rslts.ip_endpoints -ne $null) {
        $c = 'IPS:['
        foreach ($x in $rslts.ip_endpoints) { $c = $c + ' ' + $x.endpoint_address }
        $c = $c + ']'
    } }
    else { # params with no results           "qname" is ignored as redundant
      if ($e.params.host -ne $null) { $d = 'HOST:' + $e.params.host }
      if ($e.params.hostname -ne $null) { $f = 'HOSTNAME:' + $e.params.hostname }
      if ($e.params.address -ne $null) {  # only output IPv4
        if (-not $e.params.address -match '::') {
          $g = 'ADDRESS:;' + $e.params.address
    } } }
    if (($a+$b+$c+$d+$f+$g) -ne '') {
      Write-Host SRC $e.source.id $a $b $c $d $f $g PHASE $e.phase TYPE $e.type }
  }
#>