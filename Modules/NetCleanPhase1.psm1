# ---------------------------------------------------------------------------
# Phase 1 - Detect helpers
# ---------------------------------------------------------------------------

<#
.SYNOPSIS
Retrieves evidence of WFP (Windows Filtering Platform) state information.
.DESCRIPTION
Scans the WFP state to identify installed filter objects and extracts relevant properties. Attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-WfpStateEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing WFP filter objects, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges to access WFP state information.
#>
function Get-WfpStateEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $tempFile = Join-Path $env:TEMP ("netclean_wfp_{0}.xml" -f ([guid]::NewGuid().Guid))

    try {
        & netsh wfp show state file="$tempFile" 2>$null | Out-Null

        if (-not (Test-Path -LiteralPath $tempFile)) {
            return @()
        }

        [xml]$xml = Get-Content -LiteralPath $tempFile -Raw -ErrorAction Stop
        $xmlNodes = @()

        if ($xml -and $xml.DocumentElement) {
            $xmlNodes = $xml.SelectNodes('//*')
        }

        foreach ($node in @($xmlNodes)) {
            $textParts = @()

            foreach ($prop in @('displayData', 'name', 'description', 'serviceName', 'providerKey', 'calloutKey', 'layerKey')) {
                try {
                    $value = $node.$prop
                    if ($value) {
                        $textParts += ($value | Out-String).Trim()
                    }
                }
                catch {
                    Write-Verbose "Failed to extract property '$prop' from WFP XML node: $_"
                }
            }

            $joined = ($textParts | Where-Object { $_ }) -join ' '
            if ([string]::IsNullOrWhiteSpace($joined)) {
                continue
            }

            $vendor = Resolve-VendorFromText -Text @($joined)

            $results.Add([pscustomobject]@{
                    Source               = 'WFP'
                    ProductClass         = 'WfpObject'
                    Name                 = $joined
                    DisplayName          = $joined
                    Path                 = $null
                    Publisher            = $null
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = $null
                    FileDescription      = $null
                    ProductName          = $null
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    XmlNodeName          = $node.Name
                    Instance             = $node.OuterXml
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }
    finally {
        if (Test-Path -LiteralPath $tempFile) {
            Remove-Item -LiteralPath $tempFile -Force -ErrorAction SilentlyContinue
        }
    }

    return $results.ToArray() | Sort-Object Name -Unique
}

<#
.SYNOPSIS
Retrieves evidence of NDIS filter classes from the registry.
.DESCRIPTION
Scans the registry under the NDIS class keys to identify installed network filter classes. Extracts relevant properties and attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-NdisFilterClassEvidence
.OUTPUTS
A collection of custom objects representing NDIS filter class evidence, including properties such as Name, DisplayName, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges for full access to registry keys.
#>
function Get-NdisFilterClassEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object 'System.Collections.Generic.List[object]'
    $classRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Class\{4d36e974-e325-11ce-bfc1-08002be10318}'

    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $classRoot)) {
        if ($child -notmatch '^\d{4}$') { continue }

        $path = "$classRoot\$child"
        $props = Get-RegistryValuesSafe -RegistryPath $path
        if ($null -eq $props) { continue }

        $text = New-Object 'System.Collections.Generic.List[string]'

        foreach ($propertyName in @(
                'ComponentId',
                'DriverDesc',
                'ProviderName',
                'MatchingDeviceId',
                'FilterClass',
                'Characteristic'
            )) {
            if ($props.PSObject.Properties.Name -contains $propertyName) {
                $value = $props.$propertyName
                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    $text.Add([string]$value)
                }
            }
        }

        if ($text.Count -eq 0) { continue }

        $driverDesc = if ($props.PSObject.Properties.Name -contains 'DriverDesc') { $props.DriverDesc }   else { $null }
        $providerName = if ($props.PSObject.Properties.Name -contains 'ProviderName') { $props.ProviderName } else { $null }
        $componentId = if ($props.PSObject.Properties.Name -contains 'ComponentId') { $props.ComponentId }  else { $null }

        $vendor = Resolve-VendorFromText -Text $text.ToArray()

        $results.Add([pscustomobject]@{
                Source               = 'NDIS'
                ProductClass         = 'NdisFilterClass'
                Name                 = ($text.ToArray() -join ' | ')
                DisplayName          = $driverDesc
                Path                 = $null
                Publisher            = $providerName
                InstallPath          = $null
                InterfaceDescription = $driverDesc
                Manufacturer         = $providerName
                CompanyName          = $providerName
                FileDescription      = $driverDesc
                ProductName          = $componentId
                SignerSubject        = $null
                InferredVendor       = $vendor
                RegistryPath         = $path
                ComponentId          = $componentId
                Instance             = $props
            })
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of NDIS service bindings from the registry.
.DESCRIPTION
Scans the registry under the Services key to identify services that may be related to NDIS bindings. Extracts relevant properties and attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-NdisServiceBindingEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing NDIS service bindings, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges for full access to registry keys.
#>
function Get-NdisServiceBindingEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $servicesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'

    foreach ($svcName in @(Get-RegistryChildKeyNamesSafe -RegistryPath $servicesRoot)) {
        $svcPath = "$servicesRoot\$svcName"
        $linkage = Get-RegistryValuesSafe -RegistryPath "$svcPath\Linkage"
        $props = Get-RegistryValuesSafe -RegistryPath $svcPath

        $tokens = New-Object System.Collections.Generic.List[string]
        $tokens.Add([string]$svcName)

        $displayName = $null
        $group = $null
        $imagePath = $null
        $bindValues = @()
        $exportValues = @()
        $routeValues = @()

        if ($null -ne $props) {
            if ($props.PSObject.Properties.Name -contains 'DisplayName') {
                $displayName = $props.DisplayName
                if ($null -ne $displayName -and "$displayName".Trim() -ne '') {
                    $tokens.Add([string]$displayName)
                }
            }

            if ($props.PSObject.Properties.Name -contains 'Group') {
                $group = $props.Group
                if ($null -ne $group -and "$group".Trim() -ne '') {
                    $tokens.Add([string]$group)
                }
            }

            if ($props.PSObject.Properties.Name -contains 'ImagePath') {
                $imagePath = $props.ImagePath
            }
        }

        if ($null -ne $linkage) {
            if ($linkage.PSObject.Properties.Name -contains 'Bind') {
                $bindValues = @($linkage.Bind)
                foreach ($value in $bindValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }

            if ($linkage.PSObject.Properties.Name -contains 'Export') {
                $exportValues = @($linkage.Export)
                foreach ($value in $exportValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }

            if ($linkage.PSObject.Properties.Name -contains 'Route') {
                $routeValues = @($linkage.Route)
                foreach ($value in $routeValues) {
                    if ($null -ne $value -and "$value".Trim() -ne '') {
                        $tokens.Add([string]$value)
                    }
                }
            }
        }

        $tokenArray = @($tokens | Where-Object { $null -ne $_ -and "$_".Trim() -ne '' })
        if ($tokenArray.Count -eq 0) { continue }

        $joined = ($tokenArray | ForEach-Object { $_.ToString() }) -join ' '
        $vendor = Resolve-VendorFromText -Text @($joined)

        if ($joined.ToLowerInvariant() -match 'ndis|filter|lwf|wfp|vpn|fw|firewall|net|vmswitch|vmnet|vbox|vethernet|packet|inspect|falcon|sentinel|zscaler|globalprotect|forti|anyconnect') {
            $results.Add([pscustomobject]@{
                    Source               = 'NDIS'
                    ProductClass         = 'NdisServiceBinding'
                    Name                 = $svcName
                    DisplayName          = if ($null -ne $displayName -and "$displayName".Trim() -ne '') { $displayName } else { $svcName }
                    Path                 = $imagePath
                    Publisher            = $null
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = $null
                    FileDescription      = $null
                    ProductName          = $null
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    RegistryPath         = $svcPath
                    Instance             = [pscustomobject]@{
                        Service = $props
                        Linkage = $linkage
                    }
                })
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of installed MSI products from the registry.
.DESCRIPTION
Scans the registry under the MSI product keys to identify installed products. Extracts relevant properties such as DisplayName, Publisher, and InstallLocation. Attempts to infer the vendor based on these properties and known patterns.
.EXAMPLE
Get-MsiRegistryEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing installed MSI products, including properties such as Name
.NOTES
Requires appropriate permissions to access the registry keys for installed MSI products.
#>
function Get-MsiRegistryEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object 'System.Collections.Generic.List[object]'

    foreach ($root in @(
            'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products',
            'HKLM\SOFTWARE\Classes\Installer\Products'
        )) {
        foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $root)) {
            $productPath = "$root\$child\InstallProperties"
            $props = Get-RegistryValuesSafe -RegistryPath $productPath
            if ($null -eq $props) { continue }

            $displayName = if ($props.PSObject.Properties.Name -contains 'DisplayName') {
                $props.DisplayName
            }
            else {
                $null
            }

            if ([string]::IsNullOrWhiteSpace([string]$displayName)) { continue }

            $publisher = if ($props.PSObject.Properties.Name -contains 'Publisher') {
                $props.Publisher
            }
            else {
                $null
            }

            $installLocation = if ($props.PSObject.Properties.Name -contains 'InstallLocation') {
                $props.InstallLocation
            }
            else {
                $null
            }

            $uninstallString = if ($props.PSObject.Properties.Name -contains 'UninstallString') {
                $props.UninstallString
            }
            else {
                $null
            }

            $vendorText = New-Object 'System.Collections.Generic.List[string]'
            foreach ($value in @($displayName, $publisher, $installLocation, $uninstallString)) {
                if ($null -ne $value -and -not [string]::IsNullOrWhiteSpace([string]$value)) {
                    $vendorText.Add([string]$value)
                }
            }

            $vendor = Resolve-VendorFromText -Text $vendorText.ToArray()

            $results.Add([pscustomobject]@{
                    Source               = 'MSI'
                    ProductClass         = 'MsiProduct'
                    Name                 = $displayName
                    DisplayName          = $displayName
                    Path                 = $null
                    Publisher            = $publisher
                    InstallPath          = $installLocation
                    InterfaceDescription = $null
                    Manufacturer         = $publisher
                    CompanyName          = $publisher
                    FileDescription      = $null
                    ProductName          = $displayName
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    RegistryPath         = $productPath
                    Instance             = $props
                })
        }
    }

    return $results.ToArray() | Sort-Object Name -Unique
}

<#
.SYNOPSIS
Retrieves evidence of network-related INF files from the system.
.DESCRIPTION
Scans the Windows INF directory for files matching the pattern 'oem*.inf'. Extracts relevant properties such as Provider, Manufacturer, Class, and ClassGuid. Attempts to infer the vendor based on these properties and known patterns.
.EXAMPLE
Get-InfFileEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing network-related INF files, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
Requires appropriate permissions to access the INF directory and read INF files.
#>
function Get-InfFileEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]
    $infDirs = @("$env:windir\INF")

    foreach ($dir in $infDirs) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }

        foreach ($file in @(Get-ChildItem -LiteralPath $dir -Filter 'oem*.inf' -File -ErrorAction SilentlyContinue)) {
            try {
                $content = Get-Content -LiteralPath $file.FullName -ErrorAction Stop

                $provider = $null
                $manufacturer = $null
                $class = $null
                $classGuid = $null

                foreach ($line in $content) {
                    $m = [regex]::Match($line, '^\s*Provider\s*=\s*(.+)$')
                    if (-not $provider -and $m.Success) {
                        $provider = $m.Groups[1].Value.Trim().Trim('"').Trim('%')
                    }

                    $m = [regex]::Match($line, '^\s*Manufacturer\s*=\s*(.+)$')
                    if (-not $manufacturer -and $m.Success) {
                        $manufacturer = $m.Groups[1].Value.Trim().Trim('"').Trim('%')
                    }

                    $m = [regex]::Match($line, '^\s*Class\s*=\s*(.+)$')
                    if (-not $class -and $m.Success) {
                        $class = $m.Groups[1].Value.Trim().Trim('"')
                    }

                    $m = [regex]::Match($line, '^\s*ClassGuid\s*=\s*(.+)$')
                    if (-not $classGuid -and $m.Success) {
                        $classGuid = $m.Groups[1].Value.Trim().Trim('"')
                    }

                    if ($provider -and $manufacturer -and $class -and $classGuid) {
                        break
                    }
                }

                $vendor = Resolve-VendorFromText -Text @($provider, $manufacturer, $class, $file.Name)

                if ($vendor -or ($class -and $class -match 'Net|NetService')) {
                    $results.Add([pscustomobject]@{
                            Source               = 'INF'
                            ProductClass         = 'SetupApiInf'
                            Name                 = $file.Name
                            DisplayName          = $file.Name
                            Path                 = $file.FullName
                            Publisher            = $provider
                            InstallPath          = Split-Path -Path $file.FullName -Parent
                            InterfaceDescription = $null
                            Manufacturer         = $manufacturer
                            CompanyName          = $provider
                            FileDescription      = $class
                            ProductName          = $file.Name
                            SignerSubject        = $null
                            InferredVendor       = $vendor
                            Class                = $class
                            ClassGuid            = $classGuid
                            Instance             = $null
                        })
                }
            }
            catch {
                Write-Verbose "Ignored error: $_"
            }
        }
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of scheduled tasks from the system.
.DESCRIPTION
Queries the system for scheduled tasks and extracts relevant properties. Attempts to infer the vendor based on known patterns in task names, paths, and actions.
.EXAMPLE
Get-ScheduledTaskEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing scheduled tasks, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires appropriate permissions to access scheduled task information.
#>
function Get-ScheduledTaskEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop
        foreach ($task in $tasks) {
            $actions = @($task.Actions)
            $actionText = @()

            foreach ($action in $actions) {
                $actionText += $action.Execute
                $actionText += $action.Arguments
                $actionText += $action.WorkingDirectory
            }

            $vendor = Resolve-VendorFromText -Text @(
                $task.TaskName,
                $task.TaskPath,
                $actionText
            )

            if ($vendor) {
                $results.Add([pscustomobject]@{
                        Source               = 'ScheduledTask'
                        ProductClass         = 'ScheduledTask'
                        Name                 = $task.TaskName
                        DisplayName          = $task.TaskName
                        Path                 = ($actionText -join ' ')
                        Publisher            = $null
                        InstallPath          = $null
                        InterfaceDescription = $null
                        Manufacturer         = $null
                        CompanyName          = $null
                        FileDescription      = $null
                        ProductName          = $task.TaskName
                        SignerSubject        = $null
                        InferredVendor       = $vendor
                        TaskPath             = $task.TaskPath
                        Instance             = $task
                    })
            }
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of AppX packages from the system.
.DESCRIPTION
Queries the system for installed AppX packages and extracts relevant properties. Attempts to infer the vendor based on known patterns.
.EXAMPLE
Get-AppxPackageEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing AppX packages, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires appropriate permissions to access AppX package information for all users.
#>
function Get-AppxPackageEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $results = New-Object System.Collections.Generic.List[object]

    try {
        $packages = Get-AppxPackage -AllUsers -ErrorAction Stop
        foreach ($pkg in $packages) {
            $vendor = Resolve-VendorFromText -Text @(
                $pkg.Name,
                $pkg.PackageFamilyName,
                $pkg.PublisherDisplayName,
                $pkg.InstallLocation
            )

            if ($vendor) {
                $results.Add([pscustomobject]@{
                        Source               = 'AppX'
                        ProductClass         = 'AppxPackage'
                        Name                 = $pkg.Name
                        DisplayName          = $pkg.Name
                        Path                 = $pkg.InstallLocation
                        Publisher            = $pkg.PublisherDisplayName
                        InstallPath          = $pkg.InstallLocation
                        InterfaceDescription = $null
                        Manufacturer         = $pkg.PublisherDisplayName
                        CompanyName          = $pkg.PublisherDisplayName
                        FileDescription      = $null
                        ProductName          = $pkg.Name
                        SignerSubject        = $pkg.Publisher
                        InferredVendor       = $vendor
                        PackageFamilyName    = $pkg.PackageFamilyName
                        Instance             = $pkg
                    })
            }
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    return $results.ToArray()
}

<#
.SYNOPSIS
Retrieves evidence of antivirus and firewall products from the Security Center WMI namespace.
.DESCRIPTION
Queries the 'root/SecurityCenter2' WMI namespace for instances of 'AntivirusProduct' and 'FirewallProduct'. For each product found, extracts relevant properties and attempts to infer the vendor based on known patterns. Also retrieves file metadata for the product executable to enrich the evidence.
.EXAMPLE
Get-ProtectionEvidence
.OUTPUTS
System.Object[] - A collection of custom objects representing antivirus and firewall products, including properties such as Name, DisplayName, Path, Publisher, and InferredVendor.
.NOTES
- Requires administrative privileges to access the 'root/SecurityCenter2' WMI namespace.
#>
function Get-ProtectionEvidence {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $evidence = New-Object System.Collections.Generic.List[object]

    try {
        $avProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'AntivirusProduct' -ErrorAction Stop
        foreach ($item in $avProducts) {
            $meta = Get-FileMetadatum -Path $item.pathToSignedProductExe
            $evidence.Add([pscustomobject]@{
                    Source               = 'SecurityCenter2'
                    ProductClass         = 'AntivirusProduct'
                    Name                 = $item.displayName
                    DisplayName          = $item.displayName
                    Path                 = $item.pathToSignedProductExe
                    Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                    FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                    ProductName          = if ($meta) { $meta.ProductName } else { $null }
                    SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                    InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($item.displayName)) }
                    Instance             = $item
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $fwProducts = Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName 'FirewallProduct' -ErrorAction Stop
        foreach ($item in $fwProducts) {
            $meta = Get-FileMetadatum -Path $item.pathToSignedProductExe
            $evidence.Add([pscustomobject]@{
                    Source               = 'SecurityCenter2'
                    ProductClass         = 'FirewallProduct'
                    Name                 = $item.displayName
                    DisplayName          = $item.displayName
                    Path                 = $item.pathToSignedProductExe
                    Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                    FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                    ProductName          = if ($meta) { $meta.ProductName } else { $null }
                    SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                    InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($item.displayName)) }
                    Instance             = $item
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $services = Get-CimInstance Win32_Service -ErrorAction Stop
        foreach ($svc in $services) {
            $meta = Get-FileMetadatum -Path $svc.PathName
            $evidence.Add([pscustomobject]@{
                    Source               = 'Service'
                    ProductClass         = 'Service'
                    Name                 = $svc.Name
                    DisplayName          = $svc.DisplayName
                    Path                 = $svc.PathName
                    Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                    FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                    ProductName          = if ($meta) { $meta.ProductName } else { $null }
                    SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                    InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($svc.Name, $svc.DisplayName, $svc.PathName)) }
                    State                = $svc.State
                    StartMode            = $svc.StartMode
                    ServiceType          = $svc.ServiceType
                    Instance             = $svc
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $drivers = Get-CimInstance Win32_SystemDriver -ErrorAction Stop
        foreach ($drv in $drivers) {
            $meta = Get-FileMetadatum -Path $drv.PathName
            $evidence.Add([pscustomobject]@{
                    Source               = 'Driver'
                    ProductClass         = 'Driver'
                    Name                 = $drv.Name
                    DisplayName          = $drv.DisplayName
                    Path                 = $drv.PathName
                    Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                    FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                    ProductName          = if ($meta) { $meta.ProductName } else { $null }
                    SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                    InferredVendor       = if ($meta) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($drv.Name, $drv.DisplayName, $drv.PathName)) }
                    State                = $drv.State
                    StartMode            = $drv.StartMode
                    ServiceType          = $drv.ServiceType
                    Instance             = $drv
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    foreach ($root in @(
            'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
            'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
        )) {
        try {
            Get-ItemProperty -Path $root -ErrorAction SilentlyContinue | ForEach-Object {
                if ($_.DisplayName) {
                    $meta = $null
                    if ($_.DisplayIcon) {
                        $meta = Get-FileMetadatum -Path $_.DisplayIcon
                    }

                    $evidence.Add([pscustomobject]@{
                            Source               = 'Uninstall'
                            ProductClass         = 'InstalledProduct'
                            Name                 = $_.DisplayName
                            DisplayName          = $_.DisplayName
                            Path                 = $_.DisplayIcon
                            Publisher            = $_.Publisher
                            InstallPath          = $_.InstallLocation
                            InterfaceDescription = $null
                            Manufacturer         = $_.Publisher
                            CompanyName          = if ($meta) { $meta.CompanyName } else { $_.Publisher }
                            FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                            ProductName          = if ($meta) { $meta.ProductName } else { $_.DisplayName }
                            SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                            InferredVendor       = if ($meta -and $meta.InferredVendor) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($_.DisplayName, $_.Publisher, $_.InstallLocation, $_.UninstallString)) }
                            UninstallString      = $_.UninstallString
                            Instance             = $_
                        })
                }
            }
        }
        catch {
            Write-Verbose "Ignored error: $_"
        }
    }

    try {
        $adapters = Get-NetAdapter -IncludeHidden -ErrorAction Stop
        foreach ($adapter in $adapters) {
            $vendor = Resolve-VendorFromText -Text @(
                $adapter.Name,
                $adapter.InterfaceDescription,
                $adapter.DriverDescription,
                $adapter.DriverFileName
            )

            $guidValue = $null
            try {
                $guidValue = $adapter.InterfaceGuid.Guid.ToString().ToLowerInvariant()
            }
            catch {
                try {
                    $guidValue = $adapter.InterfaceGuid.ToString().Trim('{}').ToLowerInvariant()
                }
                catch {
                    $guidValue = $null
                }
            }

            $evidence.Add([pscustomobject]@{
                    Source               = 'NetAdapter'
                    ProductClass         = 'Adapter'
                    Name                 = $adapter.Name
                    DisplayName          = $adapter.Name
                    Path                 = $null
                    Publisher            = $null
                    InstallPath          = $null
                    InterfaceDescription = $adapter.InterfaceDescription
                    Manufacturer         = $null
                    CompanyName          = $null
                    FileDescription      = $null
                    ProductName          = $adapter.InterfaceDescription
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    InterfaceGuid        = $guidValue
                    MacAddress           = $adapter.MacAddress
                    Status               = $adapter.Status
                    Instance             = $adapter
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    try {
        $pnpNet = Get-PnpDevice -Class Net -ErrorAction Stop
        foreach ($dev in $pnpNet) {
            $vendor = Resolve-VendorFromText -Text @(
                $dev.FriendlyName,
                $dev.Manufacturer,
                $dev.InstanceId
            )

            $evidence.Add([pscustomobject]@{
                    Source               = 'PnpDevice'
                    ProductClass         = 'NetDevice'
                    Name                 = $dev.FriendlyName
                    DisplayName          = $dev.FriendlyName
                    Path                 = $null
                    Publisher            = $null
                    InstallPath          = $null
                    InterfaceDescription = $dev.FriendlyName
                    Manufacturer         = $dev.Manufacturer
                    CompanyName          = $dev.Manufacturer
                    FileDescription      = $null
                    ProductName          = $dev.FriendlyName
                    SignerSubject        = $null
                    InferredVendor       = $vendor
                    InstanceId           = $dev.InstanceId
                    Status               = $dev.Status
                    Class                = $dev.Class
                    Instance             = $dev
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    $servicesRoot = 'HKLM\SYSTEM\CurrentControlSet\Services'
    try {
        foreach ($svcName in @(Get-RegistryChildKeyNamesSafe -RegistryPath $servicesRoot)) {
            $svcRegPath = "$servicesRoot\$svcName"
            $svcProps = Get-RegistryValuesSafe -RegistryPath $svcRegPath
            if ($null -eq $svcProps) { continue }

            $imagePath = $svcProps.ImagePath
            $displayName = $svcProps.DisplayName
            $meta = Get-FileMetadatum -Path $imagePath

            $evidence.Add([pscustomobject]@{
                    Source               = 'ServiceRegistry'
                    ProductClass         = 'ServiceRegistry'
                    Name                 = $svcName
                    DisplayName          = $displayName
                    Path                 = $imagePath
                    Publisher            = if ($meta) { $meta.CompanyName } else { $null }
                    InstallPath          = $null
                    InterfaceDescription = $null
                    Manufacturer         = $null
                    CompanyName          = if ($meta) { $meta.CompanyName } else { $null }
                    FileDescription      = if ($meta) { $meta.FileDescription } else { $null }
                    ProductName          = if ($meta) { $meta.ProductName } else { $null }
                    SignerSubject        = if ($meta) { $meta.SignerSubject } else { $null }
                    InferredVendor       = if ($meta -and $meta.InferredVendor) { $meta.InferredVendor } else { (Resolve-VendorFromText -Text @($svcName, $displayName, $imagePath)) }
                    ServiceRegistryPath  = $svcRegPath
                    Start                = $svcProps.Start
                    Type                 = $svcProps.Type
                    Group                = $svcProps.Group
                    Instance             = $svcProps
                })
        }
    }
    catch {
        Write-Verbose "Ignored error: $_"
    }

    foreach ($item in @(Get-WfpStateEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-NdisFilterClassEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-NdisServiceBindingEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-MsiRegistryEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-InfFileEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-ScheduledTaskEvidence)) { $evidence.Add($item) }
    foreach ($item in @(Get-AppxPackageEvidence)) { $evidence.Add($item) }

    return $evidence.ToArray()
}

<#
.SYNOPSIS
Exports specified registry keys to .reg files in a provider-safe manner.
.DESCRIPTION
For each registry path provided, performs an export using `reg.exe` to ensure provider safety. Exports are saved to the specified destination directory with timestamped filenames. If `-DryRun` is specified, simulates the export process and returns the intended file paths without performing any exports.
.EXAMPLE
Export-RegistryKeys -RegistryPaths @('HKLM\SYSTEM\CurrentControlSet\Services\MyService', 'HKLM\SYSTEM\CurrentControlSet\Services\AnotherService') -DestinationPath 'C:\RegistryExports'
.EXAMPLE
Export-RegistryKeys -RegistryPaths @('HKLM\SYSTEM\CurrentControlSet\Services\MyService') -DestinationPath 'C:\RegistryExports' -DryRun
.OUTPUTS
System.String[]
.NOTES
This function relies on `reg.exe` for exporting registry keys, which ensures that the export process is provider-safe. The exported .reg files can be used for backup, analysis, or transfer to another system.
#>
function Get-ProtectionInventory {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param()

    $evidence = @(Get-ProtectionEvidence)
    $signatures = Get-VendorSignature
    $serviceMap = Get-ServiceRegistryMap
    $adapterCorrelation = @(Get-AdapterRegistryCorrelation)
    $inventory = New-Object System.Collections.Generic.List[object]

    foreach ($vendor in $signatures.Keys) {
        $signature = $signatures[$vendor]
        $matched = New-Object System.Collections.Generic.List[object]

        foreach ($item in $evidence) {
            if (Test-VendorPatternMatch -Vendor $vendor -Signature $signature -Evidence $item) {
                $matched.Add($item)
            }
        }

        if ($matched.Count -eq 0) {
            continue
        }

        $services = New-Object System.Collections.Generic.HashSet[string]
        $drivers = New-Object System.Collections.Generic.HashSet[string]
        $adapters = New-Object System.Collections.Generic.HashSet[string]
        $adapterGuids = New-Object System.Collections.Generic.HashSet[string]
        $registryKeys = New-Object System.Collections.Generic.HashSet[string]
        $evidenceStrings = New-Object System.Collections.Generic.HashSet[string]
        $categories = New-Object System.Collections.Generic.HashSet[string]

        Add-HashSetValue -Set $categories -Values $signature.Categories
        Add-HashSetValue -Set $registryKeys -Values $signature.RegistryRoots

        foreach ($item in $matched) {
            if ($item.Source -in @('Service', 'ServiceRegistry', 'NDIS')) {
                if ($item.Name) {
                    [void]$services.Add($item.Name)
                    [void]$registryKeys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$($item.Name)")
                }
                if ($item.PSObject.Properties.Name -contains 'RegistryPath' -and $item.RegistryPath) {
                    [void]$registryKeys.Add($item.RegistryPath)
                }
            }

            if ($item.Source -eq 'Driver') {
                if ($item.Name) {
                    [void]$drivers.Add($item.Name)
                    [void]$registryKeys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$($item.Name)")
                }
            }

            if ($item.Source -in @('NetAdapter', 'PnpDevice')) {
                if ($item.DisplayName) { [void]$adapters.Add($item.DisplayName) }
                if ($item.InterfaceDescription) { [void]$adapters.Add($item.InterfaceDescription) }
                if ($item.PSObject.Properties.Name -contains 'InterfaceGuid' -and $item.InterfaceGuid) {
                    [void]$adapterGuids.Add($item.InterfaceGuid)
                }
            }

            if ($item.PSObject.Properties.Name -contains 'InstallPath') {
                Add-HashSetValue -Set $registryKeys -Values (Get-VendorRootsFromInstallPath -InstallPath $item.InstallPath)
            }

            $label = @(
                $item.Source,
                $item.Name,
                $item.DisplayName,
                $item.Path,
                $item.InterfaceDescription,
                $item.CompanyName,
                $item.InferredVendor
            ) | Where-Object { $_ } | Select-Object -First 5

            if ($label.Count -gt 0) {
                [void]$evidenceStrings.Add(($label -join ' | '))
            }
        }

        foreach ($svc in @($services)) {
            $key = $svc.ToLowerInvariant()
            if ($serviceMap.ContainsKey($key)) {
                $svcInfo = $serviceMap[$key]

                foreach ($candidate in @(
                        $svcInfo.RegistryPath,
                        $svcInfo.EnumPath,
                        $svcInfo.LinkagePath,
                        $svcInfo.ParamsPath,
                        $svcInfo.InstancesPath
                    )) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }

                $imgMeta = Get-FileMetadatum -Path $svcInfo.ImagePath
                if ($imgMeta -and $imgMeta.Path) {
                    [void]$evidenceStrings.Add("ServiceBinary: $($imgMeta.Path)")
                }
            }
        }

        foreach ($drv in @($drivers)) {
            $key = $drv.ToLowerInvariant()
            if ($serviceMap.ContainsKey($key)) {
                $drvInfo = $serviceMap[$key]
                foreach ($candidate in @(
                        $drvInfo.RegistryPath,
                        $drvInfo.EnumPath,
                        $drvInfo.LinkagePath,
                        $drvInfo.ParamsPath,
                        $drvInfo.InstancesPath
                    )) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }
            }
        }

        foreach ($corr in $adapterCorrelation) {
            $adapterText = @(
                $corr.ComponentId,
                $corr.DriverDesc,
                $corr.ProviderName
            ) -join ' '

            $adapterText = $adapterText.ToLowerInvariant()
            $matchedByAdapter = $false

            foreach ($pattern in $signature.Patterns) {
                if ($adapterText -like "*$pattern*") {
                    $matchedByAdapter = $true
                    break
                }
            }

            if ($matchedByAdapter) {
                if ($corr.InterfaceGuid) { [void]$adapterGuids.Add($corr.InterfaceGuid) }

                foreach ($candidate in @($corr.ClassPath, $corr.NetworkPath, $corr.ConnectionPath, $corr.TcpipPath)) {
                    if (-not [string]::IsNullOrWhiteSpace($candidate)) {
                        [void]$registryKeys.Add($candidate)
                    }
                }

                if ($corr.DriverDesc) { [void]$adapters.Add($corr.DriverDesc) }
                if ($corr.ProviderName) { [void]$evidenceStrings.Add("AdapterProvider: $($corr.ProviderName)") }
            }
        }

        foreach ($svc in @($services)) {
            $svcl = $svc.ToLowerInvariant()
            switch -Wildcard ($svcl) {
                'vm*' { [void]$categories.Add('VirtualAdapter'); [void]$categories.Add('Hypervisor') }
                '*vbox*' { [void]$categories.Add('VirtualAdapter'); [void]$categories.Add('Hypervisor') }
                '*falcon*' { [void]$categories.Add('EDR'); [void]$categories.Add('XDR') }
                '*sentinel*' { [void]$categories.Add('EDR'); [void]$categories.Add('XDR') }
                '*defend*' { [void]$categories.Add('AV') }
                '*fire*' { [void]$categories.Add('Firewall') }
                '*vpn*' { [void]$categories.Add('VPN') }
            }
        }

        foreach ($adapter in @($adapters)) {
            $al = $adapter.ToLowerInvariant()
            switch -Wildcard ($al) {
                '*vmware*' { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*virtualbox*' { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*vbox*' { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*hyper-v*' { [void]$categories.Add('Hypervisor'); [void]$categories.Add('VirtualAdapter') }
                '*vethernet*' { [void]$categories.Add('VirtualAdapter') }
                '*vpn*' { [void]$categories.Add('VPN') }
            }
        }

        $sourceWeights = @{
            'SecurityCenter2' = 12
            'Service'         = 8
            'Driver'          = 10
            'ServiceRegistry' = 8
            'NetAdapter'      = 6
            'PnpDevice'       = 6
            'WFP'             = 10
            'NDIS'            = 9
            'MSI'             = 5
            'INF'             = 5
            'ScheduledTask'   = 4
            'AppX'            = 3
            'Uninstall'       = 4
        }

        $score = 10

        foreach ($m in $matched) {
            if ($sourceWeights.ContainsKey($m.Source)) {
                $score += $sourceWeights[$m.Source]
            }
            else {
                $score += 2
            }
        }

        $score += (@($services).Count * 4)
        $score += (@($drivers).Count * 5)
        $score += (@($adapters).Count * 2)
        $score += (@($adapterGuids).Count * 2)

        if ($matched | Where-Object { $_.Source -eq 'WFP' }) {
            $score += 8
            [void]$categories.Add('NetworkFilter')
        }

        if ($matched | Where-Object { $_.Source -eq 'NDIS' }) {
            $score += 8
            [void]$categories.Add('NetworkFilter')
        }

        $confidence = [Math]::Min(100, $score)

        $inventory.Add([pscustomobject]@{
                Vendor                  = $vendor
                Categories              = @($categories | Sort-Object -Unique)
                Confidence              = $confidence
                Services                = @($services | Sort-Object -Unique)
                Drivers                 = @($drivers | Sort-Object -Unique)
                Adapters                = @($adapters | Sort-Object -Unique)
                ProtectedInterfaceGuids = @($adapterGuids | Sort-Object -Unique)
                RegistryKeys            = @($registryKeys | Where-Object { $_ } | Sort-Object -Unique)
                Evidence                = @($evidenceStrings | Sort-Object -Unique)
                RawEvidenceCount        = $matched.Count
            })
    }

    return $inventory.ToArray() | Sort-Object Vendor
}

<#
.SYNOPSIS
Retrieves metadata for a specified file.
.DESCRIPTION
Gets detailed information about a file, including its version and company details.
.OUTPUTS
A PSCustomObject containing the file's metadata.
#>
<# Duplicate helper removed; canonical function is Get-FileMetadata. #>

<#
.SYNOPSIS
Builds an inventory of protection software from collected evidence.
.DESCRIPTION
Collects vendor signatures and evidence sources to produce a prioritized inventory of detected protection products and related registry keys.
.OUTPUTS
A collection of PSCustomObject inventory entries.
#>
function Get-ProtectionRegistryMap {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $result = New-Object System.Collections.Generic.List[object]

    foreach ($item in $Inventory) {
        $keys = New-Object System.Collections.Generic.HashSet[string]
        Add-HashSetValue -Set $keys -Values $item.RegistryKeys

        foreach ($svc in @($item.Services)) {
            [void]$keys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$svc")
            foreach ($suffix in @('Parameters', 'Linkage', 'Enum', 'Instances')) {
                $candidate = "HKLM\SYSTEM\CurrentControlSet\Services\$svc\$suffix"
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        foreach ($drv in @($item.Drivers)) {
            [void]$keys.Add("HKLM\SYSTEM\CurrentControlSet\Services\$drv")
            foreach ($suffix in @('Parameters', 'Linkage', 'Enum', 'Instances')) {
                $candidate = "HKLM\SYSTEM\CurrentControlSet\Services\$drv\$suffix"
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        foreach ($guid in @($item.ProtectedInterfaceGuids)) {
            if ([string]::IsNullOrWhiteSpace($guid)) { continue }
            $g = $guid.Trim('{}').ToLowerInvariant()

            foreach ($candidate in @(
                    "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{$g}",
                    "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$g}",
                    "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}\{$g}\Connection"
                )) {
                if (Test-RegistryPathExist -RegistryPath $candidate) {
                    [void]$keys.Add($candidate)
                }
            }
        }

        $result.Add([pscustomobject]@{
                Vendor                  = $item.Vendor
                Categories              = $item.Categories
                Confidence              = $item.Confidence
                Services                = $item.Services
                Drivers                 = $item.Drivers
                Adapters                = $item.Adapters
                ProtectedInterfaceGuids = $item.ProtectedInterfaceGuids
                RegistryKeys            = @($keys | Sort-Object -Unique)
                Evidence                = $item.Evidence
            })
    }

    return $result.ToArray() | Sort-Object Vendor
}

<#
.SYNOPSIS
Returns the set of protected interface GUIDs from inventory.
.DESCRIPTION
Creates a unique set of interface GUIDs marked as protected in an inventory.
.OUTPUTS
A list of GUID strings.
#>
function Get-ProtectedInterfaceGuidSet {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $set = New-Object System.Collections.Generic.HashSet[string]

    foreach ($item in $Inventory) {
        foreach ($guid in @($item.ProtectedInterfaceGuids)) {
            if ([string]::IsNullOrWhiteSpace($guid)) { continue }
            [void]$set.Add($guid.Trim('{}').ToLowerInvariant())
        }
    }

    return @($set) | Sort-Object
}

<#
.SYNOPSIS
Enumerates candidate registry artifacts relevant to network history.
.DESCRIPTION
Finds registry locations and interface-specific entries that may contain network history or metadata; marks whether each is protected by inventory.
.OUTPUTS
A collection of artifact candidate PSCustomObjects.
#>
function Get-NetworkPrivacyArtifactCandidate {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    $protectedGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $Inventory)
    $protectedGuidSet = New-Object System.Collections.Generic.HashSet[string]
    Add-HashSetValue -Set $protectedGuidSet -Values $protectedGuids

    $candidates = New-Object System.Collections.Generic.List[object]

    foreach ($path in @(
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed',
            'HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged'
        )) {
        if (Test-RegistryPathExist -RegistryPath $path) {
            $candidates.Add([pscustomobject]@{
                    ArtifactType  = 'NetworkList'
                    RegistryPath  = $path
                    InterfaceGuid = $null
                    IsProtected   = $false
                    Reason        = 'Network profile/signature history'
                })
        }
    }

    $tcpipRoot = 'HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces'
    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $tcpipRoot)) {
        $raw = $child.Trim('{}')
        $guid = $raw.ToLowerInvariant()

        $isGuid = $false
        try {
            [void][guid]$guid
            $isGuid = $true
        }
        catch {
            $isGuid = $false
        }

        if (-not $isGuid) { continue }

        $path = "$tcpipRoot\{$guid}"
        $isProtected = $protectedGuidSet.Contains($guid)

        $candidates.Add([pscustomobject]@{
                ArtifactType  = 'TcpipInterface'
                RegistryPath  = $path
                InterfaceGuid = $guid
                IsProtected   = $isProtected
                Reason        = if ($isProtected) { 'Protected by inventory correlation' } else { 'Non-protected interface-specific network state' }
            })
    }

    $networkRoot = 'HKLM\SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}'
    foreach ($child in @(Get-RegistryChildKeyNamesSafe -RegistryPath $networkRoot)) {
        $raw = $child.Trim('{}')
        $guid = $raw.ToLowerInvariant()

        $isGuid = $false
        try {
            [void][guid]$guid
            $isGuid = $true
        }
        catch {
            $isGuid = $false
        }

        if (-not $isGuid) { continue }

        foreach ($path in @(
                "$networkRoot\{$guid}",
                "$networkRoot\{$guid}\Connection"
            )) {
            if (Test-RegistryPathExist -RegistryPath $path) {
                $isProtected = $protectedGuidSet.Contains($guid)
                $candidates.Add([pscustomobject]@{
                        ArtifactType  = 'NetworkControl'
                        RegistryPath  = $path
                        InterfaceGuid = $guid
                        IsProtected   = $isProtected
                        Reason        = if ($isProtected) { 'Protected by inventory correlation' } else { 'Non-protected network connection metadata' }
                    })
            }
        }
    }

    return $candidates.ToArray()
}

<#
.SYNOPSIS
Filters artifact candidates to those safe to sanitize.
.DESCRIPTION
Returns artifacts from `Get-NetworkPrivacyArtifactCandidate` that are not marked protected by inventory.
.OUTPUTS
A collection of sanitizable artifact PSCustomObjects.
#>
function Get-SanitizableNetworkArtifact {
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter()]
        [AllowNull()]
        [object[]]$Inventory
    )

    if ($null -eq $Inventory -or @($Inventory).Count -eq 0) {
        $Inventory = @(Get-ProtectionInventory)
    }

    return @(Get-NetworkPrivacyArtifactCandidate -Inventory $Inventory | Where-Object { -not $_.IsProtected })
}

<#
.SYNOPSIS
Run phase 1 detection to build context for subsequent phases.
.DESCRIPTION
Runs detection routines to assemble Inventory, ProtectionRegistryMap, candidate and sanitizable artifacts and returns a context object used by later phases.
.OUTPUTS
A PSCustomObject containing detection context and summary.
#>
function Invoke-NetCleanPhase1Detect {
    [CmdletBinding()]
    [OutputType([System.Object])]
    param()

    $canLog = $null -ne (Get-Command Write-NetCleanLog -ErrorAction SilentlyContinue)
    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message 'Phase 1 detection started.'
    }

    $inventory = @(Get-ProtectionInventory)
    $protectionMap = @(Get-ProtectionRegistryMap -Inventory $inventory)
    $protectedGuids = @(Get-ProtectedInterfaceGuidSet -Inventory $inventory)
    $candidateArtifacts = @(Get-NetworkPrivacyArtifactCandidate -Inventory $inventory)
    $sanitizableArtifacts = @(Get-SanitizableNetworkArtifact -Inventory $inventory)

    $protectedRegistryPaths = @(
        $protectionMap |
        ForEach-Object { $_.RegistryKeys } |
        Where-Object { $_ } |
        Sort-Object -Unique
    )

    $result = [pscustomobject]@{
        ModuleVersion           = $script:NetCleanModuleVersion
        Phase                   = 'Detect'
        DetectedAt              = Get-Date
        Inventory               = $inventory
        ProtectionRegistryMap   = $protectionMap
        ProtectedInterfaceGuids = $protectedGuids
        CandidateArtifacts      = $candidateArtifacts
        SanitizableArtifacts    = $sanitizableArtifacts
        ProtectedRegistryPaths  = $protectedRegistryPaths
        Summary                 = [pscustomobject]@{
            ProtectedVendorsCount       = @($inventory).Count
            ProtectedInterfaceGuidCount = @($protectedGuids).Count
            CandidateArtifactCount      = @($candidateArtifacts).Count
            SanitizableArtifactCount    = @($sanitizableArtifacts).Count
        }
    }

    if ($canLog) {
        Write-NetCleanLog -Level INFO -Message ("Protected vendors detected: {0}" -f $result.Summary.ProtectedVendorsCount)
        Write-NetCleanLog -Level INFO -Message ("Protected interface GUIDs detected: {0}" -f $result.Summary.ProtectedInterfaceGuidCount)
        Write-NetCleanLog -Level INFO -Message ("Candidate artifacts detected: {0}" -f $result.Summary.CandidateArtifactCount)
        Write-NetCleanLog -Level INFO -Message ("Sanitizable artifacts identified: {0}" -f $result.Summary.SanitizableArtifactCount)

        foreach ($artifact in @($sanitizableArtifacts)) {
            $parts = New-Object System.Collections.Generic.List[string]

            if ($artifact.PSObject.Properties.Name -contains 'ArtifactType' -and $artifact.ArtifactType) {
                [void]$parts.Add("Type=$($artifact.ArtifactType)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact of type: {0}" -f $artifact.ArtifactType)
            }
            if ($artifact.PSObject.Properties.Name -contains 'Name' -and $artifact.Name) {
                [void]$parts.Add("Name=$($artifact.Name)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact named: {0}" -f $artifact.Name)
            }
            if ($artifact.PSObject.Properties.Name -contains 'RegistryPath' -and $artifact.RegistryPath) {
                [void]$parts.Add("RegistryPath=$($artifact.RegistryPath)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact with registry path: {0}" -f $artifact.RegistryPath)
            }
            if ($artifact.PSObject.Properties.Name -contains 'Path' -and $artifact.Path) {
                [void]$parts.Add("Path=$($artifact.Path)")
                Write-NetCleanLog -Level DEBUG -Message ("Evaluating artifact with path: {0}" -f $artifact.Path)
            }

            if ($parts.Count -gt 0) {
                Write-NetCleanLog -Level INFO -Message ("Preview candidate: {0}" -f ($parts.ToArray() -join ' '))
            }
        }

        # Additional detection summary for auditing
        Write-NetCleanLog -Level INFO -Message ("Detected inventory entries: {0}" -f @($inventory).Count)

        $vendors = @($inventory | ForEach-Object { $_.Vendor } | Where-Object { $_ } | Sort-Object -Unique)
        if ($vendors.Count -gt 0) {
            Write-NetCleanLog -Level INFO -Message ("Detected vendors: {0}" -f ($vendors -join ', '))
        }

        if ($protectedRegistryPaths -and $protectedRegistryPaths.Count -gt 0) {
            Write-NetCleanLog -Level INFO -Message ("Protected registry paths count: {0}" -f $protectedRegistryPaths.Count)
            foreach ($p in $protectedRegistryPaths) {
                Write-NetCleanLog -Level INFO -Message ("Protected registry path: {0}" -f $p)
            }
        }

        Write-NetCleanLog -Level INFO -Message ("Candidate artifacts: {0}, Sanitizable artifacts: {1}" -f $candidateArtifacts.Count, $sanitizableArtifacts.Count)

        # Brief console summary
        Write-Information ("Phase 1 detection: Vendors={0} ProtectedPaths={1} SanitizableCandidates={2}" -f (@($vendors).Count), @($protectedRegistryPaths).Count, @($sanitizableArtifacts).Count) -InformationAction Continue

        Write-NetCleanLog -Level INFO -Message 'Phase 1 detection complete.'
    }

    return $result
}

