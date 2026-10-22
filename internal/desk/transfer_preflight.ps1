$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)

function Assert-SafePath([string]$Path) {
    $current = [IO.Path]::GetFullPath($Path)
    while ($current) {
        try { $attrs = [IO.File]::GetAttributes($current) }
        catch [IO.FileNotFoundException] { $attrs = $null }
        catch [IO.DirectoryNotFoundException] { $attrs = $null }
        if ($null -ne $attrs -and ($attrs -band [IO.FileAttributes]::ReparsePoint)) { throw 'Unsafe reparse path.' }
        $parent = [IO.Path]::GetDirectoryName($current)
        if ($parent -eq $current) { break }
        $current = $parent
    }
}

function Get-ConfigTokens([string]$Line) {
    $matches = [regex]::Matches($Line, '(?:"([^"]*)"|''([^'']*)''|([^\s#]+)|#.*)')
    foreach ($match in $matches) {
        if ($match.Value.StartsWith('#')) { break }
        if ($match.Groups[1].Success) { $match.Groups[1].Value }
        elseif ($match.Groups[2].Success) { $match.Groups[2].Value }
        else { $match.Groups[3].Value }
    }
}

function Read-ConfigAliases([string]$Path, [string]$Base, [int]$Depth = 0) {
    if ($Depth -gt 16 -or $script:configCount -gt 128) { throw 'SSH Include limit exceeded.' }
    Assert-SafePath $Path
    if (-not [IO.File]::Exists($Path)) { return }
    $full = [IO.Path]::GetFullPath($Path)
    if ($script:configSeen.ContainsKey($full.ToLowerInvariant())) { return }
    $script:configSeen[$full.ToLowerInvariant()] = $true
    $script:configCount++
    if ((Get-Item -LiteralPath $full -Force).Length -gt 1048576) { throw 'SSH config is too large.' }
    foreach ($line in [IO.File]::ReadAllLines($full)) {
        $tokens = @(Get-ConfigTokens ($line -replace '(?i)^\s*(Host|Include)\s*=\s*', '$1 '))
        if ($tokens.Count -lt 2) { continue }
        if ($tokens[0] -ieq 'Host') {
            foreach ($alias in $tokens[1..($tokens.Count-1)]) {
                if ($alias -notmatch '[*?!]' -and $alias -match '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$') { $script:configAliases.Add($alias) }
            }
        } elseif ($tokens[0] -ieq 'Include') {
            foreach ($include in $tokens[1..($tokens.Count-1)]) {
                if ($include -match '^~[/\\]') { $include = Join-Path $env:USERPROFILE $include.Substring(2) }
                if ($include -match '[%$]') { throw 'Unsupported dynamic SSH Include path.' }
                if (-not [IO.Path]::IsPathRooted($include)) { $include = Join-Path $Base $include }
                $safePrefix = $include
                while ($safePrefix -match '[*?\[]') { $safePrefix = [IO.Path]::GetDirectoryName($safePrefix) }
                Assert-SafePath $safePrefix
                try { $items = @(Get-ChildItem -Path $include -Force -ErrorAction Stop) }
                catch { if ($_.CategoryInfo.Category -eq 'ObjectNotFound') { $items = @() } else { throw } }
                foreach ($item in $items) {
                    if ($item.PSIsContainer) { throw 'SSH Include must name files.' }
                    Read-ConfigAliases $item.FullName $Base ($Depth+1)
                }
            }
        }
    }
}

try {
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or -not [IO.Path]::IsPathRooted($env:USERPROFILE)) { throw 'Missing receiver home.' }
    $homePath = [IO.Path]::GetFullPath($env:USERPROFILE)
    Assert-SafePath $homePath
    if (-not [IO.Directory]::Exists($homePath)) { throw 'Receiver home does not exist.' }
    $sshPath = Join-Path $homePath '.ssh'
    Assert-SafePath $sshPath
    $script:configSeen = @{}
    $script:configAliases = New-Object 'System.Collections.Generic.List[string]'
    $script:configCount = 0
    Read-ConfigAliases (Join-Path $sshPath 'config') $sshPath
    if ($env:ProgramData) { Read-ConfigAliases (Join-Path $env:ProgramData 'ssh\ssh_config') (Join-Path $env:ProgramData 'ssh') }
    $managed = @{}
    $metaDir = Join-Path $sshPath 'keydesk\aliases'
    Assert-SafePath $metaDir
    if ([IO.Directory]::Exists($metaDir)) {
        foreach ($file in @(Get-ChildItem -LiteralPath $metaDir -Filter '*.json' -File -Force)) {
            Assert-SafePath $file.FullName
            if ($file.Length -gt 16384) { throw 'Managed alias metadata is too large.' }
            $meta = [IO.File]::ReadAllText($file.FullName) | ConvertFrom-Json
            if ($meta.version -ne 1 -or $meta.alias -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $meta.keyId -cnotmatch '^[0-9a-f]{64}$' -or $file.BaseName -cne $meta.alias) { throw 'Invalid managed alias metadata.' }
            if (@($script:configAliases | Where-Object { $_ -ieq $meta.alias }).Count -eq 1) { $managed[$meta.alias] = $meta.keyId }
        }
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $result = @{ ok = $true; home = $homePath; user = $identity.Name; sid = $identity.User.Value; machine = [Environment]::MachineName; aliases = @($script:configAliases | Sort-Object -Unique); managedAliases = $managed }
} catch {
    $result = @{ ok = $false; detail = 'Receiver preflight rejected an unsafe or unreadable SSH configuration.'; home = ''; user = ''; sid = ''; machine = ''; aliases = @(); managedAliases = @{} }
}
[Console]::Out.WriteLine('KEYDESK_RESULT:' + ($result | ConvertTo-Json -Depth 8 -Compress))
