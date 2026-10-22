$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
# The caller transmits JSON on stdin. Never print exceptions or native process output.

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

function Get-Digest([byte[]]$Bytes) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
}

function Test-Bytes([byte[]]$A, [byte[]]$B) {
    return [Convert]::ToBase64String($A) -ceq [Convert]::ToBase64String($B)
}

function Get-PrivateSecurity([bool]$Directory) {
    if ($Directory) { $security = New-Object Security.AccessControl.DirectorySecurity }
    else { $security = New-Object Security.AccessControl.FileSecurity }
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($script:currentSid)
    if ($Directory) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($script:currentSid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    } else { $rule = New-Object Security.AccessControl.FileSystemAccessRule($script:currentSid, 'FullControl', 'Allow') }
    $security.AddAccessRule($rule)
    return $security
}

function Ensure-Directory([string]$Path, [bool]$Private = $false) {
    Assert-SafePath $Path
    if ([IO.File]::Exists($Path)) { throw 'File blocks a directory.' }
    if (-not [IO.Directory]::Exists($Path)) {
        if ($Private) { (New-Object IO.DirectoryInfo($Path)).Create((Get-PrivateSecurity $true)) }
        else { [void][IO.Directory]::CreateDirectory($Path) }
    }
    Assert-SafePath $Path
    if ($Private) { [IO.Directory]::SetAccessControl($Path, (Get-PrivateSecurity $true)) }
}

function Write-PrivateNew([string]$Path, [byte[]]$Bytes) {
    Assert-SafePath $Path
    if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) { throw 'Private file already exists.' }
    # The ACL-aware CreateNew constructor protects the file before any bytes exist.
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [Security.AccessControl.FileSystemRights]::Write, [IO.FileShare]::None, 4096, [IO.FileOptions]::None, (Get-PrivateSecurity $false))
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush() } finally { $stream.Dispose() }
}

function Quote-Native([string]$Value) {
    return '"' + [regex]::Replace(([regex]::Replace($Value, '(\\*)"', '$1$1\"')), '(\\+)$', '$1$1') + '"'
}

function Invoke-Bounded([string]$Exe, [string[]]$Arguments, [int]$Milliseconds) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $Exe
    $info.Arguments = (($Arguments | ForEach-Object { Quote-Native $_ }) -join ' ')
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.RedirectStandardInput = $true
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $info
    try {
        if (-not $process.Start()) { throw 'Native process failed.' }
        $process.StandardInput.Close()
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($Milliseconds)) {
            try { $process.Kill() } catch {}
            $process.WaitForExit()
            return @{ code = -1; timedOut = $true; output = ''; error = '' }
        }
        return @{ code = $process.ExitCode; timedOut = $false; output = $stdout.Result; error = $stderr.Result }
    } finally { $process.Dispose() }
}

$aliasName = ''
$keyPath = ''
$stored = $false
$reused = $false
$lockOwned = $false
$createdKey = $false
$createdPublic = $false
$createdPin = $false
$createdMeta = $false
$detail = 'Invalid transfer payload.'
try {
    $raw = [Console]::In.ReadToEnd()
    if ($raw.Length -gt 131072 -or $raw.Length -lt 2) { throw 'Invalid payload size.' }
    $payload = $raw | ConvertFrom-Json
    if ($payload -isnot [Management.Automation.PSCustomObject] -or ($payload.version -isnot [int] -and $payload.version -isnot [long]) -or $payload.version -ne 1) { throw 'Invalid version.' }
    foreach ($field in @('alias','host','user','keyId','fingerprint','privateKey','publicKey','knownHosts','receiverSid','receiverMachine')) {
        if ($payload.$field -isnot [string] -or [string]::IsNullOrWhiteSpace($payload.$field)) { throw 'Missing payload field.' }
    }
    if ($payload.alias -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' -or $payload.host -cnotmatch '^[A-Za-z0-9:][A-Za-z0-9._:-]{0,252}$' -or $payload.user -cnotmatch '^[A-Za-z0-9_][A-Za-z0-9_.@-]{0,63}$') { throw 'Invalid profile fields.' }
    if (($payload.port -isnot [int] -and $payload.port -isnot [long]) -or $payload.port -lt 1 -or $payload.port -gt 65535) { throw 'Invalid port.' }
    if ($payload.keyId -cnotmatch '^[0-9a-f]{64}$' -or $payload.fingerprint -cnotmatch '^SHA256:[A-Za-z0-9+/]{43}$') { throw 'Invalid key identity.' }
    $aliasName = $payload.alias
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $script:currentSid = $identity.User
    $detail = 'Receiver identity changed; prepare the transfer again.'
    if ($payload.receiverSid -cne $script:currentSid.Value -or $payload.receiverMachine -cne [Environment]::MachineName) { throw 'Receiver mismatch.' }
    $detail = 'Invalid key material or host-key pin.'
    $privateBytes = [Convert]::FromBase64String($payload.privateKey)
    $publicBytes = [Convert]::FromBase64String($payload.publicKey)
    $pinBytes = [Convert]::FromBase64String($payload.knownHosts)
    if ($privateBytes.Length -lt 128 -or $privateBytes.Length -gt 16384 -or $publicBytes.Length -gt 4096 -or $pinBytes.Length -gt 16384) { throw 'Invalid key material size.' }
    $utf8 = New-Object Text.UTF8Encoding($false, $true)
    $privateText = $utf8.GetString($privateBytes)
    $publicText = $utf8.GetString($publicBytes)
    $pinText = $utf8.GetString($pinBytes)
    if ($privateText -cnotmatch '\A-----BEGIN OPENSSH PRIVATE KEY-----\r?\n[A-Za-z0-9+/=\r\n]+-----END OPENSSH PRIVATE KEY-----\r?\n?\z') { throw 'Invalid private key encoding.' }
    if ($publicText -cnotmatch '\Assh-ed25519 ([A-Za-z0-9+/]+={0,2})(?: [^\x00-\x1f\x7f]*)?\r?\n?\z') { throw 'Invalid public key encoding.' }
    $publicWire = [Convert]::FromBase64String($Matches[1])
    # RFC4253 ssh-ed25519 wire format: string algorithm, string 32-byte public key.
    if ($publicWire.Length -ne 51 -or [BitConverter]::ToString($publicWire[0..18]) -cne '00-00-00-0B-73-73-68-2D-65-64-32-35-35-31-39-00-00-00-20') { throw 'Invalid Ed25519 public key.' }
    $publicIdentity = Get-Digest $publicWire
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $fingerprint = 'SHA256:' + [Convert]::ToBase64String($sha.ComputeHash($publicWire)).TrimEnd('=') } finally { $sha.Dispose() }
    if ($publicIdentity -cne $payload.keyId -or $fingerprint -cne $payload.fingerprint) { throw 'Public key identity mismatch.' }
    $pinLines = @($pinText.TrimEnd("`r", "`n") -split '\r?\n')
    if ($pinLines.Count -ne 1 -or $pinLines[0] -cnotmatch '^([^\s]+) (ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) ([A-Za-z0-9+/]+={0,2})$') { throw 'Invalid host-key pin.' }
    $pinHost = $Matches[1]
    $expectedPin = if ($payload.port -eq 22) { $payload.host } else { '[' + $payload.host + ']:' + $payload.port }
    if ($pinHost -cne $expectedPin -and -not ($payload.port -eq 22 -and $pinHost -ceq ('[' + $payload.host + ']'))) { throw 'Host-key pin targets another server.' }
    $detail = 'Receiver requires Windows system OpenSSH and ssh-keygen.'
    $sshExe = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh.exe'
    $keygenExe = Join-Path $env:SystemRoot 'System32\OpenSSH\ssh-keygen.exe'
    if (-not [IO.File]::Exists($sshExe) -or -not [IO.File]::Exists($keygenExe)) { throw 'System OpenSSH unavailable.' }
    # Unknown options are rejected even in inactive Host blocks. Probe locally
    # without connecting, so older clients keep every original alias usable.
    $knownHostsProbe = Invoke-Bounded $sshExe @('-G','-F','NUL','-o','KnownHostsCommand=none','keydesk-option-check.invalid') 3000
    $knownHostsCommandSupported = $knownHostsProbe.code -eq 0
    $detail = 'Unsafe receiver path or SSH configuration.'
    if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or -not [IO.Path]::IsPathRooted($env:USERPROFILE)) { throw 'Missing receiver home.' }
    $homePath = [IO.Path]::GetFullPath($env:USERPROFILE)
    Assert-SafePath $homePath
    if (-not [IO.Directory]::Exists($homePath)) { throw 'Receiver home does not exist.' }
    $sshPath = Join-Path $homePath '.ssh'
    Ensure-Directory $sshPath
    $configPath = Join-Path $sshPath 'config'
    $lockPath = Join-Path $sshPath '.keydesk-config.lock'
    Assert-SafePath $lockPath
    $detail = 'SSH configuration is locked by another transfer; try again.'
    [void](New-Item -Path $lockPath -ItemType Directory -ErrorAction Stop)
    $lockOwned = $true
    $detail = 'Unsafe receiver path or SSH configuration.'
    Assert-SafePath $configPath
    $script:configSeen = @{}
    $script:configAliases = New-Object 'System.Collections.Generic.List[string]'
    $script:configCount = 0
    Read-ConfigAliases $configPath $sshPath
    if ($env:ProgramData) { Read-ConfigAliases (Join-Path $env:ProgramData 'ssh\ssh_config') (Join-Path $env:ProgramData 'ssh') }
    $keydeskPath = Join-Path $sshPath 'keydesk'
    $importsPath = Join-Path $keydeskPath 'imported'
    $keyDir = Join-Path $importsPath $payload.keyId
    $keyPath = Join-Path $keyDir 'id_ed25519'
    $publicPath = $keyPath + '.pub'
    $pinPath = Join-Path $sshPath ('known_hosts_' + $aliasName)
    $metaDir = Join-Path $keydeskPath 'aliases'
    $metaPath = Join-Path $metaDir ($aliasName + '.json')
    foreach ($path in @($keydeskPath,$importsPath,$keyDir,$keyPath,$publicPath,$pinPath,$metaDir,$metaPath)) { Assert-SafePath $path }
    $detail = 'Original SSH config uses an unsupported encoding or cannot be read.'
    [byte[]]$configBytes = @()
    if ([IO.File]::Exists($configPath)) { $configBytes = [IO.File]::ReadAllBytes($configPath) }
    $configText = $utf8.GetString($configBytes)
    if ($configText.Contains([string][char]0) -or $configText.StartsWith([string][char]0xfeff, [StringComparison]::Ordinal)) { throw 'Cannot safely prepend a BOM or UTF16 SSH config.' }
    $keyOption = $keyPath.Replace('\','/')
    $pinOption = $pinPath.Replace('\','/')
    # An explicit Host * resets the appended original file's pre-Host defaults.
    $blockLines = @(
        ('# BEGIN KEYDESK IMPORT ' + $aliasName + ' ' + $payload.keyId),
        ('Host ' + $aliasName),
        ('    HostName ' + $payload.host),
        ('    Port ' + $payload.port),
        ('    User ' + $payload.user),
        ('    IdentityFile "' + $keyOption + '"'),
        '    IdentitiesOnly yes',
        '    IdentityAgent none',
        ('    UserKnownHostsFile "' + $pinOption + '"'),
        '    GlobalKnownHostsFile NUL')
    if ($knownHostsCommandSupported) { $blockLines += '    KnownHostsCommand none' }
    $blockLines += @(
        '    StrictHostKeyChecking yes',
        '    VerifyHostKeyDNS no',
        '    UpdateHostKeys no',
        '    ProxyCommand none',
        '    ProxyJump none',
        ('# END KEYDESK IMPORT ' + $aliasName),
        'Host *', '')
    $block = $blockLines -join "`r`n"
    $metadata = @{ version = 1; alias = $aliasName; keyId = $payload.keyId; host = $payload.host; port = $payload.port; user = $payload.user; fingerprint = $payload.fingerprint; privateDigest = (Get-Digest $privateBytes); publicDigest = (Get-Digest $publicBytes); pinsDigest = (Get-Digest $pinBytes); configBlock = [Convert]::ToBase64String($utf8.GetBytes($block)) }
    $aliasCount = @($script:configAliases | Where-Object { $_ -ieq $aliasName }).Count
    $detail = 'Destination alias or imported key conflicts with an existing profile.'
    if ([IO.File]::Exists($metaPath)) {
        if ((Get-Item -LiteralPath $metaPath -Force).Length -gt 16384) { throw 'Metadata too large.' }
        $existing = [IO.File]::ReadAllText($metaPath) | ConvertFrom-Json
        foreach ($field in $metadata.Keys) { if ([string]$existing.$field -cne [string]$metadata[$field]) { throw 'Managed profile differs.' } }
        if ($aliasCount -ne 1 -or -not [IO.File]::Exists($keyPath) -or -not [IO.File]::Exists($publicPath) -or -not [IO.File]::Exists($pinPath)) { throw 'Managed profile is incomplete.' }
        if (-not (Test-Bytes ([IO.File]::ReadAllBytes($keyPath)) $privateBytes) -or -not (Test-Bytes ([IO.File]::ReadAllBytes($publicPath)) $publicBytes) -or -not (Test-Bytes ([IO.File]::ReadAllBytes($pinPath)) $pinBytes)) { throw 'Managed material differs.' }
        # Only other generated blocks may precede the selected generated block.
        $remaining = $utf8.GetString($configBytes)
        while (-not $remaining.StartsWith($block, [StringComparison]::Ordinal)) {
            $match = [regex]::Match($remaining, '\A# BEGIN KEYDESK IMPORT ([A-Za-z0-9][A-Za-z0-9._-]{0,63}) [0-9a-f]{64}\r\nHost \1\r\n(?:(?!# END KEYDESK IMPORT)[^\r\n]*\r\n)*# END KEYDESK IMPORT \1\r\nHost \*\r\n')
            if (-not $match.Success) { throw 'Managed config was edited.' }
            $remaining = $remaining.Substring($match.Length)
        }
        $reused = $true
    } else {
        if ($aliasCount -gt 0 -or [IO.File]::Exists($pinPath) -or [IO.Directory]::Exists($pinPath)) { throw 'Alias already exists.' }
        if ([IO.File]::Exists($keyPath) -and -not (Test-Bytes ([IO.File]::ReadAllBytes($keyPath)) $privateBytes)) { throw 'Imported key bytes differ.' }
        if ([IO.File]::Exists($publicPath) -and -not (Test-Bytes ([IO.File]::ReadAllBytes($publicPath)) $publicBytes)) { throw 'Imported public key differs.' }
    }
    $detail = 'Could not create protected imported-key directories.'
    Ensure-Directory $keydeskPath $true
    Ensure-Directory $importsPath $true
    Ensure-Directory $keyDir $true
    Ensure-Directory $metaDir $true
    $detail = 'Could not create the private key with a protected DACL.'
    if (-not [IO.File]::Exists($keyPath)) { Write-PrivateNew $keyPath $privateBytes; $createdKey = $true }
    else { [IO.File]::SetAccessControl($keyPath, (Get-PrivateSecurity $false)) }
    $detail = 'Private key does not match the selected public identity.'
    $derived = Invoke-Bounded $keygenExe @('-y','-P','','-f',$keyPath) 5000
    $derivedParts = @($derived.output.Trim() -split '\s+')
    if ($derived.code -ne 0 -or $derivedParts.Count -lt 2 -or $derivedParts[0] -cne 'ssh-ed25519' -or $derivedParts[1] -cne [Convert]::ToBase64String($publicWire)) { throw 'Private key validation failed.' }
    if (-not [IO.File]::Exists($publicPath)) { Write-PrivateNew $publicPath $publicBytes; $createdPublic = $true }
    if (-not $reused) { Write-PrivateNew $pinPath $pinBytes; $createdPin = $true }
    $detail = 'Invalid selected server host-key pin.'
    $pinCheck = Invoke-Bounded $keygenExe @('-l','-f',$pinPath) 5000
    if ($pinCheck.code -ne 0) { throw 'Host-key parsing failed.' }
    if (-not $reused) {
        $detail = 'Could not safely commit the destination SSH profile.'
        Write-PrivateNew $metaPath ($utf8.GetBytes(($metadata | ConvertTo-Json -Compress))); $createdMeta = $true
        $tempConfig = Join-Path $sshPath ('.keydesk-config-' + [Guid]::NewGuid().ToString('N') + '.tmp')
        Assert-SafePath $tempConfig
        $prefix = $utf8.GetBytes($block)
        $combined = New-Object byte[] ($prefix.Length + $configBytes.Length)
        [Array]::Copy($prefix, 0, $combined, 0, $prefix.Length)
        [Array]::Copy($configBytes, 0, $combined, $prefix.Length, $configBytes.Length)
        Write-PrivateNew $tempConfig $combined
        try {
            Assert-SafePath $configPath
            if ([IO.File]::Exists($configPath)) {
                if (-not (Test-Bytes ([IO.File]::ReadAllBytes($configPath)) $configBytes)) { throw 'Config changed during transfer.' }
                $backup = $configPath + '.keydesk-backup-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + [Guid]::NewGuid().ToString('N')
                [IO.File]::Replace($tempConfig, $configPath, $backup)
            } else { [IO.File]::Move($tempConfig, $configPath) }
        } finally { if ([IO.File]::Exists($tempConfig)) { [IO.File]::Delete($tempConfig) } }
    }
    $stored = $true
    $result = @{ ok = $true; alias = $aliasName; keyPath = $keyPath; state = 'verification_failed'; detail = 'Profile stored; destination verification could not complete.'; reused = $reused }
    # Verify the saved alias, including the receiver's normal config behavior.
    # A temporary USERPROFILE is used only by isolated tests; OpenSSH otherwise uses
    # the real Windows profile, so explicitly select the saved test config there.
    $verifyArgs = @()
    $normalHome = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
    if (-not [string]::Equals($homePath.TrimEnd('\'), $normalHome.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase)) { $verifyArgs += @('-F', $configPath) }
    if ($knownHostsCommandSupported) { $verifyArgs += @('-o','KnownHostsCommand=none') }
    $verifyArgs += @('-n','-T','-i',$keyPath,
        '-o',('UserKnownHostsFile="' + $pinOption + '"'),'-o','GlobalKnownHostsFile=NUL',
        '-o','StrictHostKeyChecking=yes','-o','VerifyHostKeyDNS=no','-o','UpdateHostKeys=no','-o','BatchMode=yes','-o','PreferredAuthentications=publickey',
        '-o','PasswordAuthentication=no','-o','KbdInteractiveAuthentication=no','-o','PubkeyAuthentication=yes',
        '-o','IdentitiesOnly=yes','-o','IdentityAgent=none','-o','ConnectionAttempts=1','-o','ConnectTimeout=7',
        '-o','ControlMaster=no','-o','ControlPath=none','-o','ClearAllForwardings=yes','-o','ForwardAgent=no',
        '-o','ForwardX11=no','-o','Tunnel=no','-o','PermitLocalCommand=no','-o','RemoteCommand=none','-o','ProxyCommand=none','-o','ProxyJump=none',
        '-o','LogLevel=ERROR',$aliasName,"printf 'KEYDESK_C_READY\n'")
    $verification = Invoke-Bounded $sshExe $verifyArgs 10000
    if ($verification.code -eq 0 -and $verification.output.Trim() -ceq 'KEYDESK_C_READY') { $result.state = 'key_ready'; $result.detail = 'Profile stored and destination public-key connection verified.' }
    elseif ($verification.timedOut -or $verification.error -match '(?i)timed out') { $result.state = 'timeout'; $result.detail = 'Profile stored; connection from this Windows receiver to the server timed out.' }
    elseif ($verification.error -match '(?i)Permission denied|authentication failed') { $result.state = 'auth_failed'; $result.detail = 'Profile stored; the server rejected the transferred public identity.' }
    elseif ($verification.error -match '(?i)Host key verification failed|REMOTE HOST IDENTIFICATION HAS CHANGED') { $result.state = 'host_key_failed'; $result.detail = 'Profile stored; the server did not match the pinned host key.' }
    elseif ($verification.error -match '(?i)Connection refused|No route to host|Network is unreachable|Could not resolve hostname|connect to host') { $result.state = 'unreachable'; $result.detail = 'Profile stored; this Windows receiver could not reach the selected server.' }
} catch {
    if (-not $stored) {
        foreach ($entry in @(@($createdMeta,$metaPath),@($createdPin,$pinPath),@($createdPublic,$publicPath),@($createdKey,$keyPath))) {
            if ($entry[0] -and $entry[1]) { try { Assert-SafePath $entry[1]; [IO.File]::Delete($entry[1]) } catch {} }
        }
        $result = @{ ok = $false; alias = $aliasName; keyPath = ''; state = 'rejected'; detail = $detail; reused = $false }
    }
} finally {
    if ($lockOwned) { try { Assert-SafePath $lockPath; [IO.Directory]::Delete($lockPath) } catch {} }
    $privateBytes = $null; $privateText = $null; $raw = $null; $payload = $null
}
[Console]::Out.WriteLine('KEYDESK_RESULT:' + ($result | ConvertTo-Json -Depth 8 -Compress))
