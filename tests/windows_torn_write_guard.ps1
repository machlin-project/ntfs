param([string]$Collector, [string]$CollectorHash)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ((Get-FileHash -LiteralPath $Collector -Algorithm SHA256).Hash.ToLowerInvariant() -cne $CollectorHash) {
    throw 'Torn-write guard collector differs.'
}
$tokens = $null
$errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Collector,[ref]$tokens,[ref]$errors)
if (@($errors).Count -ne 0) { throw 'Collector parser errors.' }
foreach ($name in @('Test-NativeTornMetadataProfile','Test-NativeTornWriteEvent')) {
    $functions = @($ast.FindAll({param($node)
        $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name
    },$false))
    if ($functions.Count -ne 1) { throw 'Unexpected pure torn-write function count.' }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$root = 'R:\MachlinWriteCases-native-write-alias-20261006'
$fields = @('FileName','FileReference','BufferOffset','TornStructureOffset',
            'BlockIndex','ExpectedSequenceNumber','ActualSequenceNumber')
$metadata = @(
    [pscustomobject]@{FileName='\$Mft';FileReference='0';BufferOffset='0';TornStructureOffset='0';BlockIndex='1';ExpectedSequenceNumber='5';ActualSequenceNumber='3'},
    [pscustomobject]@{FileName='\$MftMirr';FileReference='1';BufferOffset='0';TornStructureOffset='0';BlockIndex='1';ExpectedSequenceNumber='9';ActualSequenceNumber='8'},
    [pscustomobject]@{FileName='\MachlinWriteCases-native-write-alias-20261006\native-growth';FileReference='63';BufferOffset='4096';TornStructureOffset='0';BlockIndex='7';ExpectedSequenceNumber='9';ActualSequenceNumber='8'}
)
$profile = [pscustomobject]@{root=$root;expectedTornMetadataPages=$metadata;
    sequenceObjects=@([pscustomobject]@{relativePath='native-growth';directory=$true;present=$true;reference='844424930132031'});
    expectedTornLogPages=@([pscustomobject]@{bufferOffset='4096';blockIndex='1';expectedSequenceNumber='9';actualSequenceNumber='8'})}
$valid = @(Test-NativeTornMetadataProfile $profile $root)
if ($valid.Count -ne 3) { throw 'Valid metadata tears refused.' }
$events = @([pscustomobject]@{FileName='\$LogFile';FileReference='2';BufferOffset='4096';TornStructureOffset='0';BlockIndex='1';ExpectedSequenceNumber='9';ActualSequenceNumber='8'}) + $metadata
$positive = @()
$eventRefusals = @()
foreach ($event in $events) {
    $data = @{}
    foreach ($field in $fields) { $data[$field] = $event.$field }
    $kind = Test-NativeTornWriteEvent $data $profile
    if ($kind -cne $(if ($event.FileName -ceq '\$LogFile') {'journal'} else {'metadata'})) {
        throw 'Unexpected torn-write classification.'
    }
    $positive += [ordered]@{file=$event.FileName;kind=$kind;passed=$true}
    foreach ($field in $fields) {
        foreach ($missing in @($false,$true)) {
            $changed = $data.Clone()
            if ($missing) { $changed.Remove($field) }
            else { $changed[$field] = 'unbound' }
            $refused = $false
            try { [void](Test-NativeTornWriteEvent $changed $profile) }
            catch { $refused = $true }
            if (-not $refused) { throw 'Unbound torn-write event accepted.' }
            $eventRefusals += [ordered]@{file=$event.FileName;field=$field;missing=$missing;refused=$true}
        }
    }
}
$profileRefusals = @()
for ($index = 0; $index -lt 18; $index++) {
    $changed = ($profile | ConvertTo-Json -Depth 8 | ConvertFrom-Json)
    $page = $changed.expectedTornMetadataPages[0]
    $changedRoot = $root
    switch ($index) {
        0 {$page.FileName='\$Bad'}
        1 {$page.FileReference='1'}
        2 {$page.BufferOffset='1'}
        3 {$page.BufferOffset='1048576'}
        4 {$page.TornStructureOffset='1'}
        5 {$page.BlockIndex='2'}
        6 {$page.ExpectedSequenceNumber='0'}
        7 {$page.ExpectedSequenceNumber='65536'}
        8 {$page.ActualSequenceNumber=$page.ExpectedSequenceNumber}
        9 {$page.ActualSequenceNumber='65536'}
        10 {$page.BufferOffset='00'}
        11 {$page.BufferOffset=0}
        12 {$page.PSObject.Properties.Remove('BlockIndex')}
        13 {$page | Add-Member -NotePropertyName 'Unbound' -NotePropertyValue '0'}
        14 {$changed.expectedTornMetadataPages=@($page,$page)}
        15 {$changed.expectedTornMetadataPages=@((0..16 | ForEach-Object {$page}))}
        16 {$changedRoot='T:\MachlinWriteCases-native-write-alias-20261006'}
        17 {$changed.PSObject.Properties.Remove('sequenceObjects')}
    }
    $refused = $false
    try { [void](Test-NativeTornMetadataProfile $changed $changedRoot) }
    catch { $refused = $true }
    if (-not $refused) { throw 'Malformed torn metadata profile accepted.' }
    $profileRefusals += [ordered]@{profile=$index;refused=$true}
}
return [ordered]@{success=$true;parserErrors=0;positiveEvents=$positive;
    malformedEvents=$eventRefusals;malformedProfiles=$profileRefusals;candidateMounts=0;filesystemMutations=0}
