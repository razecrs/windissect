param(
    [Parameter(Mandatory = $true)][string]$SemanticJson,
    [Parameter(Mandatory = $true)][string]$TagsJson
)

$semantic = Get-Content -LiteralPath $SemanticJson -Raw | ConvertFrom-Json
$windissect = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
$reference = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)

foreach ($type in $semantic.classes) {
    if ($type.status -eq 'verified' -and
        $type.qualified_name -and
        $type.qualified_name -ne '<unnamed-tag>') {
        [void]$windissect.Add([string]$type.qualified_name)
    }
}

foreach ($enum in $semantic.enums) {
    if ($enum.status -eq 'verified' -and $enum.qualified_name) {
        [void]$windissect.Add([string]$enum.qualified_name)
    }
}

$typeKinds = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@('class', 'enum', 'struct', 'typedef', 'union'),
    [System.StringComparer]::OrdinalIgnoreCase
)

foreach ($line in Get-Content -LiteralPath $TagsJson) {
    if (-not $line.StartsWith('{')) { continue }
    $tag = $line | ConvertFrom-Json
    if ($tag._type -eq 'tag' -and $tag.name -and $typeKinds.Contains([string]$tag.kind)) {
        [void]$reference.Add([string]$tag.name)
    }
}

$common = 0
foreach ($name in $reference) {
    if ($windissect.Contains($name)) { $common++ }
}

[pscustomobject]@{
    windissect_verified_named_types = $windissect.Count
    reference_declared_type_names = $reference.Count
    exact_common_type_names = $common
    reference_only_type_names = $reference.Count - $common
    windissect_only_type_names = $windissect.Count - $common
} | ConvertTo-Json
