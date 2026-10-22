/*
 * Detects PHP that builds a function/string name one character at a time by
 * indexing into an alphabet string via a foreach over an array of integers,
 * then calls the resulting name as a function and invokes it. Evades plain
 * literal/regex matches for "create_function"/"eval"/"base64_decode" etc.,
 * since those names never appear as a contiguous substring anywhere in the
 * file - found in OpenXS's missed-exploit corpus analysis, 2026-10-22
 * (see OpenXS-ops/TIMELINE.md).
 */
rule CharArrayObfuscatedCall
{
    meta:
        description = "PHP building a callable name via per-character array indexing, then invoking it dynamically"
        reference = "OpenXS missed-exploit analysis 2026-10-22"
    strings:
        $charbuild = /foreach\s*\(\s*\[[0-9,\s]+\]\s*as\s*\$[A-Za-z_]\w*\s*\)\s*\{\s*\$[A-Za-z_]\w*\s*\.=\s*\$[A-Za-z_]\w*\[\$[A-Za-z_]\w*\]/
        $dyncall = /\$[A-Za-z_]\w*\s*=\s*\$[A-Za-z_]\w*\(.{0,200}\)\s*;\s*\$[A-Za-z_]\w*\(\)\s*;/s
    condition:
        $charbuild and $dyncall
}
