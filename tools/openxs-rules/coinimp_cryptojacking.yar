/*
 * CoinIMP browser cryptojacking proxy/injector - serves a hidden WASM/JS
 * miner to site visitors via a PHP proxy to coinimp's own CDN. Not
 * obfuscated at all (plain, readable PHP), which is exactly why
 * php-malware-finder's obfuscation-focused rules miss it entirely -
 * found in OpenXS's missed-exploit corpus analysis, 2026-10-22 (see
 * OpenXS-ops/TIMELINE.md). Specific enough (coinimp + wasm.stream) that
 * false positives should be essentially impossible in legitimate code.
 */
rule CoinimpCryptojackingProxy
{
    meta:
        description = "CoinIMP browser-mining proxy/injector script"
        reference = "OpenXS missed-exploit analysis 2026-10-22"
    strings:
        $coinimp = "coinimp" nocase
        $wasmstream = "wasm.stream" nocase
        $filename_match = "filename_match"
    condition:
        $coinimp and ($wasmstream or $filename_match)
}
