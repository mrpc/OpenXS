/*
 * SEO cloaking/doorway script: serves different content to search-engine
 * crawlers (detected via HTTP_REFERER) than to real visitors, fetching the
 * cloaked content from an attacker-controlled URL built directly from
 * user-supplied $_GET input (a de facto SSRF primitive). Plain, readable
 * PHP - not obfuscated at all, which is why it evades php-malware-finder's
 * obfuscation-focused rules entirely. Found in OpenXS's missed-exploit
 * corpus analysis, 2026-10-22 (see OpenXS-ops/TIMELINE.md).
 */
rule SeoCloakingDoorway
{
    meta:
        description = "SEO cloaking/doorway script gated on search-engine referer, fetching GET-controlled remote content"
        reference = "OpenXS missed-exploit analysis 2026-10-22"
    strings:
        $referer_se = /HTTP_REFERER.{0,80}(google\.|yahoo\.|bing\.)/
        $ssrf_get = /CURLOPT_URL\s*,\s*["'][^"']*["']\s*\.\s*\$_GET\[/
    condition:
        $referer_se and $ssrf_get
}
