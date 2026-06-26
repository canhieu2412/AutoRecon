#!/bin/bash
# ============================================================================
# AUTO RECON - Phase 6: Report Generation
# ============================================================================

generate_html_report() {
    local markdown_report="$1"
    local html_report="$2"
    local report_title="$3"

    if command -v perl &>/dev/null; then
        perl - "$markdown_report" "$html_report" "$report_title" <<'PERL'
use strict;
use warnings;
use open ':std', ':encoding(UTF-8)';

my ($md_path, $html_path, $title) = @ARGV;

open my $in,  '<', $md_path   or die "Unable to open markdown report: $!";
open my $out, '>', $html_path or die "Unable to write html report: $!";

sub esc {
    my ($text) = @_;
    $text //= '';
    $text =~ s/&/&amp;/g;
    $text =~ s/</&lt;/g;
    $text =~ s/>/&gt;/g;
    $text =~ s/"/&quot;/g;
    return $text;
}

sub apply_finding_markup {
    my ($text) = @_;
    $text =~ s/\[(CRITICAL|HIGH|MEDIUM|LOW|INFO)\]/'<span class="sev sev-' . lc($1) . '">[' . $1 . ']<\/span>'/ge;
    $text =~ s/\b(CVE-\d{4}-\d{4,7})\b/<span class="cve">$1<\/span>/g;
    return $text;
}

sub render_inline {
    my ($text) = @_;
    $text = esc($text);
    $text =~ s/\*\*([^*]+)\*\*/<strong>$1<\/strong>/g;
    $text =~ s/`([^`]+)`/<code>$1<\/code>/g;
    # Images (must run before the link rule): ![alt](src)
    $text =~ s/!\[([^\]]*)\]\(([^)]+)\)/'<img src="' . $2 . '" alt="' . $1 . '" loading="lazy" style="max-width:100%;border:1px solid var(--border);border-radius:6px;margin:6px 0;">'/ge;
    $text =~ s/\[([^\]]+)\]\(([^)]+)\)/'<a href="' . $2 . '">' . $1 . '<\/a>'/ge;
    $text =~ s{(https?://[A-Za-z0-9\-\._~:/\?#\[\]@!\$&'\(\)\*\+,;=%]+)}{<a href="$1">$1</a>}g;
    return apply_finding_markup($text);
}

sub render_code_line {
    my ($text) = @_;
    $text = esc($text);
    return apply_finding_markup($text);
}

sub close_lists {
    my ($out, $state) = @_;
    if ($state->{ul_open}) {
        print {$out} "</ul>\n";
        $state->{ul_open} = 0;
        $state->{ul_class} = '';
    }
    if ($state->{ol_open}) {
        print {$out} "</ol>\n";
        $state->{ol_open} = 0;
    }
}

my %state = (
    code_open     => 0,
    ul_open       => 0,
    ol_open       => 0,
    ul_class      => '',
    next_ul_class => '',
);

print {$out} <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>@{[esc($title)]}</title>
  <style>
    :root {
      --bg: #0b1220;
      --panel: #111a2b;
      --panel-alt: #0f1726;
      --text: #e5edf7;
      --muted: #9fb0c8;
      --accent: #58c4dc;
      --accent-2: #7ee081;
      --border: #24324a;
      --code: #0a1020;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
      background:
        radial-gradient(circle at top right, rgba(88,196,220,0.18), transparent 28%),
        radial-gradient(circle at top left, rgba(126,224,129,0.12), transparent 24%),
        var(--bg);
      color: var(--text);
      line-height: 1.6;
    }
    main {
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 20px 64px;
    }
    h1, h2, h3, h4 {
      line-height: 1.25;
      margin: 1.4em 0 0.5em;
    }
    h1 {
      margin-top: 0;
      font-size: 2rem;
      letter-spacing: 0.01em;
    }
    h2 {
      font-size: 1.4rem;
      padding-bottom: 0.35rem;
      border-bottom: 1px solid var(--border);
    }
    h3 { font-size: 1.1rem; }
    h4 { font-size: 1rem; color: var(--accent); }
    p, li, blockquote, summary {
      color: var(--text);
      font-size: 0.98rem;
    }
    p { margin: 0.55rem 0; }
    .meta-line {
      margin: 0.2rem 0;
      color: var(--muted);
    }
    .meta-line strong {
      color: var(--text);
    }
    ul, ol {
      margin: 0.5rem 0 0.9rem 1.4rem;
      padding: 0;
    }
    li { margin: 0.28rem 0; }
    .summary-grid {
      list-style: none;
      margin: 1rem 0 1.4rem;
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }
    .summary-card {
      margin: 0;
      padding: 0.95rem 1rem;
      border: 1px solid var(--border);
      border-radius: 14px;
      background: linear-gradient(180deg, rgba(17,26,43,0.98), rgba(15,23,38,0.94));
      box-shadow: 0 10px 30px rgba(0, 0, 0, 0.18);
    }
    .summary-card strong {
      display: block;
      margin-bottom: 0.2rem;
      color: var(--accent);
      font-size: 0.84rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    a {
      color: var(--accent);
      text-decoration: none;
    }
    a:hover { text-decoration: underline; }
    code {
      font-family: "JetBrains Mono", "Fira Code", Consolas, monospace;
      background: rgba(126, 224, 129, 0.08);
      border: 1px solid rgba(126, 224, 129, 0.18);
      border-radius: 6px;
      padding: 0.08rem 0.38rem;
      color: #c8f5cf;
    }
    pre {
      background: var(--code);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 14px 16px;
      overflow-x: auto;
      margin: 0.8rem 0 1.2rem;
    }
    pre code {
      background: transparent;
      border: 0;
      border-radius: 0;
      padding: 0;
      color: var(--text);
      display: block;
      white-space: pre;
    }
    .sev {
      display: inline-block;
      padding: 0.05rem 0.42rem;
      border-radius: 999px;
      border: 1px solid transparent;
      font-size: 0.78rem;
      font-weight: 700;
      letter-spacing: 0.02em;
      margin-right: 0.25rem;
    }
    .sev-critical {
      background: rgba(255, 91, 91, 0.16);
      border-color: rgba(255, 91, 91, 0.32);
      color: #ff9e9e;
    }
    .sev-high {
      background: rgba(255, 163, 72, 0.16);
      border-color: rgba(255, 163, 72, 0.32);
      color: #ffc078;
    }
    .sev-medium {
      background: rgba(255, 214, 102, 0.16);
      border-color: rgba(255, 214, 102, 0.32);
      color: #ffe08a;
    }
    .sev-low {
      background: rgba(88, 196, 220, 0.16);
      border-color: rgba(88, 196, 220, 0.32);
      color: #8de7f6;
    }
    .sev-info {
      background: rgba(126, 224, 129, 0.16);
      border-color: rgba(126, 224, 129, 0.32);
      color: #b8f2b9;
    }
    .cve {
      color: #ffcc7a;
      font-weight: 700;
    }
    hr {
      border: 0;
      border-top: 1px solid var(--border);
      margin: 1.2rem 0;
    }
    blockquote {
      margin: 0.8rem 0;
      padding: 0.7rem 0.9rem;
      border-left: 4px solid var(--accent);
      background: rgba(88, 196, 220, 0.08);
      color: var(--muted);
    }
    details {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 0.4rem 0.8rem;
      margin: 0.8rem 0 1rem;
    }
    summary {
      cursor: pointer;
      font-weight: 600;
      color: var(--accent);
      padding: 0.25rem 0;
    }
  </style>
</head>
<body>
<main>
HTML

while (my $line = <$in>) {
    chomp $line;

    if ($line =~ /^```/) {
        close_lists($out, \%state);
        if (!$state{code_open}) {
            print {$out} "<pre><code>";
            $state{code_open} = 1;
        } else {
            print {$out} "</code></pre>\n";
            $state{code_open} = 0;
        }
        next;
    }

    if ($state{code_open}) {
        print {$out} render_code_line($line), "\n";
        next;
    }

    if ($line =~ /^\s*$/) {
        close_lists($out, \%state);
        next;
    }

    if ($line =~ m{^</?(details|summary)>|^<summary>.*</summary>$}) {
        close_lists($out, \%state);
        print {$out} "$line\n";
        next;
    }

    if ($line =~ /^---\s*$/) {
        close_lists($out, \%state);
        print {$out} "<hr />\n";
        next;
    }

    if ($line =~ /^(#{1,4})\s+(.*)$/) {
        close_lists($out, \%state);
        my $level = length($1);
        my $heading = $2;
        $state{next_ul_class} = ($level == 2 && $heading =~ /Executive (Summary|Dashboard)/) ? 'summary-grid' : '';
        print {$out} "<h$level>", render_inline($heading), "</h$level>\n";
        next;
    }

    if ($line =~ /^>\s?(.*)$/) {
        close_lists($out, \%state);
        print {$out} "<blockquote>", render_inline($1), "</blockquote>\n";
        next;
    }

    if ($line =~ /^- (.*)$/) {
        if ($state{ol_open}) {
            print {$out} "</ol>\n";
            $state{ol_open} = 0;
        }
        if (!$state{ul_open}) {
            my $ul_class = $state{next_ul_class} || '';
            my $ul_attr = $ul_class ? qq{ class="$ul_class"} : '';
            print {$out} "<ul$ul_attr>\n";
            $state{ul_open} = 1;
            $state{ul_class} = $ul_class;
            $state{next_ul_class} = '';
        }
        my $li_attr = ($state{ul_class} && $state{ul_class} eq 'summary-grid') ? ' class="summary-card"' : '';
        print {$out} "<li$li_attr>", render_inline($1), "</li>\n";
        next;
    }

    if ($line =~ /^\d+\.\s+(.*)$/) {
        if ($state{ul_open}) {
            print {$out} "</ul>\n";
            $state{ul_open} = 0;
        }
        if (!$state{ol_open}) {
            print {$out} "<ol>\n";
            $state{ol_open} = 1;
        }
        print {$out} "<li>", render_inline($1), "</li>\n";
        next;
    }

    close_lists($out, \%state);
    my $p_class = ($line =~ /^\*\*(Generated|Author|Scan Method|Tool|Profile|OffSec Safe Mode|Input Target|Resolved Target|Target Type|Result Path)\*\*:/) ? ' class="meta-line"' : '';
    print {$out} "<p$p_class>", render_inline($line), "</p>\n";
}

close_lists($out, \%state);
print {$out} "</code></pre>\n" if $state{code_open};
print {$out} "</main>\n</body>\n</html>\n";
PERL
        return $?
    fi

    {
        echo '<!DOCTYPE html>'
        echo '<html lang="en"><head><meta charset="utf-8"><title>Recon Report</title></head><body><pre>'
        sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' "$markdown_report"
        echo '</pre></body></html>'
    } > "$html_report"
}

report_numeric_limit() {
    local value="$1"
    local fallback="$2"
    if [[ "$value" =~ ^[0-9]+$ ]] && (( value > 0 )); then
        echo "$value"
    else
        echo "$fallback"
    fi
}

report_context_file() {
    local result_dir="$1"
    echo "${result_dir}/state/target_context.env"
}

report_context_value() {
    local result_dir="$1"
    local key="$2"
    local fallback="${3:-N/A}"
    local value=""

    value=$(read_metadata_value "$(report_context_file "$result_dir")" "$key" 2>/dev/null || true)
    [[ -n "$value" ]] && printf '%s\n' "$value" || printf '%s\n' "$fallback"
}

report_phase_state_file() {
    local result_dir="$1"
    local phase="$2"
    echo "${result_dir}/state/${phase}.env"
}

report_line_count() {
    local file="$1"
    [[ -f "$file" ]] && wc -l < "$file" 2>/dev/null || echo 0
}

report_preview_file() {
    local file="$1"
    local lines="$2"
    [[ -f "$file" ]] || return 0
    head -n "$lines" "$file"
}

report_web_targets() {
    local result_dir="$1"
    {
        [[ -f "${result_dir}/scans/web_ports.txt" ]] && cat "${result_dir}/scans/web_ports.txt"
        [[ -f "${result_dir}/web/subdomain_web_targets.txt" ]] && awk '{print $NF}' "${result_dir}/web/subdomain_web_targets.txt"
    } 2>/dev/null | awk 'NF && !seen[$0]++'
}

report_web_target_key() {
    local url="$1"
    echo "$url" | sed 's|[:/]|_|g'
}

report_phase_table() {
    local result_dir="$1"
    local phase=""
    local state_file=""
    local status=""
    local started_at=""
    local finished_at=""
    local duration=""
    local detail=""

    echo "| Phase | Status | Started | Duration | Detail |"
    echo "| --- | --- | --- | --- | --- |"

    for phase in host_discovery port_scan service_enum web_recon wordlist_toolkit vuln_scan sqlmap_all_in_one sqlmap_operator brute_force report; do
        state_file=$(report_phase_state_file "$result_dir" "$phase")
        [[ -f "$state_file" ]] || continue
        status=$(read_metadata_value "$state_file" status 2>/dev/null || echo "unknown")
        started_at=$(read_metadata_value "$state_file" started_at 2>/dev/null || echo "-")
        duration=$(read_metadata_value "$state_file" duration_seconds 2>/dev/null || echo "0")
        detail=$(read_metadata_value "$state_file" detail 2>/dev/null || echo "-")
        printf '| %s | %s | %s | %ss | %s |\n' "$phase" "$status" "$started_at" "$duration" "$detail"
    done
}

report_rel_path() {
    local result_dir="$1"
    local file="$2"
    printf '%s\n' "${file#${result_dir}/}"
}

report_trim_field() {
    local value="$1"
    value="${value//$'\t'/ }"
    value="${value//$'\r'/ }"
    value="${value//$'\n'/ }"
    value=$(printf '%s\n' "$value" | sed 's/[[:space:]][[:space:]]*/ /g; s/^ //; s/ $//')
    printf '%s\n' "$value"
}

report_summary_text() {
    report_trim_field "$1" | sed 's/[<>]//g'
}

report_findings_file() {
    local result_dir="$1"
    echo "${result_dir}/state/report_findings.tsv"
}

report_reset_findings() {
    local result_dir="$1"
    ensure_result_layout "$result_dir" || return 1
    : > "$(report_findings_file "$result_dir")"
}

report_add_finding() {
    local result_dir="$1"
    local severity="$2"
    local asset="$3"
    local title="$4"
    local evidence="$5"
    local source="$6"
    local next_action="$7"

    severity=$(report_trim_field "${severity:-INFO}" | tr '[:lower:]' '[:upper:]')
    asset=$(report_trim_field "${asset:-unknown}")
    title=$(report_trim_field "${title:-Untitled finding}")
    evidence=$(report_trim_field "${evidence:-No evidence captured}")
    source=$(report_trim_field "${source:-unknown}")
    next_action=$(report_trim_field "${next_action:-Review manually}")
    evidence=$(printf '%s\n' "$evidence" | report_redact_stream)

    if [[ -s "$(report_findings_file "$result_dir")" ]] && \
       awk -F'\t' -v sev="$severity" -v asset="$asset" -v title="$title" -v source="$source" \
           '$1 == sev && $2 == asset && $3 == title && $5 == source { found = 1 } END { exit found ? 0 : 1 }' \
           "$(report_findings_file "$result_dir")"; then
        return 0
    fi

    printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
        "$severity" "$asset" "$title" "$evidence" "$source" "$next_action" >> "$(report_findings_file "$result_dir")"
}

report_finding_count() {
    local result_dir="$1"
    local severity="${2:-}"
    local findings
    findings=$(report_findings_file "$result_dir")
    [[ -s "$findings" ]] || { echo 0; return 0; }

    if [[ -n "$severity" ]]; then
        awk -F'\t' -v sev="${severity^^}" '$1 == sev { count++ } END { print count + 0 }' "$findings"
    else
        wc -l < "$findings" 2>/dev/null || echo 0
    fi
}

report_redact_stream() {
    sed -E \
        -e 's/([Pp]ass(word)?|[Pp]asswd|[Pp]wd|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey|[Bb]earer)([[:space:]]*[:=][[:space:]]*)[^[:space:];,&]+/\1\3[REDACTED]/g' \
        -e 's/([Pp]ass(word)?|[Pp]asswd|[Pp]wd|[Tt]oken|[Ss]ecret|[Aa]pi[_-]?[Kk]ey)([[:space:]]*=[[:space:]]*")[^"]+"/\1\3[REDACTED]"/g' \
        -e 's#(://[^:/@[:space:]]+:)[^@/[:space:]]+@#\1[REDACTED]@#g' \
        -e 's#([A-Za-z0-9_.-]+:)[^@[:space:]]+@#\1[REDACTED]@#g' \
        -e 's#/home/[^[:space:]"]+/auto_recon/results/[^[:space:]"]+#[RESULT_PATH]#g' \
        -e 's/\b[A-Fa-f0-9]{32,}\b/[REDACTED_HASH]/g'
}

report_preview_file_redacted() {
    local file="$1"
    local lines="$2"
    [[ -f "$file" ]] || return 0
    report_preview_file "$file" "$lines" | report_redact_stream
}

report_code_block_file() {
    local file="$1"
    local lines="$2"
    local lang="${3:-}"
    local redacted="${4:-true}"
    [[ -f "$file" && -s "$file" ]] || return 0

    echo '```'"$lang"
    if [[ "$redacted" == "true" ]]; then
        report_preview_file_redacted "$file" "$lines"
    else
        report_preview_file "$file" "$lines"
    fi
    echo '```'
}

report_details_file() {
    local title="$1"
    local file="$2"
    local lines="$3"
    local lang="${4:-}"
    local redacted="${5:-true}"
    [[ -f "$file" && -s "$file" ]] || return 0

    echo "<details>"
    echo "<summary>$(report_summary_text "$title")</summary>"
    echo ""
    report_code_block_file "$file" "$lines" "$lang" "$redacted"
    echo ""
    echo "</details>"
    echo ""
}

report_collect_cve_findings() {
    local ip="$1"
    local result_dir="$2"
    local cve_file="${result_dir}/vulns/cves_found.txt"
    local cve=""
    [[ -s "$cve_file" ]] || return 0

    while IFS= read -r cve; do
        [[ -z "$cve" ]] && continue
        report_add_finding "$result_dir" "HIGH" "$ip" "Known CVE detected: ${cve}" \
            "${cve}" "vulns/cves_found.txt" "Validate exploitability and prioritize confirmed remote paths."
    done < "$cve_file"
}

report_collect_nuclei_findings() {
    local ip="$1"
    local result_dir="$2"
    local nf=""
    local line=""
    local severity=""
    local asset=""
    local title=""
    local line_without_sev=""

    for nf in "${result_dir}/vulns/nuclei_"*.txt; do
        [[ -s "$nf" ]] || continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            severity=$(grep -oE '\[(critical|high|medium|low|info)\]' <<< "$line" | head -n 1 | tr -d '[]' | tr '[:lower:]' '[:upper:]')
            [[ -n "$severity" ]] || severity="MEDIUM"
            asset=$(grep -oE 'https?://[^ ]+|[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]+)?' <<< "$line" | tail -n 1)
            [[ -n "$asset" ]] || asset="$ip"
            line_without_sev=$(sed -E 's/\[(critical|high|medium|low|info)\][[:space:]]*//Ig' <<< "$line")
            if [[ "$line_without_sev" =~ ^\[([^]]+)\] ]]; then
                title="${BASH_REMATCH[1]}"
            else
                title="${line_without_sev%% *}"
            fi
            [[ -n "$title" && "$title" != "$line" ]] || title="Nuclei finding"
            report_add_finding "$result_dir" "$severity" "$asset" "$title" \
                "$line" "$(report_rel_path "$result_dir" "$nf")" "Open the Nuclei output and manually verify impact."
        done < <(head -n 80 "$nf")
    done
}

report_collect_sqlmap_findings() {
    local ip="$1"
    local result_dir="$2"
    local sql_file=""
    local line=""

    for sql_file in "${result_dir}/vulns/sqlmap_auto.txt" "${result_dir}/vulns/sqlmap_all_in_one.txt" "${result_dir}/vulns/sqlmap_operator/"*.txt; do
        [[ -s "$sql_file" ]] || continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            report_add_finding "$result_dir" "CRITICAL" "$ip" "SQL injection verified" \
                "$line" "$(report_rel_path "$result_dir" "$sql_file")" "Reproduce with saved SQLMap command, identify DBMS, and assess data access."
        done < <(grep -i "is vulnerable" "$sql_file" 2>/dev/null | head -n 20)
    done
}

report_collect_lfi_findings() {
    local ip="$1"
    local result_dir="$2"
    local lfi_file="${result_dir}/vulns/lfi_auto.txt"
    [[ -s "$lfi_file" ]] || return 0

    report_add_finding "$result_dir" "CRITICAL" "$ip" "Local File Inclusion evidence found" \
        "$(head -n 1 "$lfi_file" 2>/dev/null)" "vulns/lfi_auto.txt" "Confirm readable files, try log poisoning only when authorized, and document impact."
}

report_collect_web_findings() {
    local ip="$1"
    local result_dir="$2"
    local file=""
    local line=""

    if [[ -s "${result_dir}/web/default_creds.txt" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local sev="HIGH"
            local asset="$ip"
            grep -qi "WORKS" <<< "$line" && sev="CRITICAL"
            asset=$(grep -oE 'https?://[^ ]+' <<< "$line" | head -n 1)
            [[ -n "$asset" ]] || asset="$ip"
            report_add_finding "$result_dir" "$sev" "$asset" "Default credential candidate" \
                "$line" "web/default_creds.txt" "Manually validate login and document exact access level."
        done < <(grep -i "POSSIBLE LOGIN\|WORKS\|\[200\]\|\[301\]\|\[302\]" "${result_dir}/web/default_creds.txt" 2>/dev/null | head -n 20)
    fi

    for file in "${result_dir}/web/ssl_"*.txt; do
        [[ -s "$file" ]] || continue
        if grep -qi "VULNERABLE\|heartbleed\|poodle" "$file" 2>/dev/null; then
            report_add_finding "$result_dir" "HIGH" "$ip" "SSL/TLS weakness detected" \
                "$(grep -i "VULNERABLE\|heartbleed\|poodle" "$file" | head -n 1)" \
                "$(report_rel_path "$result_dir" "$file")" "Review sslscan output and validate protocol/cipher exposure."
        fi
    done

    for file in "${result_dir}/web/waf_"*.txt; do
        [[ -s "$file" ]] || continue
        if grep -Eqi "is behind|is protected|behind .+waf" "$file" 2>/dev/null && \
           ! grep -Eqi "no waf detected|no .* detected by the generic detection" "$file" 2>/dev/null; then
            report_add_finding "$result_dir" "INFO" "$ip" "WAF or filtering detected" \
                "$(grep -Eii "is behind|is protected|behind .+waf" "$file" | head -n 1)" \
                "$(report_rel_path "$result_dir" "$file")" "Account for WAF behavior during manual testing."
        fi
    done
}

report_collect_service_findings() {
    local ip="$1"
    local result_dir="$2"

    if grep -qi "Anonymous FTP login allowed\|230 Login successful" "${result_dir}/scans/ftp_"*.txt 2>/dev/null; then
        report_add_finding "$result_dir" "MEDIUM" "$ip" "Anonymous FTP access appears enabled" \
            "Anonymous FTP login evidence found" "scans/ftp_*.txt" "Enumerate readable/writable files and look for credentials or backups."
    fi

    if [[ -s "${result_dir}/scans/smb.txt" ]] && grep -qi "READ\|Anonymous\|mapping.*ok" "${result_dir}/scans/smb.txt" 2>/dev/null; then
        report_add_finding "$result_dir" "MEDIUM" "$ip" "SMB share exposure candidate" \
            "$(grep -i "READ\|Anonymous\|mapping.*ok" "${result_dir}/scans/smb.txt" | head -n 1)" \
            "scans/smb.txt" "Browse readable shares and review files for credentials or configuration leaks."
    fi

    if [[ -s "${result_dir}/vulns/nmap_vuln.txt" ]] && grep -Eqi "VULNERABLE|CVE-[0-9]{4}-[0-9]{4,7}" "${result_dir}/vulns/nmap_vuln.txt"; then
        report_add_finding "$result_dir" "HIGH" "$ip" "Nmap vuln script matched a vulnerability" \
            "$(grep -Ei "VULNERABLE|CVE-[0-9]{4}-[0-9]{4,7}" "${result_dir}/vulns/nmap_vuln.txt" | head -n 1)" \
            "vulns/nmap_vuln.txt" "Verify the Nmap script result before exploitation."
    fi
}

report_collect_searchsploit_findings() {
    local ip="$1"
    local result_dir="$2"

    if [[ -s "${result_dir}/vulns/searchsploit_auto.txt" ]] || [[ -s "${result_dir}/vulns/searchsploit_manual.txt" ]]; then
        report_add_finding "$result_dir" "INFO" "$ip" "SearchSploit exploit candidates exist" \
            "SearchSploit returned one or more candidates" "vulns/searchsploit_*.txt" "Triage exploit candidates by exact version and exploit preconditions."
    fi
}

report_collect_findings() {
    local ip="$1"
    local result_dir="$2"

    report_reset_findings "$result_dir" || return 1
    report_collect_sqlmap_findings "$ip" "$result_dir"
    report_collect_lfi_findings "$ip" "$result_dir"
    report_collect_cve_findings "$ip" "$result_dir"
    report_collect_nuclei_findings "$ip" "$result_dir"
    report_collect_web_findings "$ip" "$result_dir"
    report_collect_service_findings "$ip" "$result_dir"
    report_collect_searchsploit_findings "$ip" "$result_dir"
}

report_header_v2() {
    local ip="$1"
    local result_dir="$2"
    local scan_method="$3"
    local input_target="$4"
    local target_type="$5"
    local target_domain="$6"
    local target_display="$7"

    echo "# Recon Report: ${target_display}"
    echo ""
    echo "**Generated**: $(date '+%Y-%m-%d %H:%M:%S %Z')"
    echo "**Author**: Canhieu"
    echo "**Tool**: Auto Recon v${APP_VERSION}"
    echo "**Profile**: $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")"
    echo "**OffSec Safe Mode**: $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "ON" || echo "OFF")"
    echo "**Scan Method**: ${scan_method}"
    echo "**Input Target**: ${input_target}"
    echo "**Resolved Target**: ${ip}"
    echo "**Target Type**: ${target_type}"
    [[ -n "$target_domain" && "$target_domain" != "N/A" ]] && echo "**Primary Hostname**: ${target_domain}"
    echo "**Result Path**: \`$(basename "$result_dir")\`"
    echo ""
    echo "---"
    echo ""
}

report_executive_dashboard() {
    local ip="$1"
    local result_dir="$2"
    local ports="$3"
    local port_count="$4"
    local web_count="$5"
    local web_app_count="$6"
    local subdomain_count="$7"
    local hostname_count="$8"
    local phase_issue_count="$9"
    local api_count=0
    local param_count=0
    local vhost_count=0
    local udp_count=0

    [[ -s "${result_dir}/web/api_inventory.txt" ]] && api_count=$(report_line_count "${result_dir}/web/api_inventory.txt")
    for f in "${result_dir}/web/params_"*.txt; do [[ -s "$f" ]] && param_count=$((param_count + $(report_line_count "$f"))); done
    [[ -s "${result_dir}/web/vhosts.txt" ]] && vhost_count=$(report_line_count "${result_dir}/web/vhosts.txt")
    [[ -s "${result_dir}/scans/udp_open_ports.txt" ]] && udp_count=$(report_line_count "${result_dir}/scans/udp_open_ports.txt")

    echo "## Executive Dashboard"
    echo ""
    echo "- **Open Ports**: ${port_count} (${ports})"
    echo "- **UDP Open Ports**: ${udp_count}"
    echo "- **Web Services**: ${web_count}"
    echo "- **Distinct Web Apps / Targets**: ${web_app_count}"
    echo "- **Subdomains**: ${subdomain_count}"
    echo "- **Discovered Hostnames/VHosts**: ${hostname_count} / ${vhost_count}"
    echo "- **API Endpoints**: ${api_count}"
    echo "- **Discovered Parameters**: ${param_count}"
    echo "- **Findings**: $(report_finding_count "$result_dir") total"
    echo "- **Severity Mix**: Critical $(report_finding_count "$result_dir" CRITICAL), High $(report_finding_count "$result_dir" HIGH), Medium $(report_finding_count "$result_dir" MEDIUM), Low $(report_finding_count "$result_dir" LOW), Info $(report_finding_count "$result_dir" INFO)"
    echo "- **Phase Warnings**: ${phase_issue_count}"
    echo ""
}

report_scope_methodology() {
    local result_dir="$1"
    local scan_method="$2"
    local target_type="$3"

    echo "## Scope & Methodology"
    echo ""
    echo "- **Target Type**: ${target_type}"
    echo "- **Scan Engine**: ${scan_method}"
    echo "- **Scan Mode**: ${SCAN_MODE}"
    echo "- **Web Fuzz Tool**: ${WEB_FUZZ_TOOL}"
    echo "- **Safe Mode**: $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "Enabled" || echo "Disabled")"
    echo "- **Resume Mode**: $([ "${AUTO_RESUME_PIPELINE}" == "true" ] && echo "Enabled" || echo "Disabled")"
    echo ""
    echo "Methodology coverage:"
    echo ""
    echo "- Host discovery for CIDR/file targets when applicable."
    echo "- TCP port discovery with configured engine and targeted Nmap service detection."
    echo "- Service-specific enumeration for exposed protocols."
    echo "- Web fingerprinting, crawling, fuzzing, parameter/API discovery, hostname/vhost expansion."
    echo "- Vulnerability correlation through Nmap vuln scripts, SearchSploit, Nuclei, SQLMap/LFI checks when enabled."
    echo "- Optional brute force, operator toolkit notes, custom wordlist generation, and report indexing."
    echo ""
}

report_pipeline_health_v2() {
    local result_dir="$1"
    local phase=""
    local state_file=""
    local status=""
    local started_at=""
    local duration=""
    local detail=""

    echo "## Pipeline Health"
    echo ""
    for phase in host_discovery port_scan service_enum web_recon wordlist_toolkit vuln_scan sqlmap_all_in_one sqlmap_operator brute_force report; do
        state_file=$(report_phase_state_file "$result_dir" "$phase")
        [[ -f "$state_file" ]] || continue
        status=$(read_metadata_value "$state_file" status 2>/dev/null || echo "unknown")
        started_at=$(read_metadata_value "$state_file" started_at 2>/dev/null || echo "-")
        duration=$(read_metadata_value "$state_file" duration_seconds 2>/dev/null || echo "0")
        detail=$(read_metadata_value "$state_file" detail 2>/dev/null || echo "-")
        [[ "$phase" == "report" && "$status" == "running" ]] && status="generating"
        [[ "$phase" != "report" && "$status" == "running" ]] && status="incomplete"

        echo "- **${phase}**: ${status} (${duration}s) - ${detail}"
        echo "  Started: ${started_at}"
    done
    echo ""
}

report_key_findings() {
    local result_dir="$1"
    local findings
    local severity=""
    local asset=""
    local title=""
    local evidence=""
    local source=""
    local next_action=""
    local idx=1

    findings=$(report_findings_file "$result_dir")
    echo "## Key Findings"
    echo ""

    if [[ ! -s "$findings" ]]; then
        echo "No normalized high-signal findings were extracted from the available artifacts. Review the evidence sections for raw observations and missed context."
        echo ""
        return 0
    fi

    while IFS=$'\t' read -r severity asset title evidence source next_action; do
        echo "<details>"
        echo "<summary>$(report_summary_text "${idx}. [${severity}] ${title} - ${asset}")</summary>"
        echo ""
        echo "- **Severity**: [${severity}]"
        echo "- **Asset**: \`${asset}\`"
        echo "- **Evidence**: ${evidence}"
        echo "- **Source**: \`${source}\`"
        echo "- **Next Action**: ${next_action}"
        echo ""
        echo "</details>"
        echo ""
        idx=$((idx + 1))
    done < "$findings"
}

report_attack_surface_inventory() {
    local result_dir="$1"
    local web_targets=""

    web_targets=$(report_web_targets "$result_dir")

    echo "## Attack Surface Inventory"
    echo ""

    if [[ -s "${result_dir}/scans/alive_hosts.txt" ]]; then
        echo "### Alive Hosts"
        echo ""
        report_code_block_file "${result_dir}/scans/alive_hosts.txt" 80 ""
        echo ""
    fi

    echo "### TCP Services"
    echo ""
    if [[ -s "${result_dir}/scans/nmap_targeted.nmap" ]]; then
        echo '```'
        grep -E '^PORT[[:space:]]+STATE[[:space:]]+SERVICE|^[0-9]+/(tcp|udp)' "${result_dir}/scans/nmap_targeted.nmap"
        echo '```'
    else
        echo "No detailed TCP service scan output is available."
    fi
    echo ""

    if [[ -s "${result_dir}/scans/udp_open_ports.txt" ]] || [[ -s "${result_dir}/scans/udp_scan.nmap" ]]; then
        echo "### UDP Services"
        echo ""
        if [[ -s "${result_dir}/scans/udp_open_ports.txt" ]]; then
            report_code_block_file "${result_dir}/scans/udp_open_ports.txt" 80 ""
        else
            echo '```'
            grep '^[0-9]' "${result_dir}/scans/udp_scan.nmap" | grep 'open' | grep -v 'filtered'
            echo '```'
        fi
        echo ""
    fi

    report_details_file "Authentication Surfaces" "${result_dir}/scans/auth_surfaces.tsv" 80 "tsv"
    report_details_file "Windows Auth Inventory" "${result_dir}/scans/windows_auth_inventory.txt" 100 ""
    report_details_file "Linux Remote Access Inventory" "${result_dir}/scans/linux_remote_access_inventory.txt" 100 ""
    report_details_file "Directory Services Inventory" "${result_dir}/scans/directory_services_inventory.txt" 100 ""

    if [[ -n "$web_targets" ]]; then
        echo "### Web Targets"
        echo ""
        echo '```'
        printf '%s\n' "$web_targets" | head -n 200
        echo '```'
        echo ""
    fi

    report_details_file "Discovered Hostnames" "${result_dir}/web/discovered_hostnames.txt" 120 ""
    report_details_file "Discovered Root Domains" "${result_dir}/web/discovered_root_domains.txt" 120 ""
    report_details_file "VHosts" "${result_dir}/web/vhosts.txt" 120 ""
    report_details_file "Suggested /etc/hosts Entries" "${result_dir}/web/hosts_suggestions.txt" 120 ""
    report_details_file "API Inventory" "${result_dir}/web/api_inventory.txt" 120 ""
    report_details_file "Extra Paths" "${result_dir}/web/extra_paths.txt" 120 ""
}

report_service_evidence() {
    local result_dir="$1"
    local preview_lines="$2"
    local svc_file=""
    local svc_base=""
    local svc_name=""

    echo "## Service Evidence"
    echo ""
    for svc_file in "${result_dir}/scans/"*.txt; do
        [[ -s "$svc_file" ]] || continue
        svc_base=$(basename "$svc_file")
        case "$svc_base" in
            alive_hosts.txt|open_ports.txt|scan_method.txt|udp_open_ports.txt|web_ports.txt|auth_surfaces.tsv|windows_auth_inventory.txt|linux_remote_access_inventory.txt|directory_services_inventory.txt)
                continue
                ;;
        esac
        svc_name=$(basename "$svc_file" .txt | sed 's/_/ /g' | tr '[:lower:]' '[:upper:]')
        report_details_file "${svc_name}" "$svc_file" "$preview_lines" ""
    done
}

report_web_details() {
    local result_dir="$1"
    local preview_lines="$2"
    local finding_limit="$3"
    local url=""
    local base_name=""
    local artifact_names=""
    local artifact_count=0
    local file=""
    local web_targets=""

    web_targets=$(report_web_targets "$result_dir")

    echo "## Web Application Details"
    echo ""

    if [[ -z "$web_targets" ]]; then
        echo "No web targets were discovered or queued for detailed web recon."
        echo ""
    else
        while IFS= read -r url; do
            [[ -z "$url" ]] && continue
            base_name=$(report_web_target_key "$url")
            artifact_count=$(find "${result_dir}/web" -maxdepth 1 -type f \
                \( -name "*${base_name}*.txt" -o -name "*${base_name}*.json" \) 2>/dev/null | wc -l)
            artifact_names=$(find "${result_dir}/web" -maxdepth 1 -type f \
                \( -name "*${base_name}*.txt" -o -name "*${base_name}*.json" \) \
                -printf '%f\n' 2>/dev/null | sort | head -n "$finding_limit")

            echo "### ${url}"
            echo ""
            echo "- **Artifacts**: ${artifact_count}"
            if [[ -n "$artifact_names" ]]; then
                echo ""
                echo '```'
                printf '%s\n' "$artifact_names"
                echo '```'
                echo ""
            fi

            report_details_file "Fingerprint: ${url}" "${result_dir}/web/fingerprint_${base_name}.txt" "$preview_lines" ""
            report_details_file "Quick Hits: ${url}" "${result_dir}/web/quick_hits_${base_name}.txt" 40 ""
            report_details_file "Hinted Paths: ${url}" "${result_dir}/web/hinted_paths_${base_name}.txt" 40 ""
            report_details_file "Parameters: ${url}" "${result_dir}/web/params_${base_name}.txt" 60 ""
            report_details_file "API Fuzz: ${url}" "${result_dir}/web/api_fuzz_${base_name}.txt" 60 ""
            report_details_file "SSL/TLS: ${url}" "${result_dir}/web/ssl_${base_name}.txt" 80 ""
            report_details_file "WAF: ${url}" "${result_dir}/web/waf_${base_name}.txt" 60 ""
            report_details_file "Source Analysis: ${url}" "${result_dir}/web/source_analysis_${base_name}.txt" "$preview_lines" ""
            report_details_file "CTF / Sensitive Endpoints: ${url}" "${result_dir}/web/ctf_endpoints_${base_name}.txt" 60 ""
            report_details_file "Crawled Endpoints: ${url}" "${result_dir}/web/crawl_endpoints_${base_name}.txt" 80 ""
            report_details_file "JS Secrets: ${url}" "${result_dir}/web/js_secrets_${base_name}.txt" 60 ""
            report_details_file "arjun Params: ${url}" "${result_dir}/web/arjun_${base_name}.json" 40 "json"
            echo ""
        done <<< "$web_targets"
    fi

    report_details_file "httpx Probe (all targets)" "${result_dir}/web/httpx.txt" "$preview_lines" ""
    report_details_file "Git Exposure Handoff" "${result_dir}/web/git_exposure.txt" 40 "bash"
    report_details_file "dalfox XSS Findings" "${result_dir}/web/dalfox.txt" "$preview_lines" ""

    for file in "${result_dir}/web/feroxbuster_"*.txt "${result_dir}/web/gobuster_d"*.txt "${result_dir}/web/ffuf_"*.json "${result_dir}/web/vhost_fuzz_"*.json; do
        [[ -s "$file" ]] || continue
        report_details_file "Discovery Artifact: $(basename "$file")" "$file" "$preview_lines" "$([[ "$file" == *.json ]] && echo json || echo)"
    done

    for file in "${result_dir}/web/nikto_"*.txt "${result_dir}/web/wpscan_"*.txt "${result_dir}/web/joomla_"*.txt "${result_dir}/web/joomscan_"*.txt "${result_dir}/web/drupal_"*.txt "${result_dir}/web/cms_fuzz_"*.txt "${result_dir}/web/cms_fuzz_"*.json; do
        [[ -s "$file" ]] || continue
        report_details_file "Web Scanner Artifact: $(basename "$file")" "$file" "$preview_lines" "$([[ "$file" == *.json ]] && echo json || echo)"
    done
}

report_vulnerability_evidence() {
    local result_dir="$1"
    local preview_lines="$2"
    local finding_limit="$3"
    local file=""

    echo "## Vulnerability Evidence"
    echo ""
    report_details_file "Nmap Vuln Scripts" "${result_dir}/vulns/nmap_vuln.txt" "$preview_lines" ""
    report_details_file "CVEs Found" "${result_dir}/vulns/cves_found.txt" "$finding_limit" ""
    report_details_file "SearchSploit Auto Correlation" "${result_dir}/vulns/searchsploit_auto.txt" "$preview_lines" ""
    report_details_file "SearchSploit Manual Queries" "${result_dir}/vulns/searchsploit_manual.txt" "$preview_lines" ""
    report_details_file "SQLMap Auto" "${result_dir}/vulns/sqlmap_auto.txt" "$preview_lines" "bash"
    report_details_file "SQLMap All-in-One Summary" "${result_dir}/vulns/sqlmap_all_in_one_summary.txt" 80 "bash"
    report_details_file "SQLMap All-in-One Log" "${result_dir}/vulns/sqlmap_all_in_one.txt" "$preview_lines" "bash"
    report_details_file "SQLMap Operator Targets" "${result_dir}/vulns/sqlmap_operator_targets.txt" 80 ""
    report_details_file "SQLMap Operator Summary" "${result_dir}/vulns/sqlmap_operator_summary.txt" 80 "bash"
    report_details_file "SQLMap Operator Commands" "${result_dir}/vulns/sqlmap_operator_commands.txt" 60 "bash"
    report_details_file "SQLMap Wizard Config" "${result_dir}/vulns/sqlmap_wizard_config.txt" 80 ""
    report_details_file "LFI Auto Verification" "${result_dir}/vulns/lfi_auto.txt" "$preview_lines" "bash"
    report_details_file "Metasploit Mapping" "${result_dir}/vulns/msf_mapping.txt" "$preview_lines" "bash"
    report_details_file "Vulnerability Summary" "${result_dir}/vulns/summary.txt" 120 ""

    for file in "${result_dir}/vulns/nuclei_"*.txt "${result_dir}/vulns/sqlmap_operator/"*.txt; do
        [[ -s "$file" ]] || continue
        report_details_file "Vulnerability Artifact: $(basename "$file")" "$file" "$preview_lines" "$([[ "$file" == *.json ]] && echo json || echo)"
    done
}

report_privesc_handoff() {
    local result_dir="$1"
    local preview_lines="$2"
    [[ -d "${result_dir}/privesc" ]] || return 0

    echo "## Privilege Escalation Handoff"
    echo ""
    report_details_file "CVE / Exploit Hints (from banners)" "${result_dir}/privesc/cve_hints.txt" "$preview_lines" ""
    report_details_file "Linux Priv-Esc Cheatsheet" "${result_dir}/privesc/linux_privesc.txt" 120 "bash"
    report_details_file "Windows Priv-Esc Cheatsheet" "${result_dir}/privesc/windows_privesc.txt" 120 "bash"
    report_details_file "GTFOBins / LOLBAS Reference" "${result_dir}/privesc/gtfobins_lolbas.txt" 120 ""
    report_details_file "Handoff Summary" "${result_dir}/privesc/summary.txt" 60 ""
}

report_screenshots_gallery() {
    local result_dir="$1"
    local shotdir="${result_dir}/web/screenshots"
    local -a shots=()
    local f
    while IFS= read -r f; do shots+=("$f"); done < <(find "$shotdir" -type f \( -name '*.png' -o -name '*.jpg' -o -name '*.jpeg' \) 2>/dev/null | sort)
    [[ ${#shots[@]} -eq 0 ]] && return 0

    echo "## Web Screenshots"
    echo ""
    echo "_${#shots[@]} screenshot(s) captured. Click to view full size._"
    echo ""
    for f in "${shots[@]}"; do
        local rel
        rel=$(report_rel_path "$result_dir" "$f")
        echo "### $(basename "$f")"
        echo ""
        echo "![$(basename "$f")](${rel})"
        echo ""
        echo "[Open full size](${rel})"
        echo ""
    done
}

report_loot_wordlists_operator() {
    local result_dir="$1"
    local preview_lines="$2"
    local file=""

    echo "## Loot, Wordlists & Operator Notes"
    echo ""

    for file in "${result_dir}/loot/"*.txt; do
        [[ -s "$file" ]] || continue
        report_details_file "Loot: $(basename "$file")" "$file" 60 ""
    done

    report_details_file "Wordlist Summary" "${result_dir}/wordlists/summary.txt" 100 ""
    report_details_file "Wordlist Source Inventory" "${result_dir}/wordlists/source_inventory.txt" 100 ""
    report_details_file "Base Tokens" "${result_dir}/wordlists/base_tokens.txt" 60 ""
    report_details_file "Password Seeds" "${result_dir}/wordlists/password_seeds.txt" 60 ""
    report_details_file "Custom Usernames" "${result_dir}/wordlists/custom_usernames.txt" 60 ""
    report_details_file "Custom Passwords" "${result_dir}/wordlists/custom_passwords.txt" 60 ""
    report_details_file "Custom Content Words" "${result_dir}/wordlists/custom_content.txt" 60 ""
    report_details_file "Custom All Wordlist" "${result_dir}/wordlists/custom_all.txt" 80 ""
    report_details_file "CeWL Emails" "${result_dir}/wordlists/cewl_emails.txt" 60 ""
    report_details_file "RSMangler Passwords" "${result_dir}/wordlists/rsmangler_passwords.txt" 60 ""
    report_details_file "Crunch Custom" "${result_dir}/wordlists/crunch_custom.txt" 60 ""

    report_details_file "Toolkit Summary" "${result_dir}/toolkit/summary.txt" 100 ""
    report_details_file "Credential Cache" "${result_dir}/toolkit/credential_cache.tsv" 60 "tsv"
    report_details_file "Generated Operator Commands" "${result_dir}/toolkit/sessions/generated_commands.txt" 80 "bash"

    for file in "${result_dir}/toolkit/helpers/"*.txt; do
        [[ -s "$file" ]] || continue
        report_details_file "Toolkit Helper: $(basename "$file")" "$file" "$preview_lines" ""
    done
}

report_coverage_gaps() {
    local result_dir="$1"
    local phase=""
    local state_file=""
    local status=""
    local detail=""
    local found=false

    echo "## Coverage Gaps & Limitations"
    echo ""
    for phase in host_discovery port_scan service_enum web_recon wordlist_toolkit vuln_scan sqlmap_all_in_one sqlmap_operator brute_force; do
        state_file=$(report_phase_state_file "$result_dir" "$phase")
        [[ -f "$state_file" ]] || continue
        status=$(read_metadata_value "$state_file" status 2>/dev/null || echo "unknown")
        detail=$(read_metadata_value "$state_file" detail 2>/dev/null || echo "-")
        case "$status" in
            failed|partial|skipped|running)
                echo "- **${phase}**: ${status} - ${detail}"
                found=true
                ;;
        esac
    done

    if [[ "$found" != "true" ]]; then
        echo "No failed, partial, or skipped phases were recorded in the available state files."
    fi
    echo ""
}

report_next_steps_v2() {
    local ip="$1"
    local result_dir="$2"
    local ports="$3"
    local step=1

    echo "## Recommended Next Steps"
    echo ""

    if [[ $(report_finding_count "$result_dir" CRITICAL) -gt 0 ]]; then
        echo "${step}. **Critical findings**: Reproduce verified SQLi/LFI/default-credential evidence first and document impact."
        step=$((step + 1))
    fi
    if [[ $(report_finding_count "$result_dir" HIGH) -gt 0 ]]; then
        echo "${step}. **High findings**: Triage CVE, Nuclei, SSL/TLS, and Nmap vuln evidence against exact service versions."
        step=$((step + 1))
    fi
    if grep -qi "Anonymous FTP login allowed\|230 Login successful" "${result_dir}/scans/ftp_"*.txt 2>/dev/null; then
        echo "${step}. **FTP**: Enumerate anonymous FTP content, recover backups, and test upload paths if permitted."
        step=$((step + 1))
    fi
    if [[ -s "${result_dir}/web/hosts_suggestions.txt" ]]; then
        echo "${step}. **Host mapping**: Import suggested hostnames before browser/proxy testing."
        step=$((step + 1))
    fi
    if [[ -s "${result_dir}/web/api_inventory.txt" ]]; then
        echo "${step}. **API**: Manually review API inventory and test auth, object access, and method handling."
        step=$((step + 1))
    fi
    if [[ -s "${result_dir}/wordlists/custom_passwords.txt" ]]; then
        echo "${step}. **Credential strategy**: Reuse generated target-specific wordlists against exposed auth surfaces."
        step=$((step + 1))
    fi
    if [[ -s "${result_dir}/toolkit/sessions/generated_commands.txt" ]]; then
        echo "${step}. **Operator workflow**: Review generated commands before running them manually."
        step=$((step + 1))
    fi
    if echo "$ports" | grep -q "22"; then
        echo "${step}. **SSH**: Validate discovered usernames and password reuse paths against SSH."
        step=$((step + 1))
    fi

    echo "${step}. **Manual review**: Walk the appendix artifact index and confirm findings before final reporting."
    echo ""
}

report_file_index_v2() {
    local result_dir="$1"
    local file_index_limit="$2"
    local dir=""
    local file=""

    echo "## Appendix: Artifact Index"
    echo ""
    for dir in scans web vulns loot toolkit wordlists state; do
        [[ -d "${result_dir}/${dir}" ]] || continue
        echo "### ${dir}/"
        echo ""
        echo '```'
        find "${result_dir}/${dir}" -type f 2>/dev/null | sort | sed "s|${result_dir}/||" | head -n "$file_index_limit"
        echo '```'
        echo ""
    done

    echo "### report files"
    echo ""
    echo '```'
    for file in "${result_dir}/report.md" "${result_dir}/report.html"; do
        [[ -f "$file" ]] && report_rel_path "$result_dir" "$file"
    done
    echo '```'
}

run_report() {
    local ip="$1"
    local result_dir="$2"

    section_header "PHASE 6: REPORT GENERATION"
    ensure_result_layout "$result_dir" || return 1

    local report="${result_dir}/report.md"
    local html_report="${result_dir}/report.html"
    local preview_lines
    local finding_limit
    local file_index_limit
    local input_target
    local target_type
    local target_domain
    local target_display
    local scan_method
    local ports
    local port_count
    local web_count
    local subdomain_count
    local hostname_count
    local web_app_count
    local phase_issue_count

    preview_lines=$(report_numeric_limit "${REPORT_PREVIEW_LINES:-80}" 80)
    finding_limit=$(report_numeric_limit "${REPORT_FINDING_LIMIT:-100}" 100)
    file_index_limit=$(report_numeric_limit "${REPORT_FILE_INDEX_LIMIT:-400}" 400)

    input_target=$(report_context_value "$result_dir" input_target "$ip")
    target_type=$(report_context_value "$result_dir" target_type "unknown")
    target_domain=$(report_context_value "$result_dir" target_domain "")
    target_display=$(report_context_value "$result_dir" target_display "$ip")
    scan_method=$(cat "${result_dir}/scans/scan_method.txt" 2>/dev/null || echo "N/A")

    ports=$(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)
    if [[ -n "$ports" ]]; then
        port_count=$(echo "$ports" | tr ',' '\n' | awk 'NF' | wc -l)
    else
        ports="none"
        port_count=0
    fi

    web_count=0
    [[ -f "${result_dir}/scans/web_ports.txt" ]] && web_count=$(wc -l < "${result_dir}/scans/web_ports.txt" 2>/dev/null)
    subdomain_count=0
    [[ -f "${result_dir}/web/subdomains.txt" ]] && subdomain_count=$(wc -l < "${result_dir}/web/subdomains.txt" 2>/dev/null)
    hostname_count=0
    [[ -f "${result_dir}/web/discovered_hostnames.txt" ]] && hostname_count=$(wc -l < "${result_dir}/web/discovered_hostnames.txt" 2>/dev/null)
    web_app_count=$(report_web_targets "$result_dir" | wc -l)
    phase_issue_count=$(grep -lE '^status=(failed|partial|skipped|running)$' "${result_dir}/state/"*.env 2>/dev/null | wc -l)

    report_collect_findings "$ip" "$result_dir"

    {
        report_header_v2 "$ip" "$result_dir" "$scan_method" "$input_target" "$target_type" "$target_domain" "$target_display"
        report_executive_dashboard "$ip" "$result_dir" "$ports" "$port_count" "$web_count" "$web_app_count" "$subdomain_count" "$hostname_count" "$phase_issue_count"
        report_scope_methodology "$result_dir" "$scan_method" "$target_type"
        report_pipeline_health_v2 "$result_dir"
        report_key_findings "$result_dir"
        report_attack_surface_inventory "$result_dir"
        report_service_evidence "$result_dir" "$preview_lines"
        report_web_details "$result_dir" "$preview_lines" "$finding_limit"
        report_screenshots_gallery "$result_dir"
        report_vulnerability_evidence "$result_dir" "$preview_lines" "$finding_limit"
        report_privesc_handoff "$result_dir" "$preview_lines"
        report_loot_wordlists_operator "$result_dir" "$preview_lines"
        report_coverage_gaps "$result_dir"
        report_next_steps_v2 "$ip" "$result_dir" "$ports"
        report_file_index_v2 "$result_dir" "$file_index_limit"
    } > "$report"

    if generate_html_report "$report" "$html_report" "Recon Report: ${target_display}"; then
        log_success "Report generated -> ${report}"
        log_success "HTML report generated -> ${html_report}"
    else
        log_warn "Markdown report generated, but HTML export failed"
        log_success "Report generated -> ${report}"
    fi

    echo ""
    echo -e "  ${BOLD}${CYAN}Report Digest${NC}"
    awk '
        /^## Attack Surface Inventory/ { exit }
        /^## Appendix:/ { exit }
        { print }
    ' "$report" | head -n 100

    echo ""
    echo -e "  ${BOLD}${GREEN}View report: cat ${report}${NC}"
    echo -e "  ${BOLD}${GREEN}HTML report: xdg-open ${html_report}${NC}"
}

run_report_legacy() {
    local ip="$1"
    local result_dir="$2"

    section_header "PHASE 6: REPORT GENERATION"
    ensure_result_layout "$result_dir" || return 1

    local report="${result_dir}/report.md"
    local html_report="${result_dir}/report.html"
    local preview_lines
    local finding_limit
    local file_index_limit
    preview_lines=$(report_numeric_limit "${REPORT_PREVIEW_LINES:-80}" 80)
    finding_limit=$(report_numeric_limit "${REPORT_FINDING_LIMIT:-100}" 100)
    file_index_limit=$(report_numeric_limit "${REPORT_FILE_INDEX_LIMIT:-400}" 400)

    local input_target
    local target_type
    local target_domain
    local target_display
    local scan_method
    local ports
    local port_count
    local web_count
    local subdomain_count
    local hostname_count
    local web_app_count
    local cve_count
    local phase_issue_count
    local sqlmap_all_in_one_findings
    local sqlmap_operator_findings

    input_target=$(report_context_value "$result_dir" input_target "$ip")
    target_type=$(report_context_value "$result_dir" target_type "unknown")
    target_domain=$(report_context_value "$result_dir" target_domain "")
    target_display=$(report_context_value "$result_dir" target_display "$ip")
    scan_method=$(cat "${result_dir}/scans/scan_method.txt" 2>/dev/null || echo "N/A")

    ports=$(cat "${result_dir}/scans/open_ports.txt" 2>/dev/null)
    if [[ -n "$ports" ]]; then
        port_count=$(echo "$ports" | tr ',' '\n' | awk 'NF' | wc -l)
    else
        ports="none"
        port_count=0
    fi

    web_count=0
    [[ -f "${result_dir}/scans/web_ports.txt" ]] && web_count=$(wc -l < "${result_dir}/scans/web_ports.txt" 2>/dev/null)
    subdomain_count=0
    [[ -f "${result_dir}/web/subdomains.txt" ]] && subdomain_count=$(wc -l < "${result_dir}/web/subdomains.txt" 2>/dev/null)
    hostname_count=0
    [[ -f "${result_dir}/web/discovered_hostnames.txt" ]] && hostname_count=$(wc -l < "${result_dir}/web/discovered_hostnames.txt" 2>/dev/null)
    web_app_count=$(report_web_targets "$result_dir" | wc -l)
    cve_count=0
    [[ -f "${result_dir}/vulns/cves_found.txt" ]] && cve_count=$(wc -l < "${result_dir}/vulns/cves_found.txt" 2>/dev/null)
    phase_issue_count=$(grep -lE '^status=(failed|partial|skipped)$' "${result_dir}/state/"*.env 2>/dev/null | wc -l)
    sqlmap_all_in_one_findings=0
    [[ -f "${result_dir}/vulns/sqlmap_all_in_one.txt" ]] && sqlmap_all_in_one_findings=$(grep -c "is vulnerable" "${result_dir}/vulns/sqlmap_all_in_one.txt" 2>/dev/null || true)
    [[ -n "$sqlmap_all_in_one_findings" ]] || sqlmap_all_in_one_findings=0
    sqlmap_operator_findings=0
    for operator_log in "${result_dir}/vulns/sqlmap_operator/"*.txt; do
        [[ ! -f "$operator_log" ]] && continue
        if grep -qi "is vulnerable" "$operator_log" 2>/dev/null; then
            sqlmap_operator_findings=$((sqlmap_operator_findings + 1))
        fi
    done

    {
        echo "# Recon Report: ${target_display}"
        echo ""
        echo "**Generated**: $(date '+%Y-%m-%d %H:%M:%S %Z')"
        echo "**Scan Method**: ${scan_method}"
        echo "**Tool**: Auto Recon v${APP_VERSION}"
        echo "**Profile**: $(engagement_profile_label "${ENGAGEMENT_PROFILE:-balanced}")"
        echo "**OffSec Safe Mode**: $([ "${OFFSEC_OSCP_SAFE_MODE}" == "true" ] && echo "ON" || echo "OFF")"
        echo "**Input Target**: ${input_target}"
        echo "**Resolved Target**: ${ip}"
        echo "**Target Type**: ${target_type}"
        [[ -n "$target_domain" ]] && echo "**Primary Hostname**: ${target_domain}"
        echo "**Result Directory**: \`${result_dir}\`"
        echo ""
        echo "---"
        echo ""

        echo "## Executive Summary"
        echo ""
        echo "- **Open Ports**: ${port_count} (${ports})"
        echo "- **Web Services**: ${web_count}"
        echo "- **Distinct Web Apps / Targets**: ${web_app_count}"
        echo "- **Subdomains**: ${subdomain_count}"
        echo "- **Discovered Hostnames/VHosts**: ${hostname_count}"
        echo "- **CVEs Found**: ${cve_count}"
        echo "- **SQLMap All-in-One Findings**: ${sqlmap_all_in_one_findings}"
        echo "- **SQLMap Operator Findings**: ${sqlmap_operator_findings}"
        echo "- **Phase Warnings**: ${phase_issue_count}"
        echo ""

        echo "## Pipeline Health"
        echo ""
        report_phase_table "$result_dir"
        echo ""

        echo "## Port Scan Results"
        echo ""
        if [[ -f "${result_dir}/scans/nmap_targeted.nmap" ]]; then
            echo '```'
            grep -E '^PORT[[:space:]]+STATE[[:space:]]+SERVICE|^[0-9]+/(tcp|udp)' "${result_dir}/scans/nmap_targeted.nmap"
            echo '```'
        else
            echo "No detailed scan results available."
        fi
        echo ""

        echo "## Service Enumeration"
        echo ""
        for svc_file in "${result_dir}/scans/"*.txt; do
            [[ ! -f "$svc_file" ]] && continue
            local svc_base
            local svc_name
            svc_base=$(basename "$svc_file")
            case "$svc_base" in
                alive_hosts.txt|open_ports.txt|scan_method.txt|udp_open_ports.txt|web_ports.txt)
                    continue
                    ;;
            esac
            svc_name=$(basename "$svc_file" .txt | sed 's/_/ /g' | tr '[:lower:]' '[:upper:]')
            echo "### ${svc_name}"
            echo ""
            echo "<details>"
            echo "<summary>Preview</summary>"
            echo ""
            echo '```'
            report_preview_file "$svc_file" "$preview_lines"
            echo '```'
            echo ""
            echo "</details>"
            echo ""
        done

        if [[ -f "${result_dir}/scans/web_ports.txt" ]] && [[ -s "${result_dir}/scans/web_ports.txt" ]]; then
            echo "## Web Reconnaissance"
            echo ""

            echo "### Web Target Inventory"
            echo ""
            while read -r url; do
                [[ -z "$url" ]] && continue
                local base_name
                local artifact_count
                local artifact_names=""
                base_name=$(report_web_target_key "$url")
                artifact_count=$(find "${result_dir}/web" -maxdepth 1 -type f \
                    \( -name "*${base_name}*.txt" -o -name "*${base_name}*.json" \) 2>/dev/null | wc -l)

                echo "#### ${url}"
                echo ""
                echo "- **Artifact Count**: ${artifact_count}"

                artifact_names=$(find "${result_dir}/web" -maxdepth 1 -type f \
                    \( -name "*${base_name}*.txt" -o -name "*${base_name}*.json" \) \
                    -printf '%f\n' 2>/dev/null | sort | head -n "$finding_limit")
                if [[ -n "$artifact_names" ]]; then
                    echo ""
                    echo '```'
                    printf '%s\n' "$artifact_names"
                    echo '```'
                fi

                if [[ -f "${result_dir}/web/quick_hits_${base_name}.txt" ]] && [[ -s "${result_dir}/web/quick_hits_${base_name}.txt" ]]; then
                    echo ""
                    echo "**Quick Hits**"
                    echo ""
                    echo '```'
                    report_preview_file "${result_dir}/web/quick_hits_${base_name}.txt" 20
                    echo '```'
                fi

                if [[ -f "${result_dir}/web/hinted_paths_${base_name}.txt" ]] && [[ -s "${result_dir}/web/hinted_paths_${base_name}.txt" ]]; then
                    echo ""
                    echo "**Hinted Paths**"
                    echo ""
                    echo '```'
                    report_preview_file "${result_dir}/web/hinted_paths_${base_name}.txt" 20
                    echo '```'
                fi

                if [[ -f "${result_dir}/web/params_${base_name}.txt" ]] && [[ -s "${result_dir}/web/params_${base_name}.txt" ]]; then
                    echo ""
                    echo "**Parameter Discovery**"
                    echo ""
                    echo '```'
                    report_preview_file "${result_dir}/web/params_${base_name}.txt" 25
                    echo '```'
                fi

                if [[ -f "${result_dir}/web/api_fuzz_${base_name}.txt" ]] && [[ -s "${result_dir}/web/api_fuzz_${base_name}.txt" ]]; then
                    echo ""
                    echo "**API Endpoints**"
                    echo ""
                    echo '```'
                    report_preview_file "${result_dir}/web/api_fuzz_${base_name}.txt" 25
                    echo '```'
                fi

                echo ""
            done < <(report_web_targets "$result_dir")

            if [[ -f "${result_dir}/web/subdomains_resolved.txt" ]] && [[ -s "${result_dir}/web/subdomains_resolved.txt" ]]; then
                echo "### Subdomains Discovered"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/web/subdomains_resolved.txt" "$finding_limit"
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/web/discovered_hostnames.txt" ]] && [[ -s "${result_dir}/web/discovered_hostnames.txt" ]]; then
                echo "### Discovered Hostnames / VHosts"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/web/discovered_hostnames.txt" "$finding_limit"
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/web/hosts_suggestions.txt" ]] && [[ -s "${result_dir}/web/hosts_suggestions.txt" ]]; then
                echo "### Suggested /etc/hosts Entries"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/web/hosts_suggestions.txt" "$finding_limit"
                echo '```'
                echo ""
            fi

            for fp in "${result_dir}/web/fingerprint_"*.txt; do
                [[ ! -f "$fp" ]] && continue
                echo "### Technology Fingerprint ($(basename "$fp"))"
                echo ""
                echo '```'
                grep -A2 "WhatWeb\|Server:\|X-Powered-By:" "$fp" 2>/dev/null | head -n 20
                echo '```'
                echo ""
            done

            for fuzz in "${result_dir}/web/feroxbuster_"*.txt "${result_dir}/web/gobuster_d"*.txt "${result_dir}/web/ffuf_"*.json; do
                [[ ! -f "$fuzz" ]] && continue
                local tool_name
                tool_name=$(basename "$fuzz" | cut -d'_' -f1)
                echo "### Directory Fuzzing (${tool_name})"
                echo ""
                echo '```'
                if [[ "$fuzz" == *.json ]]; then
                    grep -oE 'https?://[^"]+' "$fuzz" 2>/dev/null | head -n "$finding_limit"
                else
                    grep -E "^http|^200|^301|^302|^307|^401|^403|^405|\\[[0-9]{3}\\]" "$fuzz" 2>/dev/null | head -n "$finding_limit"
                fi
                echo '```'
                echo ""
            done

            for nikto_f in "${result_dir}/web/nikto_"*.txt; do
                [[ ! -f "$nikto_f" ]] && continue
                echo "### Nikto Findings ($(basename "$nikto_f"))"
                echo ""
                echo '```'
                grep '+' "$nikto_f" 2>/dev/null | head -n 40
                echo '```'
                echo ""
            done

            for cms_f in "${result_dir}/web/joomla_"*.txt "${result_dir}/web/drupal_"*.txt "${result_dir}/web/cms_fuzz_"*.txt "${result_dir}/web/cms_fuzz_"*.json; do
                [[ ! -f "$cms_f" ]] && continue
                echo "### CMS Findings ($(basename "$cms_f"))"
                echo ""
                echo '```'
                if [[ "$cms_f" == *.json ]]; then
                    grep -oE 'https?://[^"]+' "$cms_f" 2>/dev/null | head -n "$preview_lines"
                else
                    report_preview_file "$cms_f" "$preview_lines"
                fi
                echo '```'
                echo ""
            done

            for sa in "${result_dir}/web/source_analysis_"*.txt; do
                [[ ! -f "$sa" ]] && continue
                if [[ $(grep -c '.' "$sa" 2>/dev/null) -gt 5 ]]; then
                    echo "### Source Code Analysis ($(basename "$sa"))"
                    echo ""
                    echo '```'
                    report_preview_file "$sa" "$preview_lines"
                    echo '```'
                    echo ""
                fi
            done
        fi

        if [[ -f "${result_dir}/scans/udp_scan.nmap" ]]; then
            echo "## UDP Scan Results"
            echo ""
            echo '```'
            grep '^[0-9]' "${result_dir}/scans/udp_scan.nmap" | grep 'open' | grep -v 'filtered'
            echo '```'
            echo ""
        fi

        echo "## Vulnerabilities"
        echo ""

        if [[ -f "${result_dir}/vulns/cves_found.txt" ]]; then
            echo "### CVEs Detected"
            echo ""
            while read -r cve; do
                [[ -z "$cve" ]] && continue
                echo "- [HIGH] **${cve}** - https://nvd.nist.gov/vuln/detail/${cve}"
            done < "${result_dir}/vulns/cves_found.txt"
            echo ""
        fi

        for nf in "${result_dir}/vulns/nuclei_"*.txt; do
            [[ ! -f "$nf" || ! -s "$nf" ]] && continue
            echo "### Nuclei Findings ($(basename "$nf"))"
            echo ""
            echo '```'
            report_preview_file "$nf" "$finding_limit"
            echo '```'
            echo ""
        done

        if [[ -f "${result_dir}/vulns/searchsploit_auto.txt" ]] || [[ -f "${result_dir}/vulns/searchsploit_manual.txt" ]]; then
            echo "### Known Exploits (SearchSploit)"
            echo ""
            if [[ -f "${result_dir}/vulns/searchsploit_auto.txt" ]]; then
                echo "#### Auto Correlation"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/vulns/searchsploit_auto.txt" 50
                echo '```'
                echo ""
            fi
            if [[ -f "${result_dir}/vulns/searchsploit_manual.txt" ]]; then
                echo "#### Manual Ranked Queries"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/vulns/searchsploit_manual.txt" "$preview_lines"
                echo '```'
                echo ""
            fi
        fi

        if [[ -f "${result_dir}/vulns/sqlmap_auto.txt" ]] && grep -qi "is vulnerable" "${result_dir}/vulns/sqlmap_auto.txt" 2>/dev/null; then
            echo "### Auto SQLi Verification (SQLMap)"
            echo ""
            echo "> **CRITICAL** Injectable parameters verified."
            echo ""
            echo '```sql'
            grep -B 1 -A 5 "is vulnerable" "${result_dir}/vulns/sqlmap_auto.txt"
            echo '```'
            echo ""
        fi

        if [[ -f "${result_dir}/vulns/sqlmap_all_in_one_summary.txt" ]]; then
            echo "### SQLMap All-in-One Workflow"
            echo ""
            echo '```bash'
            report_preview_file "${result_dir}/vulns/sqlmap_all_in_one_summary.txt" 60
            echo '```'
            echo ""
        fi

        if [[ -f "${result_dir}/vulns/sqlmap_operator_summary.txt" ]]; then
            echo "### SQLMap Operator Workflow"
            echo ""
            echo '```bash'
            report_preview_file "${result_dir}/vulns/sqlmap_operator_summary.txt" 60
            echo '```'
            echo ""

            if [[ -f "${result_dir}/vulns/sqlmap_operator_commands.txt" ]]; then
                echo "#### Repro Commands"
                echo ""
                echo '```bash'
                report_preview_file "${result_dir}/vulns/sqlmap_operator_commands.txt" 20
                echo '```'
                echo ""
            fi
        fi

        if [[ -f "${result_dir}/vulns/lfi_auto.txt" ]] && [[ -s "${result_dir}/vulns/lfi_auto.txt" ]]; then
            echo "### Auto LFI Verification"
            echo ""
            echo "> **CRITICAL** Local File Inclusion verified."
            echo ""
            echo '```bash'
            report_preview_file "${result_dir}/vulns/lfi_auto.txt" "$preview_lines"
            echo '```'
            echo ""
        fi

        if [[ -f "${result_dir}/vulns/msf_mapping.txt" ]] && grep -q "exploit/" "${result_dir}/vulns/msf_mapping.txt" 2>/dev/null; then
            echo "### Metasploit Module Mapping"
            echo ""
            echo '```bash'
            report_preview_file "${result_dir}/vulns/msf_mapping.txt" "$preview_lines"
            echo '```'
            echo ""
        fi

        for ssl_f in "${result_dir}/web/ssl_"*.txt; do
            [[ ! -f "$ssl_f" ]] && continue
            if grep -qi "VULNERABLE\|heartbleed\|poodle" "$ssl_f" 2>/dev/null; then
                echo "### SSL/TLS Vulnerabilities ($(basename "$ssl_f"))"
                echo ""
                echo '```'
                grep -A3 "VULNERABLE\|heartbleed\|poodle\|Certificate:" "$ssl_f" 2>/dev/null | head -n 30
                echo '```'
                echo ""
            fi
        done

        for waf_f in "${result_dir}/web/waf_"*.txt; do
            [[ ! -f "$waf_f" ]] && continue
            if grep -Eqi "is behind|is protected|behind .+waf" "$waf_f" 2>/dev/null && \
               ! grep -Eqi "no waf detected|no .* detected by the generic detection" "$waf_f" 2>/dev/null; then
                echo "### WAF Detected ($(basename "$waf_f"))"
                echo ""
                echo '```'
                report_preview_file "$waf_f" 30
                echo '```'
                echo ""
            fi
        done

        if [[ -f "${result_dir}/web/default_creds.txt" ]] && grep -qi "POSSIBLE LOGIN\|WORKS" "${result_dir}/web/default_creds.txt" 2>/dev/null; then
            echo "### Default Credentials"
            echo ""
            echo '```'
            grep -i "POSSIBLE LOGIN\|WORKS\|\[200\]\|\[301\]\|\[302\]" "${result_dir}/web/default_creds.txt" | head -n "$finding_limit"
            echo '```'
            echo ""
        fi

        if [[ -d "${result_dir}/loot" ]] && ls "${result_dir}/loot/"*.txt >/dev/null 2>&1; then
            echo "## Loot & Intelligence"
            echo ""
            for loot_f in "${result_dir}/loot/"*.txt; do
                [[ ! -f "$loot_f" || ! -s "$loot_f" ]] && continue
                echo "### $(basename "$loot_f" .txt)"
                echo ""
                echo '```'
                report_preview_file "$loot_f" 50
                echo '```'
                echo ""
            done
        fi

        if [[ -f "${result_dir}/scans/auth_surfaces.tsv" ]] || \
           [[ -f "${result_dir}/scans/windows_auth_inventory.txt" ]] || \
           [[ -f "${result_dir}/scans/linux_remote_access_inventory.txt" ]] || \
           [[ -f "${result_dir}/scans/directory_services_inventory.txt" ]]; then
            echo "## Operator Inventories"
            echo ""

            if [[ -f "${result_dir}/scans/auth_surfaces.tsv" ]]; then
                echo "### Authentication Surfaces"
                echo ""
                echo '```tsv'
                report_preview_file "${result_dir}/scans/auth_surfaces.tsv" 60
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/scans/windows_auth_inventory.txt" ]]; then
                echo "### Windows Auth Inventory"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/scans/windows_auth_inventory.txt" 80
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/scans/linux_remote_access_inventory.txt" ]]; then
                echo "### Linux Remote Access Inventory"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/scans/linux_remote_access_inventory.txt" 80
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/scans/directory_services_inventory.txt" ]]; then
                echo "### Directory Services Inventory"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/scans/directory_services_inventory.txt" 80
                echo '```'
                echo ""
            fi
        fi

        if [[ -f "${result_dir}/toolkit/credential_cache.tsv" ]] || \
           [[ -f "${result_dir}/toolkit/summary.txt" ]] || \
           [[ -f "${result_dir}/toolkit/sessions/generated_commands.txt" ]] || \
           compgen -G "${result_dir}/toolkit/helpers/*.txt" >/dev/null; then
            echo "## Operator Toolkit"
            echo ""

            if [[ -f "${result_dir}/toolkit/summary.txt" ]]; then
                echo "### Toolkit Summary"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/toolkit/summary.txt" 80
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/toolkit/credential_cache.tsv" ]]; then
                echo "### Credential Cache"
                echo ""
                echo '```tsv'
                report_preview_file "${result_dir}/toolkit/credential_cache.tsv" 40
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/toolkit/sessions/generated_commands.txt" ]]; then
                echo "### Generated Operator Commands"
                echo ""
                echo '```bash'
                report_preview_file "${result_dir}/toolkit/sessions/generated_commands.txt" 60
                echo '```'
                echo ""
            fi

            for helper_f in "${result_dir}/toolkit/helpers/"*.txt; do
                [[ -f "$helper_f" ]] || continue
                echo "### Toolkit Helper: $(basename "$helper_f" .txt)"
                echo ""
                echo '```'
                report_preview_file "$helper_f" 80
                echo '```'
                echo ""
            done
        fi

        if [[ -f "${result_dir}/wordlists/summary.txt" ]] || \
           [[ -f "${result_dir}/wordlists/custom_usernames.txt" ]] || \
           [[ -f "${result_dir}/wordlists/custom_passwords.txt" ]] || \
           [[ -f "${result_dir}/wordlists/custom_content.txt" ]] || \
           [[ -f "${result_dir}/wordlists/custom_all.txt" ]]; then
            echo "## Wordlist Toolkit"
            echo ""

            if [[ -f "${result_dir}/wordlists/summary.txt" ]]; then
                echo "### Wordlist Summary"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/wordlists/summary.txt" 80
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/wordlists/custom_usernames.txt" ]]; then
                echo "### Custom Usernames"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/wordlists/custom_usernames.txt" 40
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/wordlists/custom_passwords.txt" ]]; then
                echo "### Custom Passwords"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/wordlists/custom_passwords.txt" 40
                echo '```'
                echo ""
            fi

            if [[ -f "${result_dir}/wordlists/custom_content.txt" ]]; then
                echo "### Custom Content Words"
                echo ""
                echo '```'
                report_preview_file "${result_dir}/wordlists/custom_content.txt" 40
                echo '```'
                echo ""
            fi
        fi

        echo "## Recommended Next Steps"
        echo ""
        local step=1

        if grep -qi "anonymous" "${result_dir}/scans/ftp_"*.txt 2>/dev/null; then
            echo "${step}. **FTP**: Anonymous login is exposed. Enumerate files and test upload paths."
            step=$((step + 1))
        fi

        if compgen -G "${result_dir}/web/wpscan_*.txt" >/dev/null; then
            echo "${step}. **WordPress**: Review WPScan output and enumerate vulnerable plugins/themes."
            step=$((step + 1))
        fi

        if grep -qi "READ\|mapping.*ok\|Anonymous" "${result_dir}/scans/smb.txt" 2>/dev/null; then
            echo "${step}. **SMB**: Browse readable shares and collect config, creds, and scripts."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/vulns/cves_found.txt" ]]; then
            echo "${step}. **CVEs**: Prioritize exploitation paths for $(head -3 "${result_dir}/vulns/cves_found.txt" | tr '\n' ',' | sed 's/,$//')."
            step=$((step + 1))
        fi

        for nf in "${result_dir}/vulns/nuclei_"*.txt; do
            [[ -f "$nf" && -s "$nf" ]] || continue
            echo "${step}. **Nuclei**: Review $(wc -l < "$nf") findings in $(basename "$nf")."
            step=$((step + 1))
            break
        done

        if [[ -f "${result_dir}/web/default_creds.txt" ]] && grep -qi "POSSIBLE LOGIN\|WORKS" "${result_dir}/web/default_creds.txt" 2>/dev/null; then
            echo "${step}. **Default Creds**: Validate the candidate logins against the app inventory above."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/scans/udp_open_ports.txt" ]] && [[ -s "${result_dir}/scans/udp_open_ports.txt" ]]; then
            echo "${step}. **UDP**: Follow up SNMP, TFTP, or DNS based on the open UDP ports."
            step=$((step + 1))
        fi

        if echo "$ports" | grep -q "22"; then
            echo "${step}. **SSH**: Reuse discovered usernames and wordlists against SSH."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/loot/cewl_wordlist.txt" ]] && [[ -s "${result_dir}/loot/cewl_wordlist.txt" ]]; then
            echo "${step}. **Password Reuse**: Apply the CeWL wordlist ($(wc -l < "${result_dir}/loot/cewl_wordlist.txt") entries) to authenticated services."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/wordlists/custom_passwords.txt" ]] && [[ -s "${result_dir}/wordlists/custom_passwords.txt" ]]; then
            echo "${step}. **Custom Wordlists**: Reuse the generated target-derived lists under wordlists/ for Hydra, SSH, SMB, WinRM, and web logins."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/toolkit/sessions/generated_commands.txt" ]] && [[ -s "${result_dir}/toolkit/sessions/generated_commands.txt" ]]; then
            echo "${step}. **Operator Toolkit**: Replay the reviewed Windows/Linux commands saved under toolkit/sessions/generated_commands.txt."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/scans/windows_auth_inventory.txt" ]] || [[ -f "${result_dir}/scans/linux_remote_access_inventory.txt" ]]; then
            echo "${step}. **Access Paths**: Prioritize the auth surfaces and remote access inventories before manual exploitation."
            step=$((step + 1))
        fi

        if [[ -f "${result_dir}/web/hosts_suggestions.txt" ]] && [[ -s "${result_dir}/web/hosts_suggestions.txt" ]]; then
            echo "${step}. **Host Mapping**: Import the suggested hostnames before browser-based testing and proxy work."
            step=$((step + 1))
        fi

        if (( phase_issue_count > 0 )); then
            echo "${step}. **Pipeline Gaps**: Review the Pipeline Health table and rerun any phase marked failed or partial."
            step=$((step + 1))
        fi

        echo "${step}. **Manual Review**: Walk the output files listed below."
        echo ""

        echo "## Output Files"
        echo ""
        echo '```'
        find "$result_dir" -type f \
            \( -name "*.txt" -o -name "*.nmap" -o -name "*.xml" -o -name "*.json" -o -name "*.md" -o -name "*.html" -o -name "*.env" \) \
            2>/dev/null | sort | sed "s|${result_dir}/||" | head -n "$file_index_limit"
        echo '```'
    } > "$report"

    if generate_html_report "$report" "$html_report" "Recon Report: ${target_display}"; then
        log_success "Report generated → ${report}"
        log_success "HTML report generated → ${html_report}"
    else
        log_warn "Markdown report generated, but HTML export failed"
        log_success "Report generated → ${report}"
    fi

    echo ""
    echo -e "  ${BOLD}${CYAN}Report Digest${NC}"
    awk '
        /^## Port Scan Results/ { exit }
        /^## Service Enumeration/ { exit }
        /^## Output Files/ { exit }
        { print }
    ' "$report" | head -n 80

    echo ""
    echo -e "  ${BOLD}${GREEN}📄 View report: cat ${report}${NC}"
    echo -e "  ${BOLD}${GREEN}🌐 HTML report: xdg-open ${html_report}${NC}"
}
