#!/bin/bash
# ============================================================================
# AUTO RECON - TUI Layer (gum-backed, graceful fallback to classic prompts)
# ----------------------------------------------------------------------------
# Wraps charmbracelet `gum` for menus, inputs, confirms and a live phase
# tracker. Every helper falls back to the plain read/echo behaviour when gum
# is absent or output is not a TTY, so the tool works identically without gum.
#   Install gum:  sudo apt install gum   (or: go install github.com/charmbracelet/gum@latest)
# Toggle:  USE_TUI=auto|on|off   (config.sh) or --tui / --no-tui on the CLI.
# ============================================================================

# Brand palette (gum 256-colour codes).
TUI_C_PRIMARY="${TUI_C_PRIMARY:-45}"     # cyan
TUI_C_ACCENT="${TUI_C_ACCENT:-212}"      # pink
TUI_C_OK="${TUI_C_OK:-78}"               # green
TUI_C_WARN="${TUI_C_WARN:-214}"          # orange
TUI_C_DIM="${TUI_C_DIM:-244}"            # grey

# Is the gum TUI active right now?
tui_enabled() {
    case "${USE_TUI:-auto}" in
        off|false|0) return 1 ;;
    esac
    [[ -t 1 ]] || return 1
    command -v gum &>/dev/null
}

# Bordered title block. Args: title [subtitle]
tui_header() {
    local title="$1" subtitle="${2:-}"
    if tui_enabled; then
        if [[ -n "$subtitle" ]]; then
            gum style --border rounded --margin "1 0" --padding "0 2" \
                --border-foreground "$TUI_C_PRIMARY" --foreground "$TUI_C_ACCENT" --bold \
                "$title" "$(gum style --foreground "$TUI_C_DIM" "$subtitle")"
        else
            gum style --border rounded --margin "1 0" --padding "0 2" \
                --border-foreground "$TUI_C_PRIMARY" --foreground "$TUI_C_ACCENT" --bold "$title"
        fi
    else
        section_header "$title"
        [[ -n "$subtitle" ]] && echo -e "  ${DIM}${subtitle}${NC}"
    fi
}

# A faint one-line note.
tui_note() {
    if tui_enabled; then
        gum style --foreground "$TUI_C_DIM" "$1"
    else
        echo -e "  ${DIM}$1${NC}"
    fi
}

# Single-choice menu. Args: <header> <item...>  -> echoes chosen item.
# Each item is shown as-is; callers parse the leading token.
tui_choose() {
    local header="$1"; shift
    if tui_enabled; then
        gum choose --header "$header" --cursor "❯ " \
            --cursor.foreground "$TUI_C_ACCENT" --header.foreground "$TUI_C_PRIMARY" \
            --height 16 "$@"
    else
        # Plain numbered fallback.
        echo -e "  ${BOLD}${header}${NC}" >&2
        local i=1 opt
        for opt in "$@"; do printf '   %d) %s\n' "$i" "$opt" >&2; ((i++)); done
        local pick; read -r pick
        [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick <= $# )) && eval "printf '%s\n' \"\${$pick}\""
    fi
}

# Free-text input. Args: <prompt> [default] -> echoes value (or default).
tui_input() {
    local prompt="$1" default="${2:-}"
    if tui_enabled; then
        gum input --header "$prompt" --placeholder "${default:-type here}" \
            --value "$default" --header.foreground "$TUI_C_PRIMARY"
    else
        local v
        if [[ -n "$default" ]]; then
            echo -ne "  ${BOLD}${prompt} [${default}]:${NC} " >&2
        else
            echo -ne "  ${BOLD}${prompt}:${NC} " >&2
        fi
        read -r v
        printf '%s\n' "${v:-$default}"
    fi
}

# Yes/No confirm. Returns 0 for yes, 1 for no.
tui_confirm() {
    local prompt="$1"
    if tui_enabled; then
        gum confirm "$prompt"
    else
        local a; echo -ne "  ${BOLD}${prompt} [y/N]:${NC} " >&2; read -r a
        [[ "$a" =~ ^[Yy] ]]
    fi
}

# Fuzzy file/line picker over stdin. Args: <header>
tui_filter() {
    local header="$1"
    if tui_enabled; then
        gum filter --header "$header" --height 18 --header.foreground "$TUI_C_PRIMARY"
    else
        cat   # no-op passthrough
    fi
}

# ── Live phase tracker ─────────────────────────────────────────────────────
# Ordered list of pipeline phases for the dashboard.
TUI_PIPELINE_PHASES=(port_scan service_enum web_recon wordlist_toolkit vuln_scan privesc brute_force report)
declare -A TUI_PHASE_LABELS=(
    [port_scan]="Port Scan"
    [service_enum]="Service Enum"
    [web_recon]="Web Recon"
    [wordlist_toolkit]="Wordlists"
    [vuln_scan]="Vuln Scan"
    [privesc]="Priv-Esc"
    [brute_force]="Brute Force"
    [report]="Report"
)

# Map a phase-state status to an icon+colour (plain or gum).
_tui_status_glyph() {
    case "$1" in
        completed) printf '✔' ;;
        running)   printf '⟳' ;;
        partial)   printf '◐' ;;
        failed)    printf '✘' ;;
        skipped)   printf '−' ;;
        *)         printf '·' ;;
    esac
}

# Render the full pipeline dashboard from state/*.env. Arg: result_dir
tui_pipeline_overview() {
    local result_dir="$1"
    [[ -n "$result_dir" ]] || return 0
    local phase status glyph line
    local -a lines=()
    for phase in "${TUI_PIPELINE_PHASES[@]}"; do
        status=$(read_metadata_value "${result_dir}/state/${phase}.env" status 2>/dev/null)
        status="${status:-pending}"
        glyph=$(_tui_status_glyph "$status")
        printf -v line '%s  %-14s %s' "$glyph" "${TUI_PHASE_LABELS[$phase]}" "$status"
        lines+=("$line")
    done
    if tui_enabled; then
        gum style --border normal --padding "0 2" --margin "1 0" \
            --border-foreground "$TUI_C_PRIMARY" --foreground "$TUI_C_OK" \
            "Pipeline progress" "${lines[@]}"
    else
        echo -e "\n  ${BOLD}${CYAN}Pipeline progress${NC}"
        local l; for l in "${lines[@]}"; do echo "    $l"; done
        echo ""
    fi
}

# Called right after a phase finishes (hooked from run_phase_with_state) to
# refresh the dashboard during a full-auto run.
tui_after_phase() {
    local phase="$1" result_dir="$2"
    tui_enabled || return 0
    [[ "${TUI_LIVE_TRACKER:-0}" == "1" ]] || return 0
    tui_pipeline_overview "$result_dir"
}
