# bash completion for netdoc
#
# Install: drop into /usr/share/bash-completion/completions/netdoc
#   or source from ~/.bashrc:
#     source /path/to/netdoc.bash
#
# Provides:
#   - flag completion (--json, --watch, --check, --profile, --ports, ...)
#   - --check value completion (tls, dns, mail, ...)
#   - --profile value completion (fast, web, mail, full, paranoid)
#   - --ports preset completion (top20, top100, top1000)
#   - --dns transport completion (system, udp, tcp, dot, doh, doq)
#   - --format value completion (json, html, md, markdown)
#   - file completion for -f / --file / --diff

_netdoc()
{
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    opts="--json --format --timeout --dns --ports --ecs --check --profile
          --diff --write-out --watch --interval -f --file --concurrency
          --history --no-history --no-color -v --version -h --help"

    case "${prev}" in
        --check)
            COMPREPLY=( $(compgen -W "dns domain delegation tcp latency path tls http security discovery mail reputation ipv6 ports" -- "${cur}") )
            return 0
            ;;
        --profile)
            COMPREPLY=( $(compgen -W "fast web mail full paranoid" -- "${cur}") )
            return 0
            ;;
        --ports)
            COMPREPLY=( $(compgen -W "top20 top100 top1000 22 80 443 22,80,443" -- "${cur}") )
            return 0
            ;;
        --dns)
            COMPREPLY=( $(compgen -W "system udp tcp dot doh doq" -- "${cur}") )
            return 0
            ;;
        --format)
            COMPREPLY=( $(compgen -W "json html md markdown" -- "${cur}") )
            return 0
            ;;
        -f|--file|--diff)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --timeout|--interval|--concurrency|--history|--watch)
            return 0
            ;;
    esac

    if [[ ${cur} == -* ]]; then
        COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
        return 0
    fi
}
complete -F _netdoc netdoc
