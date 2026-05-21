# fish completion for netdoc
#
# Install: copy to ~/.config/fish/completions/netdoc.fish
#
# Provides flag and value completion with helpful descriptions.

complete -c netdoc -f

complete -c netdoc -l json -d "output structured JSON report"
complete -c netdoc -l format -d "output format" -xa "json html md markdown"
complete -c netdoc -l timeout -d "per-check timeout (e.g. 5s, 30s)" -r
complete -c netdoc -l dns -d "DNS transport (system, udp, tcp, dot, doh, doq)" -xa "system udp tcp dot doh doq"
complete -c netdoc -l ports -d "ports to scan (preset or list)" -xa "top20 top100 top1000"
complete -c netdoc -l ecs -d "EDNS Client-Subnet probe (CIDR or default bouquet)"
complete -c netdoc -l check -d "comma-separated check names" -xa "dns domain delegation tcp latency path tls http security discovery mail reputation ipv6 ports"
complete -c netdoc -l profile -d "curated check preset" -xa "fast web mail full paranoid"
complete -c netdoc -l diff -d "compare to baseline JSON" -r
complete -c netdoc -l write-out -d "scriptable output template" -r
complete -c netdoc -l watch -d "live re-running mode"
complete -c netdoc -l interval -d "--watch interval" -r
complete -c netdoc -s f -l file -d "newline-delimited targets file" -r
complete -c netdoc -l concurrency -d "batch parallelism (default 8)" -r
complete -c netdoc -l history -d "show last N scans from history" -r
complete -c netdoc -l no-history -d "skip appending to ~/.netdoc/history.jsonl"
complete -c netdoc -l no-color -d "disable colored output"
complete -c netdoc -s v -l version -d "print version"
complete -c netdoc -s h -l help -d "print help"
