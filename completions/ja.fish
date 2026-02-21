# Fish completions for ja (jailer)

# Disable file completions by default
complete -c ja -f

# Complete jail names from ~/.jails/ as the first argument
complete -c ja -n '__fish_is_first_arg' -a '(command ls ~/.jails/ 2>/dev/null)' -d 'jail name'

# Flags
complete -c ja -s h -l help -d 'Show help'

# After --, complete files/commands normally
complete -c ja -n '__fish_seen_argument -l --' -F
