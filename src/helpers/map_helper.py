# Maps event codes to their source (used for additional information)
event_code_to_source = {
    'Acc': 'Apache access',
    'Aud': 'Audit',
    'Aut': 'Authentication logs',
    'Err': 'Apache error',
    'Mai': 'Mail logs',
    'Sys': 'Syslogs',
    'Mon': 'Resource monitoring',
    'Dns': 'DNS packet captures',
    'Flw': 'Flow packet captures',
    'Htt': 'HTTP packet captures',
    'Nat': 'NAT packet captures',
    'Smt': 'SMTP packet captures',
    'Tls': 'TLS packet captures',
    'All': 'Multiple sources'
}

# Maps alert specific labels to generic labels (used for observable categories)
alert_label_to_observable_label = {
    '-': '-',

    'service_scan': 'service_scan',
    'dirb': 'dirb',
    'wpscan': 'wpscan',

    'webshell_cmd': 'webshell_cmd',

    'online_cracking': 'online_cracking',
    'crack_passwords': 'online_cracking',
    'attacker_change_user': 'attacker_change_user',
    'escalated_sudo_command': 'escalated_sudo_command',

    'dnsteal': 'dnsteal'
}

# Maps log specific labels to generic labels (used for observable categories)
log_labels_to_observable_label = {
    '-': '-',

    'attacker_vpn|foothold': 'attacker_vpn',
    'attacker_vpn|escalate': 'attacker_vpn',

    'dns_scan|foothold': 'dns_scan',
    'network_scan|foothold': 'network_scan',
    'traceroute|foothold': 'traceroute',

    'attacker_http|foothold|service_scan': 'service_scan',
    'service_scan|foothold': 'service_scan',
    'attacker_http|foothold|dirb': 'dirb',
    'dirb|foothold': 'dirb',
    'attacker_http|foothold|wpscan': 'wpscan',
    'wpscan|foothold': 'wpscan',

    'attacker_http|foothold|webshell_upload': 'webshell_cmd',
    'attacker_http|foothold|webshell_cmd': 'webshell_cmd',
    'webshell_cmd|escalate': 'webshell_cmd',

    'escalate|crack_passwords': 'online_cracking',
    'attacker_change_user|escalate': 'attacker_change_user',
    'escalated_command|escalated_sudo_command|escalate|escalated_sudo_session': 'escalated_sudo_command',
    'escalated_command|escalated_sudo_command|escalated_sudo_session|escalate': 'escalated_sudo_command',
    'attacker_change_user|escalate|escalated_command|escalated_sudo_command': 'escalated_sudo_command',
    'escalated_command|escalated_sudo_command|escalate': 'escalated_sudo_command',

    'dnsteal|exfiltration-service|attacker': 'dnsteal',
    'dnsteal|attacker|dnsteal-received': 'dnsteal',
    'dnsteal|attacker|dnsteal-dropped': 'dnsteal',
}
