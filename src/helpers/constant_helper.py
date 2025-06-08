MODALITY_COMBINATIONS = [
    ['logs'],
    ['wazuh'],
    ['suricata'],
    ['aminer'],
    ['logs', 'wazuh'],
    ['logs', 'suricata'],
    ['logs', 'aminer'],
    ['wazuh', 'suricata'],
    ['wazuh', 'aminer'],
    ['suricata', 'aminer'],
    ['logs', 'wazuh', 'suricata'],
    ['logs', 'wazuh', 'aminer'],
    ['logs', 'suricata', 'aminer'],
    ['wazuh', 'suricata', 'aminer'],
    ['logs', 'wazuh', 'suricata', 'aminer']
]

# Ground truth created from analysing the related papers and configuration files
ATTACK_DESCRIPTIONS = {
    'fox': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'harrison': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'russellmitchell': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'santos': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'shaw': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wardbeck': [
        'service_scan-->wpscan',
        'wpscan-->dirb',
        'dirb-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wheeler': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->offline_cracking',
        'offline_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
    'wilson': [
        'service_scan-->dirb',
        'dirb-->wpscan',
        'wpscan-->webshell_cmd',
        'webshell_cmd-->online_cracking',
        'online_cracking-->attacker_change_user',
        'attacker_change_user-->escalated_sudo_command'
    ],
}