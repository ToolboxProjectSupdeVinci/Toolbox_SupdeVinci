import nmap

def port_scan(target, port_range, scan_type):
    nm = nmap.PortScanner()
    try:
        if scan_type in ['-O', '-sP', '-sN']:
            scan_result = nm.scan(hosts=target, arguments=scan_type)
        else:
            scan_result = nm.scan(hosts=target, ports=port_range, arguments=scan_type)
    except Exception as e:
        return f"Erreur lors du scan : {e}"
    
    report_lines = []

    if scan_type == '-O':
        os_info = scan_result['scan'].get(target, {}).get('osclass', [{}])[0].get('osfamily', 'Système d\'exploitation inconnu')
        report_lines.append(f"Le système d'exploitation détecté est : {os_info}")
    elif scan_type == '-A':
        ports_info = scan_result['scan'][target].get('tcp', {})
        report_lines.append("Ports ouverts :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}")
    elif scan_type == '-sS':
        ports_info = scan_result['scan'][target].get('tcp', {})
        report_lines.append("Scan TCP SYN :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}")
    elif scan_type == '-sT':
        ports_info = scan_result['scan'][target].get('tcp', {})
        report_lines.append("Scan de connexion TCP :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}")
    elif scan_type == '-sU':
        ports_info = scan_result['scan'][target].get('udp', {})
        report_lines.append("Scan UDP :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}")
    elif scan_type == '-sV':
        ports_info = scan_result['scan'][target].get('tcp', {})
        report_lines.append("Détection de version de service :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}, Version : {info.get('version', 'Inconnue')}")
    elif scan_type == '-sP':
        hosts = scan_result['scan']
        for host, info in hosts.items():
            if info['status']['state'] == 'up':
                report_lines.append(f"L'hôte {host} est en ligne.")
            else:
                report_lines.append(f"L'hôte {host} n'est pas en ligne.")
    elif scan_type == '-sN':
        ports_info = scan_result['scan'][target].get('tcp', {})
        report_lines.append("Scan sans ping :")
        for port, info in ports_info.items():
            report_lines.append(f"Port : {port}, État : {info['state']}, Service : {info['name']}")
    else:
        report_lines.append(f"Résultats du scan {scan_type} : {scan_result}")

    return "\n".join(report_lines)
