import subprocess

def crack_password(file_path):
    try:
        result = subprocess.run(['john', '--format=raw-md5', file_path], capture_output=True, text=True)
        if "No password hashes" in result.stdout:
            return "Format de hachage non reconnu ou fichier invalide."
        elif "Loaded" in result.stdout:
            result = subprocess.run(['john', '--show', file_path], capture_output=True, text=True)
            cracked_passwords = result.stdout.strip().split('\n')
            if len(cracked_passwords) > 1:
                return f"Mot de passe craqué : {cracked_passwords[0]}"
            else:
                return "Le craquage a échoué."
        else:
            return "Le craquage a échoué."
    except Exception as e:
        return f"Erreur lors du craquage : {str(e)}"
