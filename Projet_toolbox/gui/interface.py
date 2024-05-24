import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scripts.port_scan import port_scan
from scripts.ssh_brute_force import ssh_brute_force
from scripts.dns_lookup import lookup_dns, reverse_dns
from scripts.web_crawler import crawl
from scripts.password_cracker import crack_password
from scripts.network_scanner import scan_network, format_scan_results
from scripts.report_generator import generate_report
import os
import platform

class ToolboxApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cybersécurité Toolbox")

        self.default_report_path = "C:/reports" if platform.system() == "Windows" else "/home/user/reports"
        
        self.create_widgets()
        self.make_responsive()

    def create_widgets(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.label = tk.Label(self.main_frame, text="Sélectionnez une fonctionnalité", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.nmap_button = ttk.Button(self.main_frame, text="Port Scan avec Nmap", command=self.nmap_options)
        self.nmap_button.pack(pady=5)

        self.network_scan_button = ttk.Button(self.main_frame, text="Scan de Réseau", command=self.network_scan_options)
        self.network_scan_button.pack(pady=5)

        self.ssh_button = ttk.Button(self.main_frame, text="Brute Force SSH", command=self.ssh_options)
        self.ssh_button.pack(pady=5)

        self.dns_button = ttk.Button(self.main_frame, text="DNS Lookup / Reverse DNS", command=self.dns_options)
        self.dns_button.pack(pady=5)

        self.crawl_button = ttk.Button(self.main_frame, text="Web Crawler", command=self.crawl_options)
        self.crawl_button.pack(pady=5)

        self.crack_button = ttk.Button(self.main_frame, text="Cracker de mot de passe", command=self.crack_options)
        self.crack_button.pack(pady=5)

    def make_responsive(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_configure(fill=tk.X, expand=True)

    def nmap_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options Nmap")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="IP Cible (ex: 192.168.1.1) :").pack(pady=5)
        target_entry = tk.Entry(frame)
        target_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Plage de ports (ex: 1-1000) :").pack(pady=5)
        port_range_entry = tk.Entry(frame)
        port_range_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Type de scan :").pack(pady=5)
        scan_type_var = tk.StringVar()
        scan_type_menu = ttk.Combobox(frame, textvariable=scan_type_var)
        scan_types = {
            '-sS': 'Scan TCP SYN : Ce scan est plus rapide que le scan de connexion TCP et fonctionne avec n\'importe quelle pile TCP conforme.',
            '-sT': 'Scan de connexion TCP : Type de scan TCP par défaut lorsque le scan SYN n\'est pas une option.',
            '-sU': 'Scan UDP : Scanne les ports UDP ouverts.',
            '-sP': 'Scan Ping : Vérifie uniquement si les hôtes sont en ligne.',
            '-sN': 'Scan sans ping : Effectue directement le scan des ports sans vérifier si les hôtes sont en ligne.',
            '-A': 'Scan agressif : Active la détection de l\'OS, la détection de version, le scan de script et le traceroute.',
            '-O': 'Détection de l\'OS : Devine le système d\'exploitation de l\'hôte cible.',
            '-sV': 'Détection de version de service : Tente de déterminer la version des services exécutés sur les ports ouverts.'
        }
        scan_type_menu['values'] = [f"{k} ({v.split(' : ')[0]})" for k, v in scan_types.items()]
        scan_type_menu.pack(pady=5, fill=tk.X, expand=True)

        scan_description_label = tk.Label(frame, text="", wraplength=400)
        scan_description_label.pack(pady=5, fill=tk.X, expand=True)

        def update_port_range_state(event):
            selected_scan = scan_type_var.get().split(' ')[0]
            if selected_scan in ['-O', '-sP', '-sN']:
                port_range_entry.config(state='disabled')
            else:
                port_range_entry.config(state='normal')
            scan_description_label.config(text=scan_types[selected_scan])

        scan_type_menu.bind('<<ComboboxSelected>>', update_port_range_state)

        def start_nmap_scan():
            target = target_entry.get()
            port_range = port_range_entry.get()
            scan_type = scan_type_var.get().split(' ')[0]
            if not target:
                messagebox.showerror("Erreur", "Veuillez entrer une IP cible.")
                return
            result = port_scan(target, port_range, scan_type)
            report_content = f"Type de scan : {scan_type} ({scan_types[scan_type].split(' : ')[0]})\nCible : {target}\n\n{result}"
            self.generate_report(report_content, "scan_nmap")

        start_button = ttk.Button(frame, text="Démarrer le scan", command=start_nmap_scan)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def network_scan_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options Scan de Réseau")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Plage d'IP Cible (ex: 192.168.1.0/24) :").pack(pady=5)
        target_entry = tk.Entry(frame)
        target_entry.pack(pady=5, fill=tk.X, expand=True)

        def start_network_scan():
            target = target_entry.get()
            if not target:
                messagebox.showerror("Erreur", "Veuillez entrer une plage d'IP cible.")
                return
            try:
                result = scan_network(target)
                report_content = format_scan_results(result)
                self.generate_report(report_content, "network_scan")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du scan de réseau : {str(e)}")

        start_button = ttk.Button(frame, text="Démarrer le Scan", command=start_network_scan)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def ssh_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options Brute Force SSH")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="IP Cible (ex: 192.168.1.1) :").pack(pady=5)
        target_entry = tk.Entry(frame)
        target_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Nom d'utilisateur (ex: admin) :").pack(pady=5)
        username_entry = tk.Entry(frame)
        username_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Mot de passe (ex: password123) :").pack(pady=5)
        password_entry = tk.Entry(frame, show='*')
        password_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Fichier de noms d'utilisateur (.txt) :").pack(pady=5)
        username_file_button = ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(username_entry))
        username_file_button.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Fichier de mots de passe (.txt) :").pack(pady=5)
        password_file_button = ttk.Button(frame, text="Parcourir", command=lambda: self.browse_file(password_entry))
        password_file_button.pack(pady=5, fill=tk.X, expand=True)

        def start_ssh_brute_force():
            target = target_entry.get()
            usernames = self.get_entries(username_entry)
            passwords = self.get_entries(password_entry, is_password=True)
            if not target or not usernames or not passwords:
                messagebox.showerror("Erreur", "Veuillez remplir tous les champs.")
                return
            try:
                result = ssh_brute_force(target, usernames, passwords)
                if "Succès" in result:
                    report_content = f"Cible : {target}\n\n{result}"
                else:
                    report_content = f"Cible : {target}\n\nÉchec du brute force SSH avec les informations fournies."
                self.generate_report(report_content, "bruteforce_ssh")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du brute force SSH : {str(e)}")

        start_button = ttk.Button(frame, text="Démarrer le Brute Force", command=start_ssh_brute_force)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def dns_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options DNS Lookup / Reverse DNS")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Nom de domaine ou IP (ex: google.com ou 8.8.8.8) :").pack(pady=5)
        dns_entry = tk.Entry(frame)
        dns_entry.pack(pady=5, fill=tk.X, expand=True)

        def start_dns_lookup():
            target = dns_entry.get()
            if not target:
                messagebox.showerror("Erreur", "Veuillez entrer un nom de domaine ou une IP.")
                return
            try:
                if self.is_valid_ip(target):
                    hostname, aliases = reverse_dns(target)
                    if hostname:
                        result = f"Reverse DNS pour {target} : {hostname}\nAliases : {', '.join(aliases)}"
                    else:
                        result = f"Reverse DNS échoué pour {target}"
                else:
                    ip = lookup_dns(target)
                    if ip:
                        result = f"DNS Lookup pour {target} : {ip}"
                    else:
                        result = f"DNS Lookup échoué pour {target}"
                report_content = f"Cible : {target}\n\n{result}"
                self.generate_report(report_content, "dns_lookup")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du DNS Lookup : {str(e)}")

        start_button = ttk.Button(frame, text="Démarrer le Lookup", command=start_dns_lookup)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def crawl_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options Web Crawler")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="URL Cible (ex: http://example.com) :").pack(pady=5)
        url_entry = tk.Entry(frame)
        url_entry.pack(pady=5, fill=tk.X, expand=True)

        tk.Label(frame, text="Nombre maximal de pages à crawler (ex: 10) :").pack(pady=5)
        max_pages_entry = tk.Entry(frame)
        max_pages_entry.pack(pady=5, fill=tk.X, expand=True)

        def start_crawling():
            url = url_entry.get()
            max_pages = int(max_pages_entry.get())
            if not url or not max_pages:
                messagebox.showerror("Erreur", "Veuillez entrer une URL et le nombre maximal de pages à crawler.")
                return
            try:
                report = crawl(url, max_pages)
                report_content = f"URL Cible : {url}\n\n"
                report_content += f"Liens Internes :\n" + "\n".join(report["internal_links"]) + "\n\n"
                report_content += f"Liens Externes :\n" + "\n".join(report["external_links"]) + "\n\n"
                report_content += f"Images :\n" + "\n".join(report["images"]) + "\n\n"
                report_content += f"Fichiers CSS :\n" + "\n".join(report["css_files"]) + "\n\n"
                report_content += f"Fichiers JavaScript :\n" + "\n".join(report["js_files"])
                self.generate_report(report_content, "web_crawl")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du crawling : {str(e)}")

        start_button = ttk.Button(frame, text="Démarrer le Crawl", command=start_crawling)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def crack_options(self):
        options_window = tk.Toplevel(self.root)
        options_window.title("Options Cracker de Mot de Passe")

        frame = tk.Frame(options_window)
        frame.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        tk.Label(frame, text="Chemin du fichier à cracker :").pack(pady=5)
        file_path_entry = tk.Entry(frame)
        file_path_entry.pack(pady=5, fill=tk.X, expand=True)

        def browse_file():
            file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
            if file_path:
                file_path_entry.delete(0, tk.END)
                file_path_entry.insert(0, file_path)

        browse_button = ttk.Button(frame, text="Parcourir", command=browse_file)
        browse_button.pack(pady=5, fill=tk.X, expand=True)

        def start_cracking():
            file_path = file_path_entry.get()
            if not file_path:
                messagebox.showerror("Erreur", "Veuillez entrer ou sélectionner le chemin du fichier à cracker.")
                return
            try:
                result = crack_password(file_path)
                report_content = f"Chemin du fichier : {file_path}\n\n{result}"
                self.generate_report(report_content, "password_crack")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors du cracking : {str(e)}")

        start_button = ttk.Button(frame, text="Démarrer le Cracking", command=start_cracking)
        start_button.pack(pady=5, fill=tk.X, expand=True)

    def is_valid_ip(self, ip):
        parts = ip.split('.')
        if len(parts) == 4 and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            return True
        return False

    def browse_file(self, entry_widget):
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            entry_widget.insert(tk.END, file_path)

    def get_entries(self, entry_widget, is_password=False):
        entries = entry_widget.get().split(',')
        final_entries = []
        for entry in entries:
            if entry.endswith(".txt"):
                file_path = entry
                with open(file_path, 'r') as file:
                    lines = file.read().splitlines()
                    final_entries.extend(lines)
            else:
                final_entries.append(entry)
        return final_entries

    def generate_report(self, content, function):
        default_dir = self.default_report_path
        os.makedirs(default_dir, exist_ok=True)

        save_default = messagebox.askyesno("Sauvegarder le rapport", f"Voulez-vous sauvegarder le rapport dans le chemin par défaut : {default_dir}?")

        if save_default:
            base_path = os.path.join(default_dir, f"rapport_{function}")
            counter = 1
            file_path = f"{base_path}.pdf"
            while os.path.exists(file_path):
                file_path = f"{base_path}_{counter}.pdf"
                counter += 1
        else:
            file_path = filedialog.asksaveasfilename(initialdir=default_dir, defaultextension=".pdf", filetypes=[("Fichiers PDF", "*.pdf")])
        
        if not file_path:
            return

        generate_report(content, file_path)

if __name__ == "__main__":
    root = tk.Tk()
    app = ToolboxApp(root)
    root.mainloop()
