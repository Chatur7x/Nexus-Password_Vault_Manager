import tkinter as tk
from tkinter import simpledialog, messagebox, ttk
import sys
import os

# Add cli-python to path so we can import our backend directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cli-python')))

import manager
import auth

class VaultPythonGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Pass-Vault-Manager (Python Native GUI)")
        self.root.geometry("600x400")
        
        self.enc_key = None
        self.mac_key = None
        self.vault_data = {}
        
        self.prompt_password()
        
    def prompt_password(self):
        pwd = simpledialog.askstring("Master Password", "Enter Master Password:", show='*')
        if not pwd:
            self.root.destroy()
            return
            
        try:
            salt = auth.get_or_create_salt(manager.SALT_FILE)
            self.enc_key, self.mac_key = auth.derive_keys(pwd, salt)
            
            # Load vault
            self.vault_data = manager.load_vault(self.enc_key, self.mac_key)
            self.init_ui()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt vault! Tampered data or wrong password.\n{e}")
            self.root.destroy()

    def init_ui(self):
        # Treeview for passwords
        columns = ('title', 'user')
        self.tree = ttk.Treeview(self.root, columns=columns, show='headings')
        self.tree.heading('title', text='Service Title')
        self.tree.heading('user', text='Username')
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.tree.bind('<Double-1>', self.on_item_double_click)
        
        self.refresh_list()
        
        # Bottom frame
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Button(btn_frame, text="Add Password", command=self.add_password).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Check Health", command=self.check_health).pack(side=tk.LEFT, padx=5)
        
    def refresh_list(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for title, data in self.vault_data.items():
            self.tree.insert('', tk.END, values=(title, data.get('user', '')))
            
    def on_item_double_click(self, event):
        item = self.tree.selection()[0]
        title = self.tree.item(item, "values")[0]
        entry = self.vault_data[title]
        
        pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
        totp_msg = ""
        if entry.get('totp'):
            totp_msg = f"\nTOTP Code: {manager.get_totp_token(entry['totp'])}"
            
        messagebox.showinfo(f"Details for {title}", f"User: {entry.get('user')}\nPass: {pwd}{totp_msg}")
        
    def add_password(self):
        # Simple custom dialog
        add_win = tk.Toplevel(self.root)
        add_win.title("Add Service")
        
        tk.Label(add_win, text="Title:").grid(row=0, column=0)
        title_entry = tk.Entry(add_win)
        title_entry.grid(row=0, column=1)
        
        tk.Label(add_win, text="User:").grid(row=1, column=0)
        user_entry = tk.Entry(add_win)
        user_entry.grid(row=1, column=1)
        
        tk.Label(add_win, text="Password:").grid(row=2, column=0)
        pass_entry = tk.Entry(add_win, show="*")
        pass_entry.grid(row=2, column=1)
        
        def save():
            t = title_entry.get()
            u = user_entry.get()
            p = pass_entry.get()
            
            if t and p:
                honeywords = manager.generate_honeywords(p, 5)
                real_index = 0
                passwords = honeywords[:]
                passwords.insert(0, p)
                
                self.vault_data[t] = {
                    "user": u,
                    "passwords": passwords,
                    "real_index": real_index,
                    "scrambled_pass": manager.ScrambledString(p)
                }
                manager.save_vault(self.enc_key, self.mac_key, self.vault_data)
                self.refresh_list()
                add_win.destroy()
                
        tk.Button(add_win, text="Save", command=save).grid(row=3, column=1)

    def check_health(self):
        leaks = 0
        for title, entry in self.vault_data.items():
            pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
            count = manager.check_pwned(pwd)
            if count > 0:
                leaks += 1
                messagebox.showwarning("DANGER", f"Password for {title} leaked {count} times!")
        if leaks == 0:
            messagebox.showinfo("Health", "All passwords are safe!")

if __name__ == "__main__":
    root = tk.Tk()
    app = VaultPythonGUI(root)
    root.mainloop()
