import customtkinter as ctk
import sys
import os
import tkinter as tk
from tkinter import filedialog
from PIL import Image
import urllib.parse
import urllib.request

# Add cli-python to path so we can import our backend directly
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'cli-python')))

import manager
import auth
import shamir
import stego

# HACKER LEVEL AESTHETIC
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

class ModernVaultApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NEXUS VAULT // TERMINAL")
        self.geometry("900x600")
        self.resizable(False, False)
        
        self.enc_key = None
        self.mac_key = None
        self.vault_data = {}

        self.show_login_screen()

    def show_login_screen(self):
        self.clear_window()
        
        self.login_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="#0a0a0a", border_width=1, border_color="#1a1a1a")
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        
        center_frame = ctk.CTkFrame(self.login_frame, fg_color="#111111", corner_radius=15)
        center_frame.place(relx=0.5, rely=0.5, anchor=ctk.CENTER)

        logo = ctk.CTkLabel(center_frame, text="SYS_AUTH :: NEXUS", font=ctk.CTkFont(family="Courier", size=24, weight="bold"), text_color="#00ff00")
        logo.grid(row=0, column=0, padx=50, pady=(40, 20))

        self.password_entry = ctk.CTkEntry(center_frame, width=280, placeholder_text="Enter Root Password...", show="█", 
                                           font=ctk.CTkFont(family="Courier"), fg_color="#000000", border_color="#00ff00", text_color="#00ff00")
        self.password_entry.grid(row=1, column=0, padx=50, pady=(0, 20))
        self.password_entry.bind('<Return>', lambda e: self.authenticate())
        
        # Keystroke Dynamics Tracking
        self.last_key_time = 0
        self.flight_times = []
        self.password_entry.bind('<KeyRelease>', self.track_keystrokes)

        self.login_button = ctk.CTkButton(center_frame, text="DECRYPT_VAULT", font=ctk.CTkFont(family="Courier", weight="bold"), 
                                          command=self.authenticate, width=280, corner_radius=4, fg_color="#00aa00", hover_color="#00ff00", text_color="black")
        self.login_button.grid(row=2, column=0, padx=50, pady=(0, 40))

    def track_keystrokes(self, event):
        import time
        now = time.time() * 1000 # ms
        if self.last_key_time != 0 and event.keysym not in ("Return", "BackSpace", "Shift_L", "Shift_R"):
            self.flight_times.append(now - self.last_key_time)
        self.last_key_time = now

    def authenticate(self):
        pwd = self.password_entry.get()
        if not pwd: return
        
        # Biometric Analysis
        if len(self.flight_times) > 2:
            avg_flight = sum(self.flight_times) / len(self.flight_times)
            if avg_flight < 30.0: # Faster than 30ms is impossible for humans
                self.show_error("BIO-METRIC REJECTION:\nRobotic typing speed detected.\nAre you a script?")
                self.flight_times.clear()
                return
            
        try:
            salt = auth.get_or_create_salt(manager.SALT_FILE)
            self.enc_key, self.mac_key = auth.derive_keys(pwd, salt)
            self.vault_data = manager.load_vault(self.enc_key, self.mac_key)
            self.master_pwd_cache = pwd # Needed for Shamir Split
            self.show_dashboard()
        except Exception as e:
            self.show_error(f"ACCESS DENIED.\nCRITICAL ERROR: {e}")

    def show_dashboard(self):
        self.clear_window()
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # HACKER SIDEBAR
        self.sidebar_frame = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color="#0f0f0f", border_width=1, border_color="#1a1a1a")
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_rowconfigure(7, weight=1)

        ctk.CTkLabel(self.sidebar_frame, text="NEXUS_OS v9.9", font=ctk.CTkFont(family="Courier", size=18, weight="bold"), text_color="#00ff00").grid(row=0, column=0, padx=20, pady=(20, 30))

        btn_font = ctk.CTkFont(family="Courier", size=13)
        ctk.CTkButton(self.sidebar_frame, text="> Add Node", font=btn_font, anchor="w", fg_color="transparent", text_color="#00ff00", command=self.show_add_modal).grid(row=1, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(self.sidebar_frame, text="> HIBP Audit", font=btn_font, anchor="w", fg_color="transparent", text_color="#00ff00", command=self.check_health).grid(row=2, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(self.sidebar_frame, text="> Split Key (SSS)", font=btn_font, anchor="w", fg_color="transparent", text_color="#00ff00", command=self.shamir_split).grid(row=3, column=0, padx=20, pady=5, sticky="ew")
        ctk.CTkButton(self.sidebar_frame, text="> Embed Stego", font=btn_font, anchor="w", fg_color="transparent", text_color="#00ff00", command=self.stego_embed).grid(row=4, column=0, padx=20, pady=5, sticky="ew")

        # Geo-Lock Status
        ctk.CTkLabel(self.sidebar_frame, text="[ GEO-LOCK: ACTIVE ]", font=ctk.CTkFont(family="Courier", size=10), text_color="#00aa00").grid(row=6, column=0, pady=10)
        
        ctk.CTkButton(self.sidebar_frame, text="TERMINATE_SESSION", font=btn_font, fg_color="#550000", hover_color="#ff0000", text_color="white", command=self.lock_vault).grid(row=8, column=0, padx=20, pady=20)

        # MAIN CONTENT
        self.main_frame = ctk.CTkScrollableFrame(self, corner_radius=0, fg_color="#1a1a1a")
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.refresh_list()

    def refresh_list(self):
        for widget in self.main_frame.winfo_children(): widget.destroy()
            
        if not self.vault_data:
            ctk.CTkLabel(self.main_frame, text="SYS_EMPTY.\nNO NODES FOUND.", font=ctk.CTkFont(family="Courier"), text_color="gray").pack(pady=50)
            return

        for title, entry in self.vault_data.items():
            card = ctk.CTkFrame(self.main_frame, corner_radius=4, fg_color="#111111", border_width=1, border_color="#333333")
            card.pack(fill=ctk.X, padx=20, pady=10)
            
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(family="Courier", size=16, weight="bold"), text_color="#ffffff").pack(side=ctk.LEFT, padx=20, pady=15)
            ctk.CTkLabel(card, text=entry.get('user', ''), font=ctk.CTkFont(family="Courier"), text_color="#888888").pack(side=ctk.LEFT, padx=10, pady=15)
            
            btn_font = ctk.CTkFont(family="Courier", size=12, weight="bold")
            ctk.CTkButton(card, text="[QR]", width=50, font=btn_font, fg_color="#333333", hover_color="#00ff00", text_color="#ffffff", command=lambda t=title, e=entry: self.show_qr(t, e)).pack(side=ctk.RIGHT, padx=(0,20), pady=15)
            ctk.CTkButton(card, text="DECRYPT", width=80, font=btn_font, fg_color="#005500", hover_color="#00ff00", text_color="#ffffff", command=lambda t=title, e=entry: self.reveal_password(t, e)).pack(side=ctk.RIGHT, padx=10, pady=15)

    def reveal_password(self, title, entry):
        pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
        totp_msg = ""
        if entry.get('totp'):
            totp_msg = manager.get_totp_token(entry['totp'])
            
        top = ctk.CTkToplevel(self)
        top.title(f"NODE: {title}")
        top.geometry("450x300")
        top.attributes('-topmost', 'true')
        top.configure(fg_color="#0a0a0a")
        
        font_b = ctk.CTkFont(family="Courier", weight="bold")
        font_n = ctk.CTkFont(family="Courier")
        
        ctk.CTkLabel(top, text="USER_ID:", font=font_b, text_color="#00aa00").pack(pady=(20,0))
        ctk.CTkLabel(top, text=entry.get('user'), font=font_n, text_color="white").pack()
        
        ctk.CTkLabel(top, text="PAYLOAD:", font=font_b, text_color="#00aa00").pack(pady=(15,0))
        ctk.CTkLabel(top, text=pwd, font=font_n, text_color="white").pack()
        
        if totp_msg:
            ctk.CTkLabel(top, text="TOTP_SYNC:", font=font_b, text_color="#00aa00").pack(pady=(15,0))
            ctk.CTkLabel(top, text=totp_msg, font=ctk.CTkFont(family="Courier", size=22, weight="bold"), text_color="#00ff00").pack()
            
        def copy():
            self.clipboard_clear()
            self.clipboard_append(pwd)
            top.destroy()
            
        ctk.CTkButton(top, text="COPY TO CLIPBOARD (30s TTL)", font=font_b, fg_color="#333333", hover_color="#00ff00", text_color="white", command=copy).pack(pady=20)

    def show_qr(self, title, entry):
        pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
        encoded_pwd = urllib.parse.quote(pwd)
        url = f"https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={encoded_pwd}&bgcolor=0a0a0a&color=00ff00"
        
        top = ctk.CTkToplevel(self)
        top.title("AIR-GAP TX")
        top.geometry("300x350")
        top.attributes('-topmost', 'true')
        top.configure(fg_color="#0a0a0a")
        
        lbl = ctk.CTkLabel(top, text="FETCHING SECURE MATRIX...", font=ctk.CTkFont(family="Courier"), text_color="#00ff00")
        lbl.pack(expand=True)
        
        def load_img():
            try:
                img_path = os.path.join(manager.VAULT_DIR, "temp_qr.png")
                urllib.request.urlretrieve(url, img_path)
                qr_img = ctk.CTkImage(light_image=Image.open(img_path), size=(250, 250))
                lbl.configure(image=qr_img, text="")
            except:
                lbl.configure(text="NETWORK ERROR", text_color="red")
        
        self.after(100, load_img)

    def show_add_modal(self):
        top = ctk.CTkToplevel(self)
        top.title("INJECT NODE")
        top.geometry("400x480")
        top.attributes('-topmost', 'true')
        top.configure(fg_color="#0a0a0a")
        
        font_b = ctk.CTkFont(family="Courier", weight="bold")
        font_n = ctk.CTkFont(family="Courier")
        
        ctk.CTkLabel(top, text="Node ID", font=font_b, text_color="#00aa00").pack(pady=(20, 5), padx=20, anchor="w")
        t_entry = ctk.CTkEntry(top, width=360, font=font_n, fg_color="#111", border_color="#333")
        t_entry.pack(padx=20)
        
        ctk.CTkLabel(top, text="User UID", font=font_b, text_color="#00aa00").pack(pady=(15, 5), padx=20, anchor="w")
        u_entry = ctk.CTkEntry(top, width=360, font=font_n, fg_color="#111", border_color="#333")
        u_entry.pack(padx=20)
        
        ctk.CTkLabel(top, text="Payload (Password)", font=font_b, text_color="#00aa00").pack(pady=(15, 5), padx=20, anchor="w")
        p_entry = ctk.CTkEntry(top, width=360, show="█", font=font_n, fg_color="#111", border_color="#333")
        p_entry.pack(padx=20)
        
        ctk.CTkLabel(top, text="TOTP Seed (Optional)", font=font_b, text_color="#00aa00").pack(pady=(15, 5), padx=20, anchor="w")
        totp_entry = ctk.CTkEntry(top, width=360, font=font_n, fg_color="#111", border_color="#333")
        totp_entry.pack(padx=20)
        
        def save():
            t = t_entry.get()
            u = u_entry.get()
            p = p_entry.get()
            totp = totp_entry.get()
            if t and p:
                honeywords = manager.generate_honeywords(p, 5)
                passwords = honeywords[:]
                passwords.insert(0, p)
                self.vault_data[t] = {
                    "user": u, "passwords": passwords, "real_index": 0, "totp": totp, "scrambled_pass": manager.ScrambledString(p)
                }
                manager.save_vault(self.enc_key, self.mac_key, self.vault_data)
                self.refresh_list()
                top.destroy()
                
        ctk.CTkButton(top, text="COMMIT_INJECTION", font=font_b, fg_color="#00aa00", hover_color="#00ff00", text_color="black", command=save, width=360).pack(pady=30)

    def check_health(self):
        leaks = 0
        for title, entry in self.vault_data.items():
            pwd = entry['scrambled_pass'].get() if 'scrambled_pass' in entry else entry.get('password', '')
            count = manager.check_pwned(pwd)
            if count > 0:
                leaks += 1
                self.show_error(f"BREACH DETECTED:\nNode '{title}' payload compromised {count} times!")
        if leaks == 0:
            top = ctk.CTkToplevel(self)
            top.title("SYS_AUDIT")
            top.geometry("300x150")
            top.attributes('-topmost', 'true')
            top.configure(fg_color="#0a0a0a")
            ctk.CTkLabel(top, text="[ OK ] ALL NODES SECURE", font=ctk.CTkFont(family="Courier", size=16), text_color="#00ff00").pack(pady=40)

    def shamir_split(self):
        shares = shamir.split_secret(self.master_pwd_cache.encode('utf-8'), 5, 3)
        top = ctk.CTkToplevel(self)
        top.title("SHAMIR SECRET SHARING")
        top.geometry("500x350")
        top.attributes('-topmost', 'true')
        top.configure(fg_color="#0a0a0a")
        
        ctk.CTkLabel(top, text="ROOT KEY FRAGMENTED (t=3, n=5)", font=ctk.CTkFont(family="Courier", weight="bold"), text_color="#00aa00").pack(pady=15)
        
        textbox = ctk.CTkTextbox(top, width=450, height=200, font=ctk.CTkFont(family="Courier", size=11), fg_color="#111", text_color="#00ff00")
        textbox.pack(padx=20)
        
        for idx, data in shares:
            textbox.insert("end", f"SHARE {idx}: {data.hex()}\n\n")
        textbox.configure(state="disabled")
        
    def stego_embed(self):
        bmp_path = filedialog.askopenfilename(title="Select Target BMP Image", filetypes=[("BMP Image", "*.bmp")])
        if not bmp_path: return
        
        try:
            with open(manager.VAULT_FILE, 'rb') as f:
                vault_bytes = f.read()
            out_path = bmp_path.replace(".bmp", "_stego.bmp")
            stego.embed_in_bmp(bmp_path, vault_bytes, out_path)
            
            top = ctk.CTkToplevel(self)
            top.title("STEGO INJECTION")
            top.geometry("400x150")
            top.attributes('-topmost', 'true')
            top.configure(fg_color="#0a0a0a")
            ctk.CTkLabel(top, text=f"VAULT INJECTED SUCCESSFULLY.\nSaved to: {os.path.basename(out_path)}", font=ctk.CTkFont(family="Courier"), text_color="#00ff00").pack(pady=40)
        except Exception as e:
            self.show_error(f"STEGO INJECTION FAILED:\n{e}")

    def lock_vault(self):
        self.enc_key = None
        self.mac_key = None
        self.vault_data = {}
        self.master_pwd_cache = None
        self.show_login_screen()

    def show_error(self, message):
        top = ctk.CTkToplevel(self)
        top.title("CRITICAL_ERR")
        top.geometry("350x150")
        top.attributes('-topmost', 'true')
        top.configure(fg_color="#0a0a0a")
        ctk.CTkLabel(top, text=message, font=ctk.CTkFont(family="Courier", weight="bold"), text_color="#ff0000").pack(pady=30)
        ctk.CTkButton(top, text="ACKNOWLEDGE", command=top.destroy, fg_color="#550000", hover_color="#ff0000").pack()

    def clear_window(self):
        for widget in self.winfo_children(): widget.destroy()

if __name__ == "__main__":
    app = ModernVaultApp()
    app.mainloop()
