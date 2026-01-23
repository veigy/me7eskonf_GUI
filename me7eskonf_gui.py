import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk
import re
import os
import sys

# Tato funkce umožní programu najít ikonu uvnitř zabaleného EXE
def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class EskonfTool(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ME7.5 ESKONF Editor v1.0")
        self.geometry("1300x950")

        # Načtení ikony z vnitřních zdrojů
        icon_path = resource_path("icon.ico")
        if os.path.exists(icon_path):
            try:
                self.after(200, lambda: self.iconbitmap(icon_path))
            except:
                pass
            
        self.raw_data = None
        self.found_results = []

        # Component mapping for presets
        self.comp_map = {
            "LSHHK": 12, "EFLA": 13, "LDR": 14, "TEV": 15,
            "BKV": 16, "AAV": 18, "MIL": 19, "EKP": 22,
            "SLP": 23, "ULT": 24, "UAGR": 25, "SLV": 26, "NWS": 27
        }

        self.comp_names = [
            "Ignition coil 4 (ZUE4)", "Ignition coil 3 (ZUE3)", "Ignition coil 2 (ZUE2)", "Ignition coil 1 (ZUE1)",
            "Not configured (NC)", "Not configured (NC)", "Not configured (NC)", "Not configured (NC)",
            "Fuel injector 4 (EV4)", "Fuel injector 3 (EV3)", "Fuel injector 2 (EV2)", "Fuel injector 1 (EV1)",
            "Rear O2 heater (LSHHK)", "Error lamp (EFLA)", "N75 Boost (LDR)", "N80 Evap (TEV)",
            "Brake booster (BKV)", "Not configured (NC)", "Shut off valve (AAV)", "OBD lamp (MIL)",
            "Not configured (NC)", "Not configured (NC)", "Fuel pump relay (EKP)", "SAI pump relay (SLP)",
            "N249 Diverter (ULT)", "EGR valve (UAGR)", "SAI solenoid (SLV)", "VVT N205 (NWS)"
        ]

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)
        
        # --- Sidebar ---
        self.sidebar = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        
        ctk.CTkLabel(self.sidebar, text="File Input", font=("Arial", 14, "bold")).pack(pady=(20, 5))
        self.btn_open = ctk.CTkButton(self.sidebar, text="Load BIN File", command=self.open_file)
        self.btn_open.pack(padx=20, pady=10)

        # Extended Search Option (Default OFF)
        self.ext_search_var = ctk.BooleanVar(value=False)
        self.check_ext = ctk.CTkCheckBox(self.sidebar, text="Extended Search (FF FF 00)", 
                                         variable=self.ext_search_var, font=("Arial", 11))
        self.check_ext.pack(padx=20, pady=5)
        
        ctk.CTkLabel(self.sidebar, text="Manual Entry (HEX)", font=("Arial", 14, "bold")).pack(pady=(30, 5))
        self.manual_hex_entry = ctk.CTkEntry(self.sidebar, placeholder_text="AA FF 00 ...")
        self.manual_hex_entry.pack(padx=20, pady=5, fill="x")
        
        self.btn_manual = ctk.CTkButton(self.sidebar, text="Process HEX", fg_color="transparent", border_width=1, command=self.process_manual_hex)
        self.btn_manual.pack(padx=20, pady=10)

        ctk.CTkFrame(self.sidebar, height=2, fg_color="#444444").pack(fill="x", padx=20, pady=20)
        
        self.btn_save = ctk.CTkButton(self.sidebar, text="Save Modified BIN", fg_color="#c0392b", hover_color="#a93226", 
                                     command=self.save_bin, state="disabled")
        self.btn_save.pack(padx=20, pady=10)

        self.checksum_warning = ctk.CTkLabel(self.sidebar, text="", text_color="#e74c3c", font=("Arial", 11, "bold"), wraplength=200)
        self.checksum_warning.pack(pady=10)

        # --- About Section ---
        self.about_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.about_frame.pack(side="bottom", pady=20)
        ctk.CTkLabel(self.about_frame, text="Powered by Gemini AI (Google)", font=("Arial", 10), text_color="#5dade2").pack()
        ctk.CTkLabel(self.about_frame, text="Created by Aleš Veigend", font=("Arial", 11, "bold")).pack()
        ctk.CTkLabel(self.about_frame, text="AlesVeigend@hotmail.cz", font=("Arial", 10)).pack()
        ctk.CTkLabel(self.about_frame, text="Version 1.0 | 2026", font=("Arial", 10), text_color="gray").pack()

        # --- Main Area ---
        self.scroll_frame = ctk.CTkScrollableFrame(self, label_text="ESKONF Configuration Editor")
        self.scroll_frame.grid(row=0, column=1, padx=20, pady=20, sticky="nsew")

        self.tables = []
        for i in range(2):
            self.tables.append(self.create_table_slot(i))
            self.tables[i]["frame"].pack_forget()

    def create_table_slot(self, idx):
        addr_frame = ctk.CTkFrame(self.scroll_frame, border_width=2, border_color="#333333")
        title_lbl = ctk.CTkLabel(addr_frame, text="", font=("Arial", 18, "bold"))
        title_lbl.pack(pady=(10, 5))

        top_ctrl = ctk.CTkFrame(addr_frame, fg_color="transparent")
        top_ctrl.pack(fill="x", padx=20)

        hex_frame = ctk.CTkFrame(top_ctrl, fg_color="#1a1a1a", corner_radius=10)
        hex_frame.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)
        orig_hex_lbl = ctk.CTkLabel(hex_frame, text="", font=("Courier", 14), text_color="gray")
        orig_hex_lbl.pack(anchor="w", padx=15, pady=(5,0))
        mod_hex_lbl = ctk.CTkLabel(hex_frame, text="", font=("Courier", 15, "bold"), text_color="#5dade2")
        mod_hex_lbl.pack(anchor="w", padx=15, pady=(0,5))
        btn_copy = ctk.CTkButton(hex_frame, text="Copy HEX", width=100, height=24, font=("Arial", 11, "bold"))
        btn_copy.pack(pady=5)

        preset_frame = ctk.CTkFrame(top_ctrl, fg_color="#2c3e50", corner_radius=10)
        preset_frame.pack(side="right", fill="both", pady=10)
        ctk.CTkLabel(preset_frame, text="Quick OFF Presets", font=("Arial", 11, "bold")).grid(row=0, column=0, columnspan=3, pady=5)
        
        p_btns = [
            ("KAT", ["LSHHK"]), ("N249", ["ULT"]), ("SAI", ["SLV", "SLP"]),
            ("EVAP", ["TEV"]), ("VVT", ["NWS"])
        ]
        
        for i, (text, comps) in enumerate(p_btns):
            btn = ctk.CTkButton(preset_frame, text=text, width=75, height=24, font=("Arial", 10), 
                               fg_color="#34495e", command=lambda c=comps, s=idx: self.apply_preset(s, c))
            btn.grid(row=(i//3)+1, column=i%3, padx=4, pady=2)

        combos, byte_labels = [], []
        for b_idx in range(7):
            row = ctk.CTkFrame(addr_frame, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=2)
            b_lbl = ctk.CTkLabel(row, text="", width=95, font=("Courier", 13, "bold"), anchor="w")
            b_lbl.grid(row=0, column=0, padx=5); byte_labels.append(b_lbl)
            for p_idx in range(4):
                combo = ctk.CTkOptionMenu(row, values=["Y (00)", "? (01)", "S (10)", "N (11)"], 
                                         width=130, height=30, text_color="black", font=("Arial", 13, "bold"))
                combo.grid(row=0, column=p_idx+1, padx=4, pady=2); combos.append(combo)
                ctk.CTkLabel(row, text=self.comp_names[b_idx*4+p_idx], font=("Arial", 10), text_color="white").grid(row=1, column=p_idx+1, pady=(0,2))

        return {"frame": addr_frame, "title": title_lbl, "orig_hex": orig_hex_lbl, "mod_hex": mod_hex_lbl, 
                "btn_copy": btn_copy, "combos": combos, "byte_labels": byte_labels}

    def parse_eskonf_strict(self, data):
        res = []
        patterns = [b'\xAA\xFF\x00']
        if self.ext_search_var.get():
            patterns.append(b'\xFF\xFF\x00')

        for pat in patterns:
            start = 0
            while True:
                pos = data.find(pat, start)
                if pos == -1: break
                
                b = data[pos:pos+7]
                if len(b) == 7 and all(x != 0 for x in b[3:7]):
                    p = []
                    for byte in b:
                        p.extend([(byte >> 6) & 0x03, (byte >> 4) & 0x03, 
                                 (byte >> 2) & 0x03, byte & 0x03])
                    
                    # Original logic check: no '01' values in critical section
                    if not any(any(x == 1 for x in p[i:i+4]) for i in range(12, 28, 4)):
                        res.append({"addr": pos, "bytes": list(b), "bits": p})
                start = pos + 1
        return sorted(res, key=lambda x: x['addr'])

    def apply_preset(self, slot_idx, components):
        slot = self.tables[slot_idx]
        for comp in components:
            idx = self.comp_map.get(comp)
            if idx is not None: slot["combos"][idx].set("N (11)")
        self.refresh_hex(slot_idx)

    def fill_table(self, slot_idx, item):
        slot = self.tables[slot_idx]
        slot["frame"].pack(fill="x", padx=10, pady=20)
        slot["title"].configure(text="Manual Input" if item.get("is_manual") else f"ESKONF Address: 0x{item['addr']:08X}")
        slot["orig_hex"].configure(text=f"Original HEX: {' '.join([f'{x:02X}' for x in item['bytes']])}")
        slot["btn_copy"].configure(command=lambda: self.copy_to_clipboard(slot["mod_hex"], slot["btn_copy"]))
        for i, val in enumerate(item['bits']):
            slot["combos"][i].set(["Y (00)", "? (01)", "S (10)", "N (11)"][val])
            slot["combos"][i].configure(command=lambda v, s=slot_idx: self.refresh_hex(s))
        self.refresh_hex(slot_idx)

    def refresh_hex(self, slot_idx):
        slot = self.tables[slot_idx]
        new_hex = []
        for b_idx in range(7):
            bits = [{"Y (00)": 0, "? (01)": 1, "S (10)": 2, "N (11)": 3}[slot["combos"][b_idx*4+i].get()] for i in range(4)]
            val = (bits[0] << 6) | (bits[1] << 4) | (bits[2] << 2) | bits[3]
            new_hex.append(val); slot["byte_labels"][b_idx].configure(text=f"BYTE {b_idx}: {val:02X}")
        slot["mod_hex"].configure(text=f"Modified HEX: {' '.join([f'{x:02X}' for x in new_hex])}")
        slot["mod_hex"].tab_version = "\t".join([f"{x:02X}" for x in new_hex]); slot["mod_hex"].current_bytes = new_hex
        for c in slot["combos"]: c.configure(button_color=self.get_color(c.get()), fg_color=self.get_color(c.get()))

    def save_bin(self):
        if not self.raw_data: return
        file_path = filedialog.asksaveasfilename(defaultextension=".bin", filetypes=[("Binary files", "*.bin")])
        if file_path:
            new_data = bytearray(self.raw_data)
            # Save top 2 found instances
            for i, item in enumerate(self.found_results[:2]):
                addr = item['addr']
                new_data[addr:addr+7] = bytes(self.tables[i]["mod_hex"].current_bytes)
            with open(file_path, "wb") as f: f.write(new_data)
            self.checksum_warning.configure(text="SAVED! FIX CHECKSUM NOW!")
            messagebox.showwarning("Checksum Warning", "File saved! You MUST correct checksums (e.g., using ME7Sum) before flashing!")

    def open_file(self):
        path = filedialog.askopenfilename(filetypes=[("Binary files", "*.bin")])
        if path:
            with open(path, "rb") as f: self.raw_data = f.read()
            self.found_results = self.parse_eskonf_strict(self.raw_data)
            for s in self.tables: s["frame"].pack_forget()
            for i, item in enumerate(self.found_results[:2]): self.fill_table(i, item)
            self.btn_save.configure(state="normal" if self.found_results else "disabled")
            self.checksum_warning.configure(text="")

    def process_manual_hex(self):
        raw = re.sub(r'[\s\t]+', '', self.manual_hex_entry.get().strip())
        if len(raw) == 14:
            b_data = [int(raw[i:i+2], 16) for i in range(0, 14, 2)]
            p = []
            for b in b_data: p.extend([(b >> 6) & 0x03, (b >> 4) & 0x03, (b >> 2) & 0x03, b & 0x03])
            for s in self.tables: s["frame"].pack_forget()
            self.fill_table(0, {"bytes": b_data, "bits": p, "is_manual": True})
            self.btn_save.configure(state="disabled")

    def copy_to_clipboard(self, lbl, btn):
        self.clipboard_clear(); self.clipboard_append(lbl.tab_version)
        btn.configure(text="Copied! ✓", fg_color="#27ae60")
        self.after(1000, lambda: btn.configure(text="Copy HEX", fg_color=ctk.ThemeManager.theme["CTkButton"]["fg_color"]))

    def get_color(self, v):
        return {"00": "#2ecc71", "11": "#e74c3c", "10": "#f1c40f"}.get(v[3:5], "#95a5a6")

if __name__ == "__main__":
    EskonfTool().mainloop()
