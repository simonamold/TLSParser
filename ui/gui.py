from scapy.all import sniff, TCP, wrpcap, get_if_list
import tkinter as tk
from tkinter import filedialog, ttk
import logging
import threading
from tkinter import messagebox

from parser.tls_record import TLSRecord
from tools.extract_tls_from_file import extract_tls_packet_from_file

logger = logging.getLogger(__name__)


class TLSParserApp:
    def __init__(self, root):
        self.root = root
        self.root.title("TLS Parser")
        self.root.geometry("800x600")

        self.setup_ui()
        self.packets = []

        self.stop_flag = False
        self.capture_thread = None
        self.raw_capture_packets = []
        self.captured_packets = []

        self.packet_count = -1

    def setup_ui(self):
        self.root.grid_rowconfigure(1, weight=1)  
        self.root.grid_rowconfigure(2, weight=2)  
        self.root.grid_columnconfigure(0, weight=1)

        self.btn_frame = tk.Frame(self.root)
        self.btn_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.btn_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.interface_label = tk.Label(self.btn_frame, text="Interfață:")

        self.interface_label.pack(side="left", padx=(0, 5))

        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(self.btn_frame, textvariable=self.interface_var, width=20)
        self.interface_combo['values'] = get_if_list()
        self.interface_combo.current(0)  # selectează prima interfață ca implicit
        self.interface_combo.pack(side="left", padx=(0, 15))

        self.start_btn = tk.Button(self.btn_frame, text="Start", command=self.start_capture)
        self.stop_btn = tk.Button(self.btn_frame, text="Stop", command=self.stop_capture)
        self.save_btn = tk.Button(self.btn_frame, text="Save", command=self.save_capture)
        self.open_file_btn = tk.Button(self.btn_frame, text="Open file", command=self.load_file)
        self.start_btn.pack(side="left", padx=5)
        self.stop_btn.pack(side="left", padx=5)
        self.save_btn.pack(side="left", padx=5)
        self.open_file_btn.pack(side="left", padx=5)
 
        self.tree_frame = ttk.Frame(self.root, padding=10)
        self.tree_frame.grid(row=1, column=0, sticky="nsew")
        self.tree_frame.grid_rowconfigure(0, weight=1)
        self.tree_frame.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(self.tree_frame, 
                                 columns=("id", "type", "version", "length"), 
                                 show="headings",
                                 height=15)
        self.tree.heading("id", text="Id")
        self.tree.heading("type", text="Type")
        self.tree.heading("length", text="Length")
        self.tree.heading("version", text="Version")
        self.tree.bind("<<TreeviewSelect>>", self.on_packet_select)
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.tree_scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=self.tree_scrollbar.set)
        self.tree_scrollbar.grid(row=0, column=1, sticky="ns")

        self.details_frame = tk.Frame(self.root)
        self.details_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=5)
        self.details_frame.grid_rowconfigure(0, weight=1)
        self.details_frame.grid_columnconfigure(0, weight=1)

        self.details = tk.Text(self.details_frame, height=10)
        self.details.grid(row=0, column=0, sticky="nsew")

        self.details_scrollbar = ttk.Scrollbar(self.details_frame, orient="vertical", command=self.details.yview)
        self.details.configure(yscrollcommand=self.details_scrollbar.set)
        self.details_scrollbar.grid(row=0, column=1, sticky="ns")

    def start_capture(self):
        self.stop_flag = False
        self.start_btn.config(state='disabled')
        self.interface_combo.config(state='disabled')
        self.capture_thread = threading.Thread(target=self.sniff_packets, daemon=True)

        self.capture_thread.start()

    def stop_capture(self):
        self.stop_flag = True
        self.start_btn.config(state='normal')
        self.interface_combo.config(state='normal')

    def sniff_packets(self):
        sniff(filter="tcp port 443",
              prn=self.packet_callback,
              stop_filter=self.stop_filter,
              iface=self.interface_var.get(),
              store=False)
        
    def packet_callback(self, pkt):
        if self.stop_flag: return True
        if pkt.haslayer(TCP) and pkt[TCP].dport == 443 and pkt[TCP].payload:
            raw_data = bytes(pkt[TCP].payload)
            self.raw_capture_packets.append(pkt)
            self.captured_packets.append(raw_data)

            self.packet_count += 1
            pkt_id = self.packet_count

            try:
                parsed = TLSRecord(raw_data)
                parsed.parse()  
                content_type = parsed.content_type.name if hasattr(parsed.content_type, "name") else parsed.content_type
                version = parsed.version.name if hasattr(parsed.version, "name") else parsed.version
                self.root.after(0, lambda: self.tree.insert(
                    "", "end", 
                    iid=pkt_id, 
                    values=(pkt_id, content_type, version, parsed.length)))
                self.packets.append(parsed)
            except Exception as e:
                logger.error(f"Failed to parse packet {pkt_id}", exc_info=True)
                self.packets.append(None)
                self.tree.insert("", "end", id=pkt_id, values=("Invalid", len(raw_data)))

    def stop_filter(self, pkt):
        return self.stop_flag
    

    def load_file(self):
        path = filedialog.askopenfilename(filetypes=[("All files", "*.*")])
        if not path:
            return
       
        self.load_file_thread = threading.Thread(target=self._process_file, args=(path,), daemon=True)
        self.load_file_thread.start()

    def _process_file(self, path):
        self.tree.delete(*self.tree.get_children())
        self.details.delete("1.0", tk.END)
        self.packets.clear()

        try:
            raw_payloads = extract_tls_packet_from_file(path)

            print(f"Lungime raw_payloads =  {len(raw_payloads)}")
            for i, raw_data in enumerate(raw_payloads):
                try:
                    parsed = TLSRecord(raw_data)
                    parsed.parse()
                    self.packets.append(parsed)
                    content_type = parsed.content_type.name if hasattr(parsed.content_type, "name") else parsed.content_type
                    version = parsed.version.name if hasattr(parsed.version, "name") else parsed.version
                    self.tree.insert("","end", iid=i, value=(i, content_type, version, parsed.length))
                except Exception as e:
                    logger.error(f"Failed to parse packet {i}", exc_info=True)
                    self.packets.append(None)
                    self.root.after(0, lambda: 
                                    self.tree.insert("", "end", iid=i, values=("Invalid", len(raw_data))))
            if not raw_payloads:
                    self._safe_show_info("No TLS packets", "No TLS payloads were found in the selected file.")

        except Exception as e:
            logging.error("Error processing PCAP file", exc_info=True)
            self._safe_show_error("Error", "Failed to load the PCAP file.")

    def _safe_show_info(self, title, message):
        self.root.after(0, lambda: messagebox.showinfo(title, message))

    def _safe_show_error(self, title, message):
        self.root.after(0, lambda: messagebox.showerror(title, message))  

            
    def on_packet_select(self, event):
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        pkt = self.packets[index]
        self.details.delete("1.0", tk.END)
        self.details.insert("1.0", str(pkt))  

    def save_capture(self):
        if not self.captured_packets:
            messagebox.showinfo("No Data", "No TLS Payloads to save")
            return
        file_path = filedialog.asksaveasfilename(
            defaultextension=".pcap",
            filetypes=[("All files", "*.*")]
        )

        if file_path and self.captured_packets:
            try:
                # with open(file_path, "wb") as f:
                #     for payload in self.captured_packets:
                #         f.write(payload)
                wrpcap(file_path, self.raw_capture_packets)
                messagebox.showinfo("Saved", 
                                    f"Saved {len(self.raw_capture_packets)} packets")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file:\n{e}")

def run_gui():
    root = tk.Tk()
    app = TLSParserApp(root)
    root.mainloop()