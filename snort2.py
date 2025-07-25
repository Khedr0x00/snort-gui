import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import threading
import os
import sys

class SnortApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Snort GUI Tool")
        self.root.geometry("900x700")
        self.root.resizable(True, True)

        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TNotebook.Tab', font=('Inter', 10, 'bold'), padding=[10, 5])
        self.style.configure('TButton', font=('Inter', 10), padding=6, borderwidth=2, relief="raised")
        self.style.map('TButton',
                       foreground=[('pressed', 'red'), ('active', 'blue')],
                       background=[('pressed', '!focus', 'gray'), ('active', 'lightgray')])
        self.style.configure('TLabel', font=('Inter', 10))
        self.style.configure('TEntry', font=('Inter', 10))
        self.style.configure('TCheckbutton', font=('Inter', 10))
        self.style.configure('TText', font=('Inter', 10))
        self.style.configure('TLabelframe.Label', font=('Inter', 11, 'bold'))

        # Snort process handler
        self.snort_process = None
        self.output_thread = None
        self.stop_output_thread = threading.Event()

        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)

        # Create frames for each tab
        self.config_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.run_snort_frame = ttk.Frame(self.notebook, padding="10 10 10 10")
        self.log_viewer_frame = ttk.Frame(self.notebook, padding="10 10 10 10")

        # Add frames to the notebook
        self.notebook.add(self.config_frame, text="Configuration")
        self.notebook.add(self.run_snort_frame, text="Run Snort")
        self.notebook.add(self.log_viewer_frame, text="Log Viewer")

        # Initialize UI for each tab
        self._setup_config_tab()
        self._setup_run_snort_tab()
        self._setup_log_viewer_tab()

        # Handle window closing
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)

    def _create_section_label(self, parent, text):
        """Helper to create a section label."""
        label = ttk.Label(parent, text=text, font=('Inter', 12, 'bold'), anchor='w')
        label.pack(pady=(10, 5), fill='x')
        return label

    def _create_input_row_with_browse(self, parent, label_text, default_value="", browse_command=None):
        """Helper to create a label, entry, and an optional browse button."""
        frame = ttk.Frame(parent)
        frame.pack(fill='x', pady=2)
        label = ttk.Label(frame, text=label_text, width=25)
        label.pack(side='left', padx=(0, 5))
        entry = ttk.Entry(frame)
        entry.insert(0, default_value)
        entry.pack(side='left', fill='x', expand=True)
        if browse_command:
            browse_button = ttk.Button(frame, text="Browse", command=lambda: browse_command(entry))
            browse_button.pack(side='right', padx=(5, 0))
        return entry

    def _create_command_output_area(self, parent, height=5, label_text="Generated Command"):
        """Helper to create a text area for command output."""
        output_frame = ttk.LabelFrame(parent, text=label_text, padding="5 5 5 5")
        output_frame.pack(fill='both', expand=True, pady=10)
        output_text = tk.Text(output_frame, height=height, wrap='word', state='disabled', background='#f0f0f0', borderwidth=1, relief="solid")
        output_text.pack(fill='both', expand=True)
        return output_text

    def _set_command_output(self, text_widget, command):
        """Helper to update the command output text area."""
        text_widget.config(state='normal')
        text_widget.delete(1.0, tk.END)
        text_widget.insert(tk.END, command)
        text_widget.config(state='disabled')

    def _browse_file(self, entry_widget):
        """Opens a file dialog and sets the selected file path to the entry widget."""
        filepath = filedialog.askopenfilename()
        if filepath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, filepath)

    def _browse_directory(self, entry_widget):
        """Opens a directory dialog and sets the selected directory path to the entry widget."""
        dirpath = filedialog.askdirectory()
        if dirpath:
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, dirpath)

    def _setup_config_tab(self):
        """Sets up the Configuration tab UI."""
        self._create_section_label(self.config_frame, "Snort Paths")

        self.snort_executable_path_entry = self._create_input_row_with_browse(
            self.config_frame, "Snort Executable Path:", "/usr/sbin/snort", self._browse_file
        )
        self.snort_config_path_entry = self._create_input_row_with_browse(
            self.config_frame, "Snort Config File (-c):", "/etc/snort/snort.conf", self._browse_file
        )
        self.snort_rules_path_entry = self._create_input_row_with_browse(
            self.config_frame, "Snort Rules Path (-R):", "/etc/snort/rules", self._browse_directory
        )

        self._create_section_label(self.config_frame, "Network Interface")
        self.snort_interface_entry = ttk.Entry(self.config_frame)
        self.snort_interface_entry.insert(0, "eth0")
        self.snort_interface_entry.pack(fill='x', pady=5)
        ttk.Label(self.config_frame, text="Enter network interface (e.g., eth0, ens33, en0)").pack(anchor='w')

        self._create_section_label(self.config_frame, "Logging Options")
        self.snort_log_dir_entry = self._create_input_row_with_browse(
            self.config_frame, "Log Directory (-l):", "/var/log/snort", self._browse_directory
        )
        self.snort_alert_file_entry = self._create_input_row_with_browse(
            self.config_frame, "Alert File (default: alert):", "", self._browse_file
        )
        ttk.Label(self.config_frame, text="If empty, default 'alert' file will be used in log directory.").pack(anchor='w')

    def _setup_run_snort_tab(self):
        """Sets up the Run Snort tab UI."""
        self._create_section_label(self.run_snort_frame, "Snort Command Generation")

        # Snort Mode Selection
        mode_frame = ttk.LabelFrame(self.run_snort_frame, text="Snort Mode", padding="5 5 5 5")
        mode_frame.pack(fill='x', pady=5)
        self.snort_mode_var = tk.StringVar(value="NIDS") # Default to NIDS
        ttk.Radiobutton(mode_frame, text="Network Intrusion Detection System (NIDS) (-A full -q)", variable=self.snort_mode_var, value="NIDS").pack(anchor='w')
        ttk.Radiobutton(mode_frame, text="Packet Sniffer (console) (-v)", variable=self.snort_mode_var, value="Sniffer").pack(anchor='w')
        ttk.Radiobutton(mode_frame, text="Packet Sniffer (verbose) (-v -d -e)", variable=self.snort_mode_var, value="VerboseSniffer").pack(anchor='w')
        ttk.Radiobutton(mode_frame, text="Custom Command", variable=self.snort_mode_var, value="Custom").pack(anchor='w')

        self.custom_command_entry = ttk.Entry(self.run_snort_frame)
        self.custom_command_entry.pack(fill='x', pady=5)
        ttk.Label(self.run_snort_frame, text="Enter custom Snort arguments (e.g., -r capture.pcap)").pack(anchor='w')

        generate_button = ttk.Button(self.run_snort_frame, text="Generate Snort Command", command=self._generate_snort_command)
        generate_button.pack(pady=10)

        self.snort_command_output = self._create_command_output_area(self.run_snort_frame)

        # Snort Process Control
        self._create_section_label(self.run_snort_frame, "Snort Process Control")
        control_frame = ttk.Frame(self.run_snort_frame)
        control_frame.pack(pady=10)

        self.start_button = ttk.Button(control_frame, text="Start Snort", command=self._start_snort)
        self.start_button.pack(side='left', padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Snort", command=self._stop_snort, state='disabled')
        self.stop_button.pack(side='left', padx=5)

        self.snort_status_label = ttk.Label(self.run_snort_frame, text="Status: Idle", font=('Inter', 10, 'italic'))
        self.snort_status_label.pack(pady=5)

        self.snort_console_output = self._create_command_output_area(self.run_snort_frame, height=15, label_text="Snort Console Output (Live)")

    def _generate_snort_command(self):
        """Generates the Snort command based on current configurations and selected mode."""
        snort_exec = self.snort_executable_path_entry.get().strip()
        snort_config = self.snort_config_path_entry.get().strip()
        snort_rules = self.snort_rules_path_entry.get().strip()
        snort_interface = self.snort_interface_entry.get().strip()
        snort_log_dir = self.snort_log_dir_entry.get().strip()
        snort_alert_file = self.snort_alert_file_entry.get().strip()
        snort_mode = self.snort_mode_var.get()
        custom_args = self.custom_command_entry.get().strip()

        if not snort_exec:
            messagebox.showerror("Input Error", "Snort Executable Path is required.")
            return
        if not os.path.exists(snort_exec):
            messagebox.showerror("File Not Found", f"Snort executable not found at: {snort_exec}")
            return

        command = [snort_exec]

        # Add common arguments
        if snort_config:
            if not os.path.exists(snort_config):
                messagebox.showwarning("File Not Found", f"Snort config file not found at: {snort_config}. Command generated anyway.")
            command.extend(["-c", snort_config])
        if snort_interface:
            command.extend(["-i", snort_interface])
        if snort_rules:
            if not os.path.exists(snort_rules):
                messagebox.showwarning("Directory Not Found", f"Snort rules directory not found at: {snort_rules}. Command generated anyway.")
            command.extend(["-R", snort_rules])
        if snort_log_dir:
            if not os.path.exists(snort_log_dir):
                try:
                    os.makedirs(snort_log_dir)
                except OSError as e:
                    messagebox.showwarning("Directory Creation Error", f"Could not create log directory {snort_log_dir}: {e}. Command generated anyway.")
            command.extend(["-l", snort_log_dir])
        if snort_alert_file:
            command.extend(["-A", f"full -F {snort_alert_file}"]) # Example for specific alert file

        # Add mode-specific arguments
        if snort_mode == "NIDS":
            command.extend(["-A", "full", "-q"]) # Full alerts, quiet mode
        elif snort_mode == "Sniffer":
            command.append("-v") # Verbose
        elif snort_mode == "VerboseSniffer":
            command.extend(["-v", "-d", "-e"]) # Verbose, dump packet data, show link-layer headers
        elif snort_mode == "Custom":
            if custom_args:
                command.extend(custom_args.split()) # Split custom args by space

        self._set_command_output(self.snort_command_output, " ".join(command))
        return command # Return as list for subprocess

    def _start_snort(self):
        """Starts the Snort process."""
        if self.snort_process and self.snort_process.poll() is None:
            messagebox.showinfo("Snort Status", "Snort is already running.")
            return

        command = self._generate_snort_command()
        if not command: # If command generation failed (e.g., input error)
            return

        try:
            # Ensure the output text area is clear and enabled for new output
            self.snort_console_output.config(state='normal')
            self.snort_console_output.delete(1.0, tk.END)
            self.snort_console_output.config(state='disabled')

            # Start Snort as a subprocess
            # Use preexec_fn=os.setsid to create a new session, allowing process to be killed cleanly
            # For Windows, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP might be needed
            if sys.platform == "win32":
                self.snort_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                      text=True, bufsize=1, universal_newlines=True,
                                                      creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
            else:
                self.snort_process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                                      text=True, bufsize=1, universal_newlines=True,
                                                      preexec_fn=os.setsid)

            self.snort_status_label.config(text="Status: Running...")
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')

            # Start a thread to read Snort's output
            self.stop_output_thread.clear()
            self.output_thread = threading.Thread(target=self._read_snort_output)
            self.output_thread.daemon = True # Allow thread to exit with main app
            self.output_thread.start()

            messagebox.showinfo("Snort Control", "Snort started successfully. Check console output tab.")

        except FileNotFoundError:
            messagebox.showerror("Error", f"Snort executable not found at '{command[0]}'. Please check the path in Configuration tab.")
            self.snort_status_label.config(text="Status: Error (Executable not found)")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
        except PermissionError:
            messagebox.showerror("Error", "Permission denied. You might need to run this application with administrator/root privileges.")
            self.snort_status_label.config(text="Status: Error (Permission denied)")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start Snort: {e}")
            self.snort_status_label.config(text="Status: Error")
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')

    def _read_snort_output(self):
        """Reads output from the Snort process and updates the GUI."""
        if not self.snort_process or not self.snort_process.stdout:
            return

        for line in iter(self.snort_process.stdout.readline, ''):
            if self.stop_output_thread.is_set():
                break
            self.root.after(0, self._update_console_output, line) # Update GUI from main thread

        # Ensure the process is fully terminated and cleaned up
        self.snort_process.stdout.close()
        self.snort_process.wait()
        self.root.after(0, self._snort_process_finished)


    def _update_console_output(self, line):
        """Appends a line to the console output text area."""
        self.snort_console_output.config(state='normal')
        self.snort_console_output.insert(tk.END, line)
        self.snort_console_output.see(tk.END) # Auto-scroll to the end
        self.snort_console_output.config(state='disabled')

    def _stop_snort(self):
        """Stops the Snort process."""
        if self.snort_process and self.snort_process.poll() is None:
            try:
                # Set the event to stop the output reading thread
                self.stop_output_thread.set()
                if self.output_thread and self.output_thread.is_alive():
                    self.output_thread.join(timeout=2) # Give thread a moment to finish

                if sys.platform == "win32":
                    subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.snort_process.pid)])
                else:
                    os.killpg(os.getpgid(self.snort_process.pid), subprocess.signal.SIGTERM) # Kill process group

                self.snort_process.wait(timeout=5) # Wait for process to terminate
                messagebox.showinfo("Snort Control", "Snort stopped successfully.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to stop Snort: {e}")
            finally:
                self._snort_process_finished()
        else:
            messagebox.showinfo("Snort Status", "Snort is not running.")

    def _snort_process_finished(self):
        """Updates GUI state when Snort process terminates."""
        self.snort_process = None
        self.snort_status_label.config(text="Status: Stopped")
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.stop_output_thread.clear() # Reset event for next run

    def _setup_log_viewer_tab(self):
        """Sets up the Log Viewer tab UI."""
        self._create_section_label(self.log_viewer_frame, "Snort Alert Log Viewer")

        self.log_file_path_entry = self._create_input_row_with_browse(
            self.log_viewer_frame, "Alert Log File Path:", "/var/log/snort/alert", self._browse_file
        )
        load_log_button = ttk.Button(self.log_viewer_frame, text="Load Log File", command=self._load_log_file)
        load_log_button.pack(pady=10)

        self.log_content_text = self._create_command_output_area(self.log_viewer_frame, height=25, label_text="Log Content")

    def _load_log_file(self):
        """Loads and displays content of the specified log file."""
        log_path = self.log_file_path_entry.get().strip()
        if not log_path:
            messagebox.showerror("Input Error", "Please specify a log file path.")
            return

        if not os.path.exists(log_path):
            messagebox.showerror("File Not Found", f"Log file not found at: {log_path}")
            return

        try:
            with open(log_path, 'r', errors='ignore') as f:
                content = f.read()
            self._set_command_output(self.log_content_text, content)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read log file: {e}")

    def _on_closing(self):
        """Handles closing the application window."""
        if self.snort_process and self.snort_process.poll() is None:
            if messagebox.askyesno("Exit", "Snort is currently running. Do you want to stop it and exit?"):
                self._stop_snort()
                self.root.destroy()
            else:
                pass # Don't close the window
        else:
            self.root.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = SnortApp(root)
    root.mainloop()
