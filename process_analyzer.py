import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
import time
import threading
from datetime import datetime
import pandas as pd

class ProcessAnalyzer(tk.Tk):
    def __init__(self):
        super().__init__()
        
        # Configure the main window
        self.title("AI-Powered Performance Analyzer for OS Processes")
        self.geometry("1200x700")
        self.configure(bg="#1a1a1a")
        
        # Configure style for dark theme with better contrast
        style = ttk.Style()
        style.configure("Treeview", background="#1a1a1a", foreground="#ffffff", fieldbackground="#1a1a1a")
        style.configure("Treeview.Heading", background="#2c3e50", foreground="#ffffff")
        style.configure("TNotebook", background="#1a1a1a")
        style.configure("TNotebook.Tab", background="#2c3e50", foreground="#ffffff")
        style.map("TNotebook.Tab", background=[('selected', '#3498db')])
        style.configure("TProgressbar", background="#3498db", troughcolor="#1a1a1a")
        
        # Initialize variables
        self.process_data = {}
        self.selected_pid = None
        self.monitoring = False
        self.history_data = {}
        self.update_interval = 1000  # milliseconds
        
        # Alert thresholds
        self.cpu_threshold = 80  # CPU usage threshold (%)
        self.memory_threshold = 80  # Memory usage threshold (%)
        self.alerts_enabled = True
        self.alerted_processes = set()  # Track processes that have triggered alerts
        
        # Create the main frame
        self.create_widgets()
        
        # Start monitoring
        self.toggle_monitoring()

    def check_resource_alerts(self, pid, proc_info):
        if not self.alerts_enabled:
            return

        process_name = proc_info['name']
        cpu_percent = proc_info['cpu_percent']
        memory_percent = proc_info['memory_percent']
        alert_msg = []

        # Check CPU threshold
        if cpu_percent > self.cpu_threshold:
            alert_msg.append(f"CPU usage: {cpu_percent:.1f}%")

        # Check memory threshold
        if memory_percent > self.memory_threshold:
            alert_msg.append(f"Memory usage: {memory_percent:.1f}%")

        # Show alert if thresholds exceeded and not already alerted
        if alert_msg and pid not in self.alerted_processes:
            self.alerted_processes.add(pid)
            alert_text = f"Process {process_name} (PID: {pid}) has high resource usage:\n" + "\n".join(alert_msg)
            messagebox.showwarning("Resource Alert", alert_text)

    def create_control_buttons(self):
        # Style configuration for buttons
        button_style = {
            'font': ('Arial', 10, 'bold'),
            'pady': 8,
            'padx': 15,
            'borderwidth': 2,
            'relief': 'raised',
            'bg': '#3498db',
            'fg': 'white',
            'activebackground': '#2980b9',
            'activeforeground': 'white'
        }

        # Add alert settings
        alert_frame = tk.Frame(self.top_frame, bg="#1a1a1a")
        alert_frame.pack(side=tk.RIGHT, padx=10)

        # Alert toggle button
        button_style['bg'] = '#e74c3c'
        button_style['activebackground'] = '#c0392b'
        self.alert_btn = tk.Button(alert_frame, text="Disable Alerts", command=self.toggle_alerts, **button_style)
        self.alert_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.alert_btn, "Toggle system alerts for high resource usage")

        # Threshold settings button
        button_style['bg'] = '#2ecc71'
        button_style['activebackground'] = '#27ae60'
        self.threshold_btn = tk.Button(alert_frame, text="Set Thresholds", command=self.set_thresholds, **button_style)
        self.threshold_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.threshold_btn, "Configure CPU and Memory usage alert thresholds")

        # Process control frame
        process_frame = tk.LabelFrame(self.top_frame, text="Process Controls", bg="#1a1a1a", fg="#ffffff", padx=5, pady=5)
        process_frame.pack(side=tk.LEFT, padx=10)

        # Kill Process button
        button_style['bg'] = '#e74c3c'
        button_style['activebackground'] = '#c0392b'
        self.kill_btn = tk.Button(process_frame, text="Kill Process", command=self.kill_selected_process,
                                state=tk.DISABLED, **button_style)
        self.kill_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.kill_btn, "Terminate the selected process")

        # Process Details button
        button_style['bg'] = '#9b59b6'
        button_style['activebackground'] = '#8e44ad'
        self.details_btn = tk.Button(process_frame, text="Process Details", command=self.show_process_details,
                                state=tk.DISABLED, **button_style)
        self.details_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.details_btn, "View detailed information about the selected process")

        # Refresh button
        button_style['bg'] = '#2ecc71'
        button_style['activebackground'] = '#27ae60'
        self.refresh_btn = tk.Button(process_frame, text="Refresh", command=self.refresh_processes, **button_style)
        self.refresh_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.refresh_btn, "Manually refresh the process list")
        
        # Monitor toggle button
        button_style['bg'] = '#e67e22'
        button_style['activebackground'] = '#d35400'
        self.monitor_btn = tk.Button(process_frame, text="Stop Monitoring", command=self.toggle_monitoring, **button_style)
        self.monitor_btn.pack(side=tk.LEFT, padx=5)
        self.create_tooltip(self.monitor_btn, "Toggle automatic process monitoring")

    def create_tooltip(self, widget, text):
        def show_tooltip(event):
            tooltip = tk.Toplevel()
            tooltip.wm_overrideredirect(True)
            tooltip.wm_geometry(f"+{event.x_root+10}+{event.y_root+10}")

            label = tk.Label(tooltip, text=text, justify=tk.LEFT,
                          background="#ffffe0", relief="solid", borderwidth=1,
                          font=("Arial", "9", "normal"))
            label.pack()

            def hide_tooltip():
                tooltip.destroy()

            widget.tooltip = tooltip
            widget.bind('<Leave>', lambda e: hide_tooltip())

        widget.bind('<Enter>', show_tooltip)
        
        # Filter entry
        tk.Label(self.top_frame, text="Filter:", bg="#1a1a1a", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        self.filter_var = tk.StringVar()
        self.filter_entry = tk.Entry(self.top_frame, textvariable=self.filter_var, width=20)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_var.trace("w", lambda *args: self.apply_filter())
        
        # Sort options
        tk.Label(self.top_frame, text="Sort by:", bg="#1a1a1a", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        self.sort_var = tk.StringVar(value="CPU %")
        sort_options = ["PID", "Name", "CPU %", "Memory %", "Status"]
        sort_menu = tk.OptionMenu(self.top_frame, self.sort_var, *sort_options, command=self.apply_sort)
        sort_menu.pack(side=tk.LEFT, padx=5)
        
        # Update interval
        tk.Label(self.top_frame, text="Update interval (ms):", bg="#1a1a1a", fg="#ffffff").pack(side=tk.LEFT, padx=5)
        self.interval_var = tk.StringVar(value="1000")
        interval_entry = tk.Entry(self.top_frame, textvariable=self.interval_var, width=6)
        interval_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(self.top_frame, text="Apply", command=self.update_interval_setting,
                 bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=5)
    
    def create_process_table(self):
        # Create a frame for the table
        table_frame = tk.Frame(self.left_panel)
        table_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(table_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Treeview for process list
        columns = ("PID", "Name", "CPU %", "Memory %", "Status", "Threads")
        self.process_tree = ttk.Treeview(table_frame, columns=columns, show="headings", 
                                        yscrollcommand=scrollbar.set, height=20)
        
        # Configure columns
        for col in columns:
            self.process_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c))
            width = 100 if col != "Name" else 200
            self.process_tree.column(col, width=width, anchor=tk.CENTER)
        
        self.process_tree.pack(fill=tk.BOTH, expand=True)
        scrollbar.config(command=self.process_tree.yview)
        
        # Bind selection event
        self.process_tree.bind("<<TreeviewSelect>>", self.on_process_select)
    
    def create_performance_graphs(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.right_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # CPU and Memory tab
        self.cpu_mem_tab = tk.Frame(self.notebook, bg="#f0f0f0")
        self.notebook.add(self.cpu_mem_tab, text="CPU & Memory")
        
        # Create figures for CPU and Memory with dark theme
        plt.style.use('dark_background')
        
        self.cpu_fig = plt.Figure(figsize=(6, 3), dpi=100, facecolor='#2c3e50')
        self.cpu_ax = self.cpu_fig.add_subplot(111)
        self.cpu_ax.set_facecolor('#34495e')
        self.cpu_canvas = FigureCanvasTkAgg(self.cpu_fig, self.cpu_mem_tab)
        self.cpu_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.mem_fig = plt.Figure(figsize=(6, 3), dpi=100, facecolor='#2c3e50')
        self.mem_ax = self.mem_fig.add_subplot(111)
        self.mem_ax.set_facecolor('#34495e')
        self.mem_canvas = FigureCanvasTkAgg(self.mem_fig, self.cpu_mem_tab)
        self.mem_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # IO and Network tab
        self.io_net_tab = tk.Frame(self.notebook, bg="#f0f0f0")
        self.notebook.add(self.io_net_tab, text="I/O & Network")
        
        # Create figures for IO and Network
        self.io_fig = plt.Figure(figsize=(6, 3), dpi=100)
        self.io_ax = self.io_fig.add_subplot(111)
        self.io_canvas = FigureCanvasTkAgg(self.io_fig, self.io_net_tab)
        self.io_canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # System Overview tab
        self.system_tab = tk.Frame(self.notebook, bg="#f0f0f0")
        self.notebook.add(self.system_tab, text="System Overview")
        
        # Create system overview widgets
        self.create_system_overview()
    
    def create_system_overview(self):
        # System info frame
        info_frame = tk.Frame(self.system_tab, bg="#1a1a1a")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # CPU usage progress bar
        tk.Label(info_frame, text="CPU Usage:", bg="#1a1a1a", fg="#ffffff", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w", pady=5)
        self.cpu_progress = ttk.Progressbar(info_frame, orient=tk.HORIZONTAL, length=300, mode="determinate")
        self.cpu_progress.grid(row=0, column=1, sticky="w", padx=10)
        self.cpu_percent_label = tk.Label(info_frame, text="0%", bg="#1a1a1a", fg="#ffffff")
        self.cpu_percent_label.grid(row=0, column=2, sticky="w")
        
        # Memory usage progress bar
        tk.Label(info_frame, text="Memory Usage:", bg="#1a1a1a", fg="#ffffff", font=("Arial", 10, "bold")).grid(row=1, column=0, sticky="w", pady=5)
        self.mem_progress = ttk.Progressbar(info_frame, orient=tk.HORIZONTAL, length=300, mode="determinate")
        self.mem_progress.grid(row=1, column=1, sticky="w", padx=10)
        self.mem_percent_label = tk.Label(info_frame, text="0%", bg="#1a1a1a", fg="#ffffff")
        self.mem_percent_label.grid(row=1, column=2, sticky="w")
        
        # Disk usage progress bar
        tk.Label(info_frame, text="Disk Usage:", bg="#1a1a1a", fg="#ffffff", font=("Arial", 10, "bold")).grid(row=2, column=0, sticky="w", pady=5)
        self.disk_progress = ttk.Progressbar(info_frame, orient=tk.HORIZONTAL, length=300, mode="determinate")
        self.disk_progress.grid(row=2, column=1, sticky="w", padx=10)
        self.disk_percent_label = tk.Label(info_frame, text="0%", bg="#1a1a1a", fg="#ffffff")
        self.disk_percent_label.grid(row=2, column=2, sticky="w")
        
        # System information
        system_info_frame = tk.LabelFrame(self.system_tab, text="System Information", bg="#f0f0f0")
        system_info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Get system information
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        cpu_count = psutil.cpu_count(logical=True)
        cpu_physical = psutil.cpu_count(logical=False)
        mem_total = round(psutil.virtual_memory().total / (1024**3), 2)  # GB
        
        # Display system information
        info_text = f"System Boot Time: {boot_time}\n"
        info_text += f"CPU Cores: {cpu_physical} Physical, {cpu_count} Logical\n"
        info_text += f"Total Memory: {mem_total} GB\n"
        info_text += f"Platform: {psutil.POSIX and 'POSIX' or 'Windows'}\n"
        
        system_info_label = tk.Label(system_info_frame, text=info_text, bg="#f0f0f0", justify=tk.LEFT, padx=10, pady=10)
        system_info_label.pack(fill=tk.BOTH, expand=True)
        
        # Top processes frame
        top_processes_frame = tk.LabelFrame(self.system_tab, text="Top Processes", bg="#f0f0f0")
        top_processes_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Treeview for top processes
        columns = ("PID", "Name", "CPU %", "Memory %")
        self.top_processes_tree = ttk.Treeview(top_processes_frame, columns=columns, show="headings", height=5)
        
        # Configure columns
        for col in columns:
            self.top_processes_tree.heading(col, text=col)
            width = 100 if col != "Name" else 200
            self.top_processes_tree.column(col, width=width, anchor=tk.CENTER)
        
        self.top_processes_tree.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def refresh_processes(self):
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Get process information
        self.process_data = {}
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'status', 'num_threads']):
            try:
                proc_info = proc.info
                pid = proc_info['pid']
                
                # Initialize CPU and memory percentages with default values if None
                proc_info['cpu_percent'] = proc_info.get('cpu_percent', 0.0) or 0.0
                proc_info['memory_percent'] = proc_info.get('memory_percent', 0.0) or 0.0
                self.process_data[pid] = proc_info
                
                # Check resource usage alerts
                self.check_resource_alerts(pid, proc_info)
                
                # Format values
                cpu_percent = f"{proc_info['cpu_percent']:.1f}%"
                memory_percent = f"{proc_info['memory_percent']:.1f}%"
                
                # Add to treeview
                self.process_tree.insert("", tk.END, values=(
                    pid,
                    proc_info['name'],
                    cpu_percent,
                    memory_percent,
                    proc_info['status'],
                    proc_info['num_threads']
                ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
        
        # Apply current filter and sort
        self.apply_filter()
        self.apply_sort()
        
        # Update system overview
        self.update_system_overview()
        
        # Update top processes
        self.update_top_processes()
    
    def update_system_overview(self):
        # Update CPU usage
        cpu_percent = psutil.cpu_percent()
        self.cpu_progress["value"] = cpu_percent
        self.cpu_percent_label.config(text=f"{cpu_percent:.1f}%")
        
        # Update memory usage
        mem = psutil.virtual_memory()
        mem_percent = mem.percent
        self.mem_progress["value"] = mem_percent
        self.mem_percent_label.config(text=f"{mem_percent:.1f}%")
        
        # Update disk usage
        disk = psutil.disk_usage('/')
        disk_percent = disk.percent
        self.disk_progress["value"] = disk_percent
        self.disk_percent_label.config(text=f"{disk_percent:.1f}%")
    
    def update_top_processes(self):
        # Clear existing items
        for item in self.top_processes_tree.get_children():
            self.top_processes_tree.delete(item)
        
        # Sort processes by CPU usage
        top_cpu_procs = sorted(self.process_data.values(), key=lambda x: x['cpu_percent'], reverse=True)[:5]
        
        # Add to treeview
        for proc in top_cpu_procs:
            self.top_processes_tree.insert("", tk.END, values=(
                proc['pid'],
                proc['name'],
                f"{proc['cpu_percent']:.1f}%",
                f"{proc['memory_percent']:.1f}%"
            ))
    
    def apply_filter(self):
        filter_text = self.filter_var.get().lower()
        
        # Clear existing items
        for item in self.process_tree.get_children():
            self.process_tree.delete(item)
        
        # Apply filter
        for pid, proc_info in self.process_data.items():
            if (filter_text in str(pid).lower() or 
                filter_text in proc_info['name'].lower() or 
                filter_text in proc_info['status'].lower()):
                
                # Format values
                cpu_percent = f"{proc_info['cpu_percent']:.1f}%"
                memory_percent = f"{proc_info['memory_percent']:.1f}%"
                
                # Add to treeview
                self.process_tree.insert("", tk.END, values=(
                    pid,
                    proc_info['name'],
                    cpu_percent,
                    memory_percent,
                    proc_info['status'],
                    proc_info['num_threads']
                ))
        
        # Apply current sort
        self.apply_sort()
    
    def apply_sort(self, *args):
        sort_by = self.sort_var.get()
        self.sort_by_column(sort_by)
    
    def sort_by_column(self, col):
        # Get all items
        items = [(self.process_tree.set(item, col), item) for item in self.process_tree.get_children('')]
        
        # Sort items
        if col in ["PID", "Threads"]:
            # Numeric sort
            items.sort(key=lambda x: int(x[0]) if x[0].isdigit() else 0)
        elif col in ["CPU %", "Memory %"]:
            # Percentage sort
            items.sort(key=lambda x: float(x[0].rstrip('%')) if x[0].rstrip('%').replace('.', '', 1).isdigit() else 0)
        else:
            # Text sort
            items.sort()
        
        # Rearrange items
        for index, (val, item) in enumerate(items):
            self.process_tree.move(item, '', index)
    
    def create_widgets(self):
        # Create main frames
        self.top_frame = tk.Frame(self, bg="#1a1a1a")
        self.top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Create control buttons
        self.create_control_buttons()
        
        # Create main content area
        content_frame = tk.Frame(self, bg="#1a1a1a")
        content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create left and right panels
        self.left_panel = tk.Frame(content_frame, bg="#1a1a1a")
        self.left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.right_panel = tk.Frame(content_frame, bg="#1a1a1a")
        self.right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Create process table
        self.create_process_table()
        
        # Create performance graphs
        self.create_performance_graphs()
    
    def toggle_alerts(self):
        self.alerts_enabled = not self.alerts_enabled
        self.alert_btn.config(text="Enable Alerts" if not self.alerts_enabled else "Disable Alerts")
        if self.alerts_enabled:
            self.alert_btn.config(bg="#FF9800")
        else:
            self.alert_btn.config(bg="#9E9E9E")
            self.alerted_processes.clear()  # Clear alert history when disabled
    
    def set_thresholds(self):
        # Create threshold settings window
        settings_window = tk.Toplevel(self)
        settings_window.title("Alert Thresholds")
        settings_window.geometry("300x150")
        settings_window.configure(bg="#f0f0f0")
        
        # CPU threshold
        tk.Label(settings_window, text="CPU Threshold (%)", bg="#f0f0f0").pack(pady=5)
        cpu_entry = tk.Entry(settings_window)
        cpu_entry.insert(0, str(self.cpu_threshold))
        cpu_entry.pack()
        
        # Memory threshold
        tk.Label(settings_window, text="Memory Threshold (%)", bg="#f0f0f0").pack(pady=5)
        mem_entry = tk.Entry(settings_window)
        mem_entry.insert(0, str(self.memory_threshold))
        mem_entry.pack()
        
        def apply_settings():
            try:
                self.cpu_threshold = float(cpu_entry.get())
                self.memory_threshold = float(mem_entry.get())
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Error", "Please enter valid numbers for thresholds")
        
        # Apply button
        tk.Button(settings_window, text="Apply", command=apply_settings,
                  bg="#4CAF50", fg="white").pack(pady=10)
    
    def kill_selected_process(self):
        if not self.selected_pid:
            return
        
        try:
            process = psutil.Process(self.selected_pid)
            process_name = process.name()
            
            # Ask for confirmation
            if messagebox.askyesno("Confirm Action",
                                  f"Are you sure you want to terminate {process_name} (PID: {self.selected_pid})?\n\nThis action cannot be undone."):
                process.terminate()
                messagebox.showinfo("Success", f"Process {process_name} (PID: {self.selected_pid}) has been terminated.")
                self.refresh_processes()
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Failed to terminate process: {str(e)}")
    
    def show_process_details(self):
        if not self.selected_pid:
            return
        
        try:
            process = psutil.Process(self.selected_pid)
            
            # Gather detailed process information
            info = {
                "Name": process.name(),
                "PID": process.pid,
                "Status": process.status(),
                "CPU %": f"{process.cpu_percent():.1f}%",
                "Memory %": f"{process.memory_percent():.1f}%",
                "Memory Usage": f"{process.memory_info().rss / (1024*1024):.1f} MB",
                "Threads": process.num_threads(),
                "Priority": process.nice(),
                "Created": datetime.fromtimestamp(process.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
                "Username": process.username(),
                "Command Line": " ".join(process.cmdline()) if process.cmdline() else "N/A"
            }
            
            # Create details window
            details_window = tk.Toplevel(self)
            details_window.title(f"Process Details - {info['Name']} (PID: {info['PID']})")
            details_window.geometry("600x400")
            details_window.configure(bg="#f0f0f0")
            
            # Create text widget to display information
            text_widget = tk.Text(details_window, wrap=tk.WORD, bg="#ffffff", font=("Courier", 10))
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            # Insert information
            for key, value in info.items():
                text_widget.insert(tk.END, f"{key}: {value}\n")
            
            text_widget.configure(state=tk.DISABLED)
            
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            messagebox.showerror("Error", f"Failed to get process details: {str(e)}")
    
    def on_process_select(self, event):
        # Get selected item
        selection = self.process_tree.selection()
        if not selection:
            self.kill_btn.config(state=tk.DISABLED)
            self.details_btn.config(state=tk.DISABLED)
            return
        
        # Get PID of selected process
        item = selection[0]
        pid = int(self.process_tree.item(item, "values")[0])
        self.selected_pid = pid
        
        # Enable kill and details buttons
        self.kill_btn.config(state=tk.NORMAL)
        self.details_btn.config(state=tk.NORMAL)
        
        # Update graphs for selected process
        self.update_process_graphs()
    
    def update_process_graphs(self):
        if not self.selected_pid or self.selected_pid not in self.process_data:
            return
        
        # Get process info
        try:
            proc = psutil.Process(self.selected_pid)
            proc_name = proc.name()
            
            # Update history data
            current_time = time.time()
            if self.selected_pid not in self.history_data:
                self.history_data[self.selected_pid] = {
                    'times': [],
                    'cpu': [],
                    'memory': [],
                    'io_read': [],
                    'io_write': []
                }
            
            # Add current data point
            history = self.history_data[self.selected_pid]
            history['times'].append(current_time)
            history['cpu'].append(proc.cpu_percent())
            history['memory'].append(proc.memory_percent())
            
            # IO counters (may not be available for all processes)
            try:
                io_counters = proc.io_counters()
                history['io_read'].append(io_counters.read_bytes)
                history['io_write'].append(io_counters.write_bytes)
            except (psutil.AccessDenied, AttributeError):
                history['io_read'].append(0)
                history['io_write'].append(0)
            
            # Limit history length
            max_points = 60
            if len(history['times']) > max_points:
                history['times'] = history['times'][-max_points:]
                history['cpu'] = history['cpu'][-max_points:]
                history['memory'] = history['memory'][-max_points:]
                history['io_read'] = history['io_read'][-max_points:]
                history['io_write'] = history['io_write'][-max_points:]
            
            # Update CPU graph
            self.cpu_ax.clear()
            self.cpu_ax.plot(range(len(history['cpu'])), history['cpu'], color='#3498db', linewidth=2)
            self.cpu_ax.set_title(f"CPU Usage for {proc_name} (PID: {self.selected_pid})", color='white')
            self.cpu_ax.set_ylabel("CPU %", color='white')
            self.cpu_ax.set_ylim(0, max(100, max(history['cpu']) * 1.1 if history['cpu'] else 100))
            self.cpu_ax.grid(True, color='#95a5a6', alpha=0.2)
            self.cpu_ax.tick_params(colors='white')
            self.cpu_canvas.draw()
            
            # Update Memory graph
            self.mem_ax.clear()
            self.mem_ax.plot(range(len(history['memory'])), history['memory'], color='#e74c3c', linewidth=2)
            self.mem_ax.set_title(f"Memory Usage for {proc_name} (PID: {self.selected_pid})", color='white')
            self.mem_ax.set_ylabel("Memory %", color='white')
            self.mem_ax.set_ylim(0, max(100, max(history['memory']) * 1.1 if history['memory'] else 100))
            self.mem_ax.grid(True, color='#95a5a6', alpha=0.2)
            self.mem_ax.tick_params(colors='white')
            self.mem_canvas.draw()
            
            # Update IO graph if data is available
            if any(history['io_read']) or any(history['io_write']):
                self.io_ax.clear()
                
                # Calculate IO rates
                io_read_rates = [0]
                io_write_rates = [0]
                
                for i in range(1, len(history['times'])):
                    time_diff = history['times'][i] - history['times'][i-1]
                    if time_diff > 0:
                        read_rate = (history['io_read'][i] - history['io_read'][i-1]) / time_diff / 1024  # KB/s
                        write_rate = (history['io_write'][i] - history['io_write'][i-1]) / time_diff / 1024  # KB/s
                        io_read_rates.append(read_rate)
                        io_write_rates.append(write_rate)
                    else:
                        io_read_rates.append(0)
                        io_write_rates.append(0)
                
                self.io_ax.plot(range(len(io_read_rates)), io_read_rates, 'g-', label="Read (KB/s)")
                self.io_ax.plot(range(len(io_write_rates)), io_write_rates, 'm-', label="Write (KB/s)")
                self.io_ax.set_title(f"I/O Activity for {proc_name} (PID: {self.selected_pid})")
                self.io_ax.set_ylabel("KB/s")
                self.io_ax.legend()
                self.io_ax.grid(True)
                self.io_canvas.draw()
        
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            # Process no longer exists or access denied
            self.selected_pid = None
    
    def toggle_monitoring(self):
        self.monitoring = not self.monitoring
        
        if self.monitoring:
            self.monitor_btn.config(text="Stop Monitoring", bg="#f44336")
            self.refresh_processes()
            self.after(self.update_interval, self.update_monitoring)
        else:
            self.monitor_btn.config(text="Start Monitoring", bg="#4CAF50")
    
    def update_monitoring(self):
        if not self.monitoring:
            return
        
        # Refresh process data
        self.refresh_processes()
        
        # Update graphs if a process is selected
        if self.selected_pid:
            self.update_process_graphs()
        
        # Schedule next update
        self.after(self.update_interval, self.update_monitoring)
    
    def update_interval_setting(self):
        try:
            new_interval = int(self.interval_var.get())
            if new_interval < 100:
                messagebox.showwarning("Invalid Interval", "Update interval must be at least 100ms.")
                self.interval_var.set(str(self.update_interval))
                return
            
            self.update_interval = new_interval
            messagebox.showinfo("Success", f"Update interval set to {new_interval}ms.")
        except ValueError:
            messagebox.showerror("Error", "Please enter a valid number for the update interval.")
            self.interval_var.set(str(self.update_interval))

# Run the application
if __name__ == "__main__":
    app = ProcessAnalyzer()
    app.mainloop()

    def toggle_alerts(self):
        self.alerts_enabled = not self.alerts_enabled
        self.alert_btn.config(
            text="Enable Alerts" if not self.alerts_enabled else "Disable Alerts",
            bg="#9E9E9E" if not self.alerts_enabled else "#FF9800"
        )
        if self.alerts_enabled:
            self.alerted_processes.clear()  # Reset alerted processes when re-enabling
    
    def set_thresholds(self):
        # Create threshold settings window
        settings_window = tk.Toplevel(self)
        settings_window.title("Alert Thresholds")
        settings_window.geometry("300x200")
        settings_window.configure(bg="#f0f0f0")
        settings_window.transient(self)
        settings_window.grab_set()
        
        # CPU threshold setting
        cpu_frame = tk.Frame(settings_window, bg="#f0f0f0")
        cpu_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(cpu_frame, text="CPU Threshold (%): ", bg="#f0f0f0").pack(side=tk.LEFT)
        cpu_var = tk.StringVar(value=str(self.cpu_threshold))
        cpu_entry = tk.Entry(cpu_frame, textvariable=cpu_var, width=5)
        cpu_entry.pack(side=tk.LEFT)
        
        # Memory threshold setting
        mem_frame = tk.Frame(settings_window, bg="#f0f0f0")
        mem_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(mem_frame, text="Memory Threshold (%): ", bg="#f0f0f0").pack(side=tk.LEFT)
        mem_var = tk.StringVar(value=str(self.memory_threshold))
        mem_entry = tk.Entry(mem_frame, textvariable=mem_var, width=5)
        mem_entry.pack(side=tk.LEFT)
        
        def apply_settings():
            try:
                new_cpu = int(cpu_var.get())
                new_mem = int(mem_var.get())
                
                if not (0 <= new_cpu <= 100 and 0 <= new_mem <= 100):
                    raise ValueError("Thresholds must be between 0 and 100")
                
                self.cpu_threshold = new_cpu
                self.memory_threshold = new_mem
                self.alerted_processes.clear()  # Reset alerts with new thresholds
                settings_window.destroy()
                messagebox.showinfo("Success", "Alert thresholds updated successfully")
                
            except ValueError as e:
                messagebox.showerror("Error", str(e))
        
        # Apply button
        tk.Button(settings_window, text="Apply", command=apply_settings,
                  bg="#2196F3", fg="white", padx=20).pack(pady=20)
