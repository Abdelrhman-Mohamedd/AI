"""
Modern Vulnerability Detection GUI Application
A contemporary Tkinter-based interface for the VulneraPred vulnerability detection system
Features blue-themed design with modern UI components
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import os
from pathlib import Path
from datetime import datetime


# Import the prediction modules
from predict import detect_vulnerability_patterns, predict_code, load_models, calculate_risk_factors
from vulnerapred.features import CodeFeatureExtractor
import joblib


class ModernColors:
    """Modern color palette with blue primary theme"""
    # Primary Blue Shades
    PRIMARY = "#2196F3"      # Bright blue
    PRIMARY_DARK = "#1976D2"  # Dark blue
    PRIMARY_DARKER = "#0D47A1" # Very dark blue
    PRIMARY_LIGHT = "#BBDEFB" # Light blue
    
    # Accent Colors
    SUCCESS = "#4CAF50"      # Green
    WARNING = "#FFC107"      # Amber
    ERROR = "#F44336"        # Red
    INFO = "#2196F3"         # Blue
    
    # Backgrounds
    BG_PRIMARY = "#F5F7FA"   # Light background
    BG_SECONDARY = "#FFFFFF" # White
    BG_TERTIARY = "#E3F2FD"  # Light blue background
    
    # Text
    TEXT_PRIMARY = "#212121"   # Dark text
    TEXT_SECONDARY = "#757575" # Gray text
    TEXT_LIGHT = "#FFFFFF"     # White text
    
    # Borders
    BORDER = "#E0E0E0"
    BORDER_LIGHT = "#F0F0F0"
    
    # Severity Icons & Colors
    SEVERITY_CRITICAL = "#D32F2F"  # Deep red
    SEVERITY_HIGH = "#F57C00"      # Deep orange
    SEVERITY_MEDIUM = "#FBC02D"    # Amber
    SEVERITY_LOW = "#388E3C"       # Green


class ModernVulnerabilityDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("VulneraPred - Vulnerability Detection System")
        self.root.geometry("1400x900")
        self.root.minsize(1000, 700)
        
        # Set window background
        self.root.configure(bg=ModernColors.BG_PRIMARY)
        
        # Configure styles
        self.setup_modern_styles()
        
        # Create UI first
        self.create_menu()
        self.create_header()
        self.create_widgets()
        
        # Load models after UI is ready
        self.models_loaded = False
        self.load_models_thread()
        
    def setup_modern_styles(self):
        """Configure modern ttk styles with blue theme"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('TFrame', background=ModernColors.BG_PRIMARY)
        style.configure('TLabelFrame', background=ModernColors.BG_PRIMARY)
        style.configure('TLabel', background=ModernColors.BG_PRIMARY, foreground=ModernColors.TEXT_PRIMARY)
        
        # Title styles
        style.configure('Title.TLabel',
                       font=('Segoe UI', 24, 'bold'),
                       background=ModernColors.BG_PRIMARY,
                       foreground=ModernColors.PRIMARY_DARK)
        
        style.configure('Subtitle.TLabel',
                       font=('Segoe UI', 12),
                       background=ModernColors.BG_PRIMARY,
                       foreground=ModernColors.TEXT_SECONDARY)
        
        style.configure('Header.TLabel',
                       font=('Segoe UI', 11, 'bold'),
                       background=ModernColors.BG_PRIMARY,
                       foreground=ModernColors.TEXT_PRIMARY)
        
        style.configure('Status.TLabel',
                       font=('Segoe UI', 10),
                       background=ModernColors.BG_PRIMARY,
                       foreground=ModernColors.TEXT_SECONDARY)
        
        # Status labels
        style.configure('Vulnerable.TLabel',
                       foreground=ModernColors.SEVERITY_CRITICAL,
                       font=('Segoe UI', 13, 'bold'),
                       background=ModernColors.BG_PRIMARY)
        
        style.configure('Safe.TLabel',
                       foreground=ModernColors.SUCCESS,
                       font=('Segoe UI', 13, 'bold'),
                       background=ModernColors.BG_PRIMARY)
        
        # Buttons
        style.configure('Accent.TButton',
                       font=('Segoe UI', 10, 'bold'))
        
        style.map('Accent.TButton',
                 foreground=[('active', ModernColors.TEXT_LIGHT)],
                 background=[('active', ModernColors.PRIMARY_DARK)])
        
        style.configure('Primary.TButton',
                       font=('Segoe UI', 10, 'bold'),
                       background=ModernColors.PRIMARY)
        
        style.map('Primary.TButton',
                 background=[('active', ModernColors.PRIMARY_DARK), ('disabled', '#CCCCCC')])
        
        style.configure('Secondary.TButton',
                       font=('Segoe UI', 9),
                       background=ModernColors.BG_SECONDARY)
        
        # LabelFrame with modern style
        style.configure('Card.TLabelFrame',
                       background=ModernColors.BG_SECONDARY,
                       foreground=ModernColors.TEXT_PRIMARY,
                       font=('Segoe UI', 11, 'bold'),
                       borderwidth=1)
        
        # Progressbar
        style.configure('Horizontal.TProgressbar',
                       background=ModernColors.PRIMARY,
                       troughcolor=ModernColors.BG_TERTIARY,
                       bordercolor=ModernColors.BORDER,
                       lightcolor=ModernColors.PRIMARY_LIGHT,
                       darkcolor=ModernColors.PRIMARY)
        
        # Notebook (tabs)
        style.configure('TNotebook',
                       background=ModernColors.BG_PRIMARY,
                       borderwidth=0)
        
        style.configure('TNotebook.Tab',
                       font=('Segoe UI', 10),
                       padding=[20, 10])
        
    def create_menu(self):
        """Create modern menu bar"""
        menubar = tk.Menu(self.root, bg=ModernColors.BG_SECONDARY, fg=ModernColors.TEXT_PRIMARY)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0,
                           bg=ModernColors.BG_SECONDARY, fg=ModernColors.TEXT_PRIMARY,
                           activebackground=ModernColors.PRIMARY_LIGHT,
                           activeforeground=ModernColors.PRIMARY_DARK)
        menubar.add_cascade(label="📁 File", menu=file_menu)
        file_menu.add_command(label="Open File", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Clear All", command=self.clear_all, accelerator="Ctrl+L")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit, accelerator="Ctrl+Q")
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0,
                           bg=ModernColors.BG_SECONDARY, fg=ModernColors.TEXT_PRIMARY,
                           activebackground=ModernColors.PRIMARY_LIGHT,
                           activeforeground=ModernColors.PRIMARY_DARK)
        menubar.add_cascade(label="✏️ Edit", menu=edit_menu)
        edit_menu.add_command(label="Select All", command=self.select_all_code, accelerator="Ctrl+A")
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0,
                           bg=ModernColors.BG_SECONDARY, fg=ModernColors.TEXT_PRIMARY,
                           activebackground=ModernColors.PRIMARY_LIGHT,
                           activeforeground=ModernColors.PRIMARY_DARK)
        menubar.add_cascade(label="❓ Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
        help_menu.add_command(label="Documentation", command=self.show_documentation)
        
        # Keyboard shortcuts
        self.root.bind('<Control-o>', lambda e: self.open_file())
        self.root.bind('<Control-l>', lambda e: self.clear_all())
        self.root.bind('<Control-q>', lambda e: self.root.quit())
        self.root.bind('<Control-a>', lambda e: self.select_all_code())
        
    def create_header(self):
        """Create modern header section"""
        header_frame = tk.Frame(self.root, bg=ModernColors.PRIMARY, height=100)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=0, pady=0)
        header_frame.pack_propagate(False)
        
        # Header content
        content = tk.Frame(header_frame, bg=ModernColors.PRIMARY)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=15)
        
        # Title with icon
        title_label = tk.Label(content, text="🛡️ VulneraPred",
                              font=('Segoe UI', 28, 'bold'),
                              fg=ModernColors.TEXT_LIGHT,
                              bg=ModernColors.PRIMARY)
        title_label.pack(anchor=tk.W)
        
        # Subtitle
        subtitle_label = tk.Label(content, text="Modern AI-Powered Vulnerability Detection System",
                                 font=('Segoe UI', 11),
                                 fg=ModernColors.PRIMARY_LIGHT,
                                 bg=ModernColors.PRIMARY)
        subtitle_label.pack(anchor=tk.W)
        
    def create_widgets(self):
        """Create main UI widgets with modern design"""
        # Main container
        main_frame = tk.Frame(self.root, bg=ModernColors.BG_PRIMARY)
        main_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=15, pady=15)
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Create two main panels
        left_frame = tk.Frame(main_frame, bg=ModernColors.BG_PRIMARY)
        left_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 7))
        
        right_frame = tk.Frame(main_frame, bg=ModernColors.BG_PRIMARY)
        right_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(7, 0))
        
        # Configure grid weights
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(0, weight=1)
        
        # ===== LEFT PANEL - CODE INPUT =====
        self.create_input_panel(left_frame)
        
        # ===== RIGHT PANEL - RESULTS =====
        self.create_results_panel(right_frame)
        
        # ===== BOTTOM STATUS BAR =====
        self.create_status_bar()
        
    def create_input_panel(self, parent):
        """Create code input panel with modern styling"""
        # Card background
        card = tk.Frame(parent, bg=ModernColors.BG_SECONDARY, relief=tk.FLAT)
        card.pack(fill=tk.BOTH, expand=True)
        
        # Add subtle border
        border = tk.Frame(card, bg=ModernColors.BORDER, height=1)
        border.pack(fill=tk.X)
        
        # Header with gradient effect
        header = tk.Frame(card, bg=ModernColors.BG_TERTIARY, height=50)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        header_content = tk.Frame(header, bg=ModernColors.BG_TERTIARY)
        header_content.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        title = tk.Label(header_content, text="📝 Code Input",
                        font=('Segoe UI', 12, 'bold'),
                        bg=ModernColors.BG_TERTIARY,
                        fg=ModernColors.PRIMARY_DARK)
        title.pack(anchor=tk.W)
        
        # File info
        info_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        info_frame.pack(fill=tk.X, padx=15, pady=(10, 5))
        
        self.file_label = tk.Label(info_frame, text="📄 No file loaded",
                                   font=('Segoe UI', 9),
                                   fg=ModernColors.TEXT_SECONDARY,
                                   bg=ModernColors.BG_SECONDARY)
        self.file_label.pack(anchor=tk.W)
        
        # Code editor
        editor_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        editor_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        self.code_text = scrolledtext.ScrolledText(editor_frame,
                                                    wrap=tk.WORD,
                                                    font=('Consolas', 10),
                                                    bg='#1e1e1e',  # Dark background like VS Code
                                                    fg='#d4d4d4',  # Light gray text
                                                    insertbackground='#ffffff',
                                                    selectbackground='#264f78',
                                                    relief=tk.FLAT,
                                                    borderwidth=1,
                                                    highlightthickness=0)
        self.code_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure syntax highlighting tags
        self._setup_syntax_highlighting()
        
        # Bind events for real-time syntax highlighting
        self.code_text.bind('<KeyRelease>', lambda e: self._highlight_syntax())
        self.code_text.bind('<<Paste>>', lambda e: self.root.after(10, self._highlight_syntax))
        
        # Action buttons
        btn_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        btn_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.open_btn = tk.Button(btn_frame,
                                 text="📁 Open File",
                                 command=self.open_file,
                                 bg=ModernColors.PRIMARY,
                                 fg=ModernColors.TEXT_LIGHT,
                                 font=('Segoe UI', 10, 'bold'),
                                 relief=tk.FLAT,
                                 padx=15,
                                 pady=8,
                                 cursor="hand2",
                                 activebackground=ModernColors.PRIMARY_DARK,
                                 activeforeground=ModernColors.TEXT_LIGHT)
        self.open_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.analyze_btn = tk.Button(btn_frame,
                                    text="🔍 Analyze Code",
                                    command=self.analyze_code,
                                    bg=ModernColors.PRIMARY_DARK,
                                    fg=ModernColors.TEXT_LIGHT,
                                    font=('Segoe UI', 10, 'bold'),
                                    relief=tk.FLAT,
                                    padx=15,
                                    pady=8,
                                    cursor="hand2",
                                    state=tk.DISABLED,
                                    activebackground=ModernColors.PRIMARY_DARKER,
                                    activeforeground=ModernColors.TEXT_LIGHT)
        self.analyze_btn.pack(side=tk.LEFT, padx=(0, 8))
        
        self.clear_btn = tk.Button(btn_frame,
                                  text="🗑️ Clear",
                                  command=self.clear_all,
                                  bg=ModernColors.BG_TERTIARY,
                                  fg=ModernColors.PRIMARY_DARK,
                                  font=('Segoe UI', 10, 'bold'),
                                  relief=tk.FLAT,
                                  padx=15,
                                  pady=8,
                                  cursor="hand2",
                                  activebackground=ModernColors.PRIMARY_LIGHT,
                                  activeforeground=ModernColors.PRIMARY_DARKER)
        self.clear_btn.pack(side=tk.LEFT)
        
    def create_results_panel(self, parent):
        """Create analysis results panel with modern styling"""
        # Main card
        card = tk.Frame(parent, bg=ModernColors.BG_SECONDARY, relief=tk.FLAT)
        card.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header = tk.Frame(card, bg=ModernColors.BG_TERTIARY, height=50)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        header_content = tk.Frame(header, bg=ModernColors.BG_TERTIARY)
        header_content.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)
        
        title = tk.Label(header_content, text="📊 Analysis Results",
                        font=('Segoe UI', 12, 'bold'),
                        bg=ModernColors.BG_TERTIARY,
                        fg=ModernColors.PRIMARY_DARK)
        title.pack(anchor=tk.W)
        
        # Status indicators
        stats_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        stats_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Create 4 stat boxes
        stat_data = [
            ("Status", "status_label", "🔵"),
            ("Confidence", "confidence_label", "📈"),
            ("Priority", "priority_label", "⚠️"),
            ("Time", "time_label", "⏱️")
        ]
        
        for i, (label_text, attr_name, icon) in enumerate(stat_data):
            stat_box = tk.Frame(stats_frame, bg=ModernColors.BG_TERTIARY, relief=tk.FLAT)
            stat_box.grid(row=0, column=i, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
            stats_frame.columnconfigure(i, weight=1)
            
            label = tk.Label(stat_box, text=f"{icon} {label_text}",
                            font=('Segoe UI', 9),
                            fg=ModernColors.TEXT_SECONDARY,
                            bg=ModernColors.BG_TERTIARY)
            label.pack(anchor=tk.W)
            
            value = tk.Label(stat_box, text="N/A",
                            font=('Segoe UI', 11, 'bold'),
                            fg=ModernColors.PRIMARY_DARK,
                            bg=ModernColors.BG_TERTIARY)
            value.pack(anchor=tk.W, pady=(3, 0))
            
            setattr(self, attr_name, value)
        
        # Progress bar
        prog_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        prog_frame.pack(fill=tk.X, padx=15, pady=(0, 15))
        
        self.progress = ttk.Progressbar(prog_frame, mode='indeterminate', length=300)
        self.progress.pack(fill=tk.X)
        
        # Divider
        divider = tk.Frame(card, bg=ModernColors.BORDER, height=1)
        divider.pack(fill=tk.X, padx=15, pady=10)
        
        # Results header
        result_header = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        result_header.pack(fill=tk.X, padx=15, pady=(0, 10))
        
        result_title = tk.Label(result_header, text="📋 Detailed Report",
                               font=('Segoe UI', 11, 'bold'),
                               fg=ModernColors.TEXT_PRIMARY,
                               bg=ModernColors.BG_SECONDARY)
        result_title.pack(anchor=tk.W)
        
        # Results area - use a canvas with scrollbar for custom widgets
        text_frame = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        text_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=(0, 15))
        
        # Create canvas for scrollable content
        self.results_canvas = tk.Canvas(text_frame, bg=ModernColors.BG_SECONDARY, 
                                        highlightthickness=0)
        scrollbar = ttk.Scrollbar(text_frame, orient="vertical", command=self.results_canvas.yview)
        
        self.results_container = tk.Frame(self.results_canvas, bg=ModernColors.BG_SECONDARY)
        
        self.results_canvas.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.results_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        self.results_window = self.results_canvas.create_window((0, 0), window=self.results_container, 
                                                                anchor="nw")
        
        # Bind resize event
        self.results_container.bind("<Configure>", 
                                   lambda e: self.results_canvas.configure(scrollregion=self.results_canvas.bbox("all")))
        self.results_canvas.bind("<Configure>", self._on_canvas_configure)
        
    def _on_canvas_configure(self, event):
        """Update canvas window width when canvas is resized"""
        self.results_canvas.itemconfig(self.results_window, width=event.width)
    
    def _setup_syntax_highlighting(self):
        """Setup syntax highlighting color tags"""
        # Python keywords
        self.code_text.tag_configure('keyword', foreground='#569cd6')  # Blue
        self.code_text.tag_configure('builtin', foreground='#4ec9b0')  # Cyan
        self.code_text.tag_configure('string', foreground='#ce9178')   # Orange
        self.code_text.tag_configure('comment', foreground='#6a9955')  # Green
        self.code_text.tag_configure('number', foreground='#b5cea8')   # Light green
        self.code_text.tag_configure('decorator', foreground='#c586c0') # Purple
        self.code_text.tag_configure('function', foreground='#dcdcaa')  # Yellow
        self.code_text.tag_configure('class', foreground='#4ec9b0')     # Cyan
    
    def _highlight_syntax(self):
        """Apply syntax highlighting to code"""
        import re
        
        # Remove all existing tags
        for tag in ['keyword', 'builtin', 'string', 'comment', 'number', 'decorator', 'function', 'class']:
            self.code_text.tag_remove(tag, '1.0', tk.END)
        
        code = self.code_text.get('1.0', tk.END)
        
        # Python keywords
        keywords = r'\b(def|class|if|elif|else|for|while|try|except|finally|with|as|import|from|return|yield|pass|break|continue|raise|assert|del|global|nonlocal|lambda|and|or|not|in|is|True|False|None)\b'
        for match in re.finditer(keywords, code):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.code_text.tag_add('keyword', start, end)
        
        # Built-in functions
        builtins = r'\b(print|len|range|str|int|float|list|dict|set|tuple|open|type|isinstance|enumerate|zip|map|filter|input|sum|max|min|abs|round|sorted|reversed|any|all|bool|bytes|bytearray|callable|chr|ord|compile|complex|delattr|dir|divmod|eval|exec|format|getattr|globals|hasattr|hash|help|hex|id|iter|next|oct|pow|property|repr|setattr|slice|staticmethod|super|vars)\b'
        for match in re.finditer(builtins, code):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.code_text.tag_add('builtin', start, end)
        
        # Strings (single and double quotes, including f-strings and raw strings)
        string_patterns = [
            r'f?"[^"]*"',
            r"f?'[^']*'",
            r'"""[^"]*"""',
            r"'''[^']*'''",
            r'r"[^"]*"',
            r"r'[^']*'"
        ]
        for pattern in string_patterns:
            for match in re.finditer(pattern, code, re.DOTALL):
                start = f"1.0+{match.start()}c"
                end = f"1.0+{match.end()}c"
                self.code_text.tag_add('string', start, end)
        
        # Comments
        for match in re.finditer(r'#[^\n]*', code):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.code_text.tag_add('comment', start, end)
        
        # Numbers
        for match in re.finditer(r'\b\d+\.?\d*\b', code):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.code_text.tag_add('number', start, end)
        
        # Decorators
        for match in re.finditer(r'@\w+', code):
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            self.code_text.tag_add('decorator', start, end)
        
        # Function definitions
        for match in re.finditer(r'\bdef\s+(\w+)', code):
            start = f"1.0+{match.start(1)}c"
            end = f"1.0+{match.end(1)}c"
            self.code_text.tag_add('function', start, end)
        
        # Class definitions
        for match in re.finditer(r'\bclass\s+(\w+)', code):
            start = f"1.0+{match.start(1)}c"
            end = f"1.0+{match.end(1)}c"
            self.code_text.tag_add('class', start, end)
        
    def create_status_bar(self):
        """Create modern status bar"""
        status_frame = tk.Frame(self.root, bg=ModernColors.PRIMARY_DARK, height=40)
        status_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        status_frame.pack_propagate(False)
        
        self.status_bar = tk.Label(status_frame,
                                   text="⏳ Loading models...",
                                   fg=ModernColors.TEXT_LIGHT,
                                   bg=ModernColors.PRIMARY_DARK,
                                   font=('Segoe UI', 9),
                                   anchor=tk.W,
                                   padx=15)
        self.status_bar.pack(fill=tk.BOTH, expand=True)
        
    def load_models_thread(self):
        """Load ML models in background thread"""
        def load():
            try:
                self.update_status_bar("⏳ Loading models...", "loading")
                
                # Use load_models from predict.py
                self.classifier, self.predictor, self.feature_extractor = load_models("models")
                
                self.models_loaded = True
                self.update_status_bar("✅ Ready - Models loaded successfully", "ready")
                self.analyze_btn.config(state=tk.NORMAL)
            except Exception as e:
                self.models_loaded = False
                self.update_status_bar(f"❌ Error loading models: {str(e)}", "error")
                messagebox.showerror("Error", f"Failed to load models:\n{str(e)}")
        
        thread = threading.Thread(target=load, daemon=True)
        thread.start()
        
    def open_file(self):
        """Open Python file dialog"""
        filename = filedialog.askopenfilename(
            title="Select Python File",
            filetypes=[("Python files", "*.py"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                self.code_text.delete(1.0, tk.END)
                self.code_text.insert(1.0, content)
                
                # Apply syntax highlighting
                self._highlight_syntax()
                
                file_size = len(content)
                file_size_str = f"{file_size / 1024:.1f} KB" if file_size > 1024 else f"{file_size} B"
                self.file_label.config(text=f"📄 {os.path.basename(filename)} ({file_size_str})",
                                      fg=ModernColors.TEXT_PRIMARY)
                
                self.current_file = filename
                self.update_status_bar(f"✅ Loaded: {os.path.basename(filename)}", "ready")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to open file:\n{str(e)}")
                self.update_status_bar(f"❌ Failed to open file", "error")
                
    def analyze_code(self):
        """Analyze code for vulnerabilities"""
        code = self.code_text.get(1.0, tk.END).strip()
        
        if not code:
            messagebox.showwarning("Warning", "Please enter or load code to analyze")
            return
            
        if not self.models_loaded:
            messagebox.showerror("Error", "Models not loaded. Please wait or restart.")
            return
        
        # Run analysis in background thread
        thread = threading.Thread(target=self.run_analysis, args=(code,), daemon=True)
        thread.start()
        
    def run_analysis(self, code):
        """Run vulnerability analysis"""
        start_time = datetime.now()
        try:
            # Update UI
            self.root.after(0, lambda: self.progress.start(10))
            self.root.after(0, lambda: self.analyze_btn.config(state=tk.DISABLED))
            self.root.after(0, lambda: self.update_status_bar("🔍 Analyzing code...", "analyzing"))
            
            # First, check if it's valid Python code
            import ast as ast_module
            is_valid_python = True
            syntax_error_msg = None
            
            try:
                ast_module.parse(code)
            except SyntaxError as e:
                is_valid_python = False
                syntax_error_msg = str(e)
            except Exception:
                is_valid_python = False
                syntax_error_msg = "Unable to parse - not valid Python code"
            
            # If not valid Python, show appropriate message
            if not is_valid_python:
                analysis_time = (datetime.now() - start_time).total_seconds()
                self.root.after(0, lambda: self.display_syntax_error_result(syntax_error_msg, analysis_time))
                return
            
            # Perform ML prediction
            is_vulnerable, vulnerability_score, urgency_score = predict_code(
                code, self.classifier, self.predictor, self.feature_extractor, threshold=0.5
            )
            
            # Detect vulnerability patterns
            vulnerabilities = detect_vulnerability_patterns(code)
            
            # Extract statistics
            stats = self.feature_extractor.extract_statistical_features(code)
            
            # Filter out syntax_error from vulnerabilities (shouldn't be treated as security issue)
            vulnerabilities = [v for v in vulnerabilities if v.get('type', '').lower() != 'syntax_error']
            
            # If patterns detected, boost vulnerability score
            if vulnerabilities and not is_vulnerable:
                is_vulnerable = True
                vulnerability_score = max(vulnerability_score, 0.85)
            
            # Calculate risk factors
            risk_factors = calculate_risk_factors(code, stats)
            
            # Build result dict
            ml_result = {
                'is_vulnerable': is_vulnerable,
                'confidence': vulnerability_score * 100,
                'urgency_score': urgency_score,
                'statistics': stats,
                'risk_factors': risk_factors
            }
            
            # Calculate analysis time
            analysis_time = (datetime.now() - start_time).total_seconds()
            
            # Update UI with results
            self.root.after(0, lambda: self.display_results(is_vulnerable, 
                                                           vulnerability_score * 100, 
                                                           urgency_score, ml_result, 
                                                           vulnerabilities,
                                                           analysis_time))
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed:\n{str(e)}"))
            self.root.after(0, lambda: self.update_status_bar(f"❌ Analysis failed", "error"))
        finally:
            self.root.after(0, lambda: self.progress.stop())
            self.root.after(0, lambda: self.analyze_btn.config(state=tk.NORMAL))
    
    def display_syntax_error_result(self, error_msg, analysis_time):
        """Display results when input is not valid Python code"""
        # Stop progress bar
        self.progress.stop()
        self.analyze_btn.config(state=tk.NORMAL)
        
        # Update status widgets - NOT VULNERABLE because it's not even code
        self.status_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.confidence_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.priority_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.time_label.config(text=f"{analysis_time:.2f}s", fg=ModernColors.PRIMARY_DARK)
        
        # Clear previous results
        for widget in self.results_container.winfo_children():
            widget.destroy()
        
        # Show syntax error message
        self._create_card_section(self.results_container, "⚠️ Invalid Python Code", [
            ("Status", "Not valid Python code"),
            ("Issue", "Syntax error detected"),
            ("Error", error_msg),
            ("Note", "Cannot analyze non-Python text for vulnerabilities")
        ], ModernColors.WARNING)
        
        # Explanation
        self._create_card_section(self.results_container, "ℹ️ What This Means", [
            ("Analysis Result", "Unable to perform security analysis"),
            ("Reason", "The input is not valid Python code"),
            ("Security Status", "N/A - Not applicable to non-code text"),
            ("Action Required", "Please provide valid Python code to analyze")
        ], ModernColors.INFO)
        
        # Footer
        footer = tk.Frame(self.results_container, bg=ModernColors.BG_PRIMARY, height=2)
        footer.pack(fill=tk.X, pady=10)
        
        timestamp = tk.Label(self.results_container, 
                            text=f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                            font=('Segoe UI', 8),
                            fg=ModernColors.TEXT_SECONDARY,
                            bg=ModernColors.BG_SECONDARY)
        timestamp.pack(pady=10)
        
        self.update_status_bar(f"⚠️ Invalid Python code detected", "error")
            
    def display_results(self, is_vulnerable, confidence, urgency, ml_result, vulnerabilities, analysis_time):
        """Display analysis results in UI with modern styling"""
        # Update status labels
        if is_vulnerable:
            status_text = "VULNERABLE"
            status_color = ModernColors.SEVERITY_CRITICAL
            priority = "CRITICAL" if urgency > 80 else "HIGH" if urgency > 60 else "MEDIUM"
        else:
            status_text = "SAFE"
            status_color = ModernColors.SUCCESS
            priority = "LOW"
        
        # Update status widgets (update text and color only)
        self.status_label.config(text=status_text, fg=status_color)
        self.confidence_label.config(text=f"{confidence:.1f}%", fg=ModernColors.PRIMARY_DARK)
        self.priority_label.config(text=priority, fg=status_color)
        self.time_label.config(text=f"{analysis_time:.2f}s", fg=ModernColors.PRIMARY_DARK)
        
        # Clear previous results
        for widget in self.results_container.winfo_children():
            widget.destroy()
        
        # Get data
        stats = ml_result.get('statistics', {})
        risk_factors = ml_result.get('risk_factors', {})
        
        # 1. CODE STATISTICS CARD
        self._create_card_section(self.results_container, "📊 Code Statistics", [
            ("Code Length", f"{stats.get('code_length', 0):,} characters"),
            ("Lines of Code", f"{stats.get('line_count', 0):,}"),
            ("SQL Keywords", str(stats.get('sql_keywords', 0))),
            ("Dangerous Functions", str(stats.get('dangerous_functions', 0))),
            ("String Operations", str(stats.get('string_operations', 0))),
            ("Network Operations", str(stats.get('network_operations', 0))),
            ("File Operations", str(stats.get('file_operations', 0)))
        ])
        
        # 2. VULNERABILITIES SECTION
        if vulnerabilities:
            vuln_title = f"⚠️ Vulnerabilities Detected ({len(vulnerabilities)})"
            vuln_frame = self._create_section_header(self.results_container, vuln_title, 
                                                     ModernColors.SEVERITY_CRITICAL)
            
            for i, vuln in enumerate(vulnerabilities, 1):
                self._create_vulnerability_card(vuln_frame, vuln, i)
        else:
            # If ML detected vulnerability but no specific patterns found
            if is_vulnerable:
                self._create_card_section(self.results_container, "⚠️ Security Assessment", [
                    ("Status", "Potentially vulnerable"),
                    ("Analysis Methods", "ML detection (pattern/AST found no specific issues)"),
                    ("ML Confidence", f"{confidence:.1f}%"),
                    ("Details", "ML model flagged this code as potentially risky"),
                    ("Note", "Manual code review recommended")
                ], ModernColors.WARNING)
            else:
                self._create_card_section(self.results_container, "✅ Security Assessment", [
                    ("Status", "No vulnerabilities detected"),
                    ("Analysis Methods", "Pattern matching + AST analysis + ML"),
                    ("Result", "Code appears secure")
                ], ModernColors.SUCCESS)
        
        # 3. RISK ASSESSMENT CARD
        if risk_factors:
            risk_items = [
                ("Code Complexity", risk_factors.get('code_complexity', 'UNKNOWN')),
                ("Dangerous Functions", risk_factors.get('dangerous_functions', 'UNKNOWN')),
                ("Input Handling", risk_factors.get('input_handling', 'UNKNOWN')),
                ("Error Handling", risk_factors.get('error_handling', 'UNKNOWN')),
                ("Authentication", risk_factors.get('authentication', 'UNKNOWN'))
            ]
            self._create_card_section(self.results_container, "🎯 Risk Assessment", risk_items)
        
        # 4. RECOMMENDATIONS SECTION
        recommendations = self._get_recommendations(is_vulnerable, vulnerabilities)
        if recommendations:
            self._create_recommendations_section(self.results_container, recommendations, is_vulnerable)
        
        # 5. FOOTER
        footer = tk.Frame(self.results_container, bg=ModernColors.BG_PRIMARY, height=2)
        footer.pack(fill=tk.X, pady=10)
        
        timestamp = tk.Label(self.results_container, 
                            text=f"Analysis completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                            font=('Segoe UI', 8),
                            fg=ModernColors.TEXT_SECONDARY,
                            bg=ModernColors.BG_SECONDARY)
        timestamp.pack(pady=10)
        
        self.update_status_bar(f"✅ Analysis complete ({analysis_time:.2f}s)", "ready")
    
    def _create_section_header(self, parent, title, color=None):
        """Create a section header"""
        frame = tk.Frame(parent, bg=ModernColors.BG_SECONDARY)
        frame.pack(fill=tk.X, pady=(15, 10))
        
        label = tk.Label(frame, text=title,
                        font=('Segoe UI', 12, 'bold'),
                        fg=color or ModernColors.PRIMARY_DARK,
                        bg=ModernColors.BG_SECONDARY,
                        anchor=tk.W)
        label.pack(fill=tk.X, padx=10)
        
        return frame
    
    def _create_card_section(self, parent, title, items, title_color=None):
        """Create a card-style section with items"""
        # Header
        header_frame = tk.Frame(parent, bg=ModernColors.BG_TERTIARY)
        header_frame.pack(fill=tk.X, pady=(10, 0))
        
        title_label = tk.Label(header_frame, text=title,
                              font=('Segoe UI', 11, 'bold'),
                              fg=title_color or ModernColors.PRIMARY_DARK,
                              bg=ModernColors.BG_TERTIARY,
                              anchor=tk.W)
        title_label.pack(fill=tk.X, padx=15, pady=10)
        
        # Content
        content_frame = tk.Frame(parent, bg=ModernColors.BG_SECONDARY, 
                                relief=tk.SOLID, borderwidth=1, 
                                highlightbackground=ModernColors.BORDER,
                                highlightthickness=1)
        content_frame.pack(fill=tk.X, pady=(0, 10))
        
        for label, value in items:
            row = tk.Frame(content_frame, bg=ModernColors.BG_SECONDARY)
            row.pack(fill=tk.X, padx=15, pady=5)
            
            label_widget = tk.Label(row, text=label + ":",
                                   font=('Segoe UI', 9),
                                   fg=ModernColors.TEXT_SECONDARY,
                                   bg=ModernColors.BG_SECONDARY,
                                   anchor=tk.W,
                                   width=20)
            label_widget.pack(side=tk.LEFT)
            
            value_widget = tk.Label(row, text=value,
                                   font=('Segoe UI', 9, 'bold'),
                                   fg=ModernColors.TEXT_PRIMARY,
                                   bg=ModernColors.BG_SECONDARY,
                                   anchor=tk.W)
            value_widget.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def _create_vulnerability_card(self, parent, vuln, index):
        """Create a detailed vulnerability card"""
        severity = vuln.get('severity', 'MEDIUM')
        vuln_type = vuln.get('type', 'Unknown')
        description = vuln.get('description', 'No description')
        line = vuln.get('line', 'N/A')
        detection = vuln.get('pattern', 'N/A')
        
        if detection == 'AST Analysis':
            detection = 'AST'
        else:
            detection = 'Pattern'
        
        # Color based on severity
        if severity == "CRITICAL":
            color = ModernColors.SEVERITY_CRITICAL
            icon = "🔴"
        elif severity == "HIGH":
            color = ModernColors.SEVERITY_HIGH
            icon = "🟠"
        elif severity == "MEDIUM":
            color = ModernColors.SEVERITY_MEDIUM
            icon = "🟡"
        else:
            color = ModernColors.SEVERITY_LOW
            icon = "🟢"
        
        # Card frame
        card = tk.Frame(parent, bg=ModernColors.BG_SECONDARY,
                       relief=tk.SOLID, borderwidth=1,
                       highlightbackground=color,
                       highlightthickness=2)
        card.pack(fill=tk.X, pady=5, padx=10)
        
        # Header with severity
        header = tk.Frame(card, bg=color)
        header.pack(fill=tk.X)
        
        header_label = tk.Label(header, text=f"{icon} #{index} {vuln_type}",
                               font=('Segoe UI', 10, 'bold'),
                               fg=ModernColors.TEXT_LIGHT,
                               bg=color)
        header_label.pack(anchor=tk.W, padx=10, pady=5)
        
        # Content
        content = tk.Frame(card, bg=ModernColors.BG_SECONDARY)
        content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Description
        desc_label = tk.Label(content, text=description,
                             font=('Segoe UI', 9),
                             fg=ModernColors.TEXT_PRIMARY,
                             bg=ModernColors.BG_SECONDARY,
                             wraplength=450,
                             justify=tk.LEFT)
        desc_label.pack(anchor=tk.W, pady=(0, 5))
        
        # Details row
        details = tk.Frame(content, bg=ModernColors.BG_SECONDARY)
        details.pack(fill=tk.X)
        
        tk.Label(details, text=f"Severity: {severity}",
                font=('Segoe UI', 8, 'bold'),
                fg=color,
                bg=ModernColors.BG_SECONDARY).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Label(details, text=f"Line: {line}",
                font=('Segoe UI', 8),
                fg=ModernColors.TEXT_SECONDARY,
                bg=ModernColors.BG_SECONDARY).pack(side=tk.LEFT, padx=(0, 15))
        
        tk.Label(details, text=f"Detection: {detection}",
                font=('Segoe UI', 8),
                fg=ModernColors.TEXT_SECONDARY,
                bg=ModernColors.BG_SECONDARY).pack(side=tk.LEFT)
    
    def _create_recommendations_section(self, parent, recommendations, is_vulnerable):
        """Create recommendations section"""
        # Header
        header_color = ModernColors.SEVERITY_CRITICAL if is_vulnerable else ModernColors.SUCCESS
        header_text = "💡 Recommendations" if is_vulnerable else "✅ Security Best Practices"
        
        header_frame = tk.Frame(parent, bg=header_color)
        header_frame.pack(fill=tk.X, pady=(15, 0))
        
        title_label = tk.Label(header_frame, text=header_text,
                              font=('Segoe UI', 11, 'bold'),
                              fg=ModernColors.TEXT_LIGHT,
                              bg=header_color)
        title_label.pack(fill=tk.X, padx=15, pady=10)
        
        # Content
        content_frame = tk.Frame(parent, bg=ModernColors.BG_SECONDARY,
                                relief=tk.SOLID, borderwidth=1,
                                highlightbackground=ModernColors.BORDER,
                                highlightthickness=1)
        content_frame.pack(fill=tk.X, pady=(0, 10))
        
        for category, items in recommendations:
            if category:
                cat_label = tk.Label(content_frame, text=category,
                                    font=('Segoe UI', 9, 'bold'),
                                    fg=ModernColors.PRIMARY_DARK,
                                    bg=ModernColors.BG_SECONDARY,
                                    anchor=tk.W)
                cat_label.pack(fill=tk.X, padx=15, pady=(10, 5))
            
            for item in items:
                item_frame = tk.Frame(content_frame, bg=ModernColors.BG_SECONDARY)
                item_frame.pack(fill=tk.X, padx=20, pady=2)
                
                bullet = tk.Label(item_frame, text="•",
                                 font=('Segoe UI', 9),
                                 fg=ModernColors.PRIMARY,
                                 bg=ModernColors.BG_SECONDARY)
                bullet.pack(side=tk.LEFT, padx=(0, 5))
                
                text = tk.Label(item_frame, text=item,
                               font=('Segoe UI', 9),
                               fg=ModernColors.TEXT_PRIMARY,
                               bg=ModernColors.BG_SECONDARY,
                               wraplength=400,
                               justify=tk.LEFT,
                               anchor=tk.W)
                text.pack(side=tk.LEFT, fill=tk.X, expand=True)
    
    def _get_recommendations(self, is_vulnerable, vulnerabilities):
        """Get recommendations based on vulnerabilities"""
        recommendations = []
        
        if is_vulnerable:
            vuln_types = set(v.get('type', '') for v in vulnerabilities)
            
            if any('SQL Injection' in t for t in vuln_types):
                recommendations.append(("SQL Injection Prevention:", [
                    "Use parameterized queries instead of string concatenation",
                    "Example: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
                    "Validate and sanitize all user inputs"
                ]))
            
            if any('Command Injection' in t for t in vuln_types):
                recommendations.append(("Command Injection Prevention:", [
                    "Avoid shell=True in subprocess calls",
                    "Use argument lists: subprocess.run(['ping', host])",
                    "Validate and whitelist allowed commands"
                ]))
            
            if any('Code Injection' in t or 'eval' in t.lower() or 'exec' in t.lower() for t in vuln_types):
                recommendations.append(("Code Injection Prevention:", [
                    "Never use eval() or exec() with user input",
                    "Use ast.literal_eval() for safe data parsing",
                    "Implement strict input validation"
                ]))
            
            if any('XSS' in t or 'Cross-Site' in t for t in vuln_types):
                recommendations.append(("XSS Prevention:", [
                    "Use template engines with auto-escaping",
                    "Sanitize all user input before rendering",
                    "Implement Content Security Policy (CSP)"
                ]))
            
            if any('Path Traversal' in t for t in vuln_types):
                recommendations.append(("Path Traversal Prevention:", [
                    "Validate file paths against allowed directories",
                    "Use os.path.abspath() and check path prefix",
                    "Never concatenate user input with file paths"
                ]))
            
            recommendations.append(("General Security:", [
                "Review and fix all detected vulnerabilities immediately",
                "Implement comprehensive input validation",
                "Follow OWASP Top 10 guidelines",
                "Keep all dependencies updated"
            ]))
        else:
            recommendations.append(("", [
                "Code appears secure - continue following best practices",
                "Perform regular security audits",
                "Keep dependencies up to date",
                "Monitor for new vulnerability patterns",
                "Use security linters in CI/CD pipeline"
            ]))
        
        return recommendations
        
    def clear_all(self):
        """Clear all inputs and results"""
        self.code_text.delete(1.0, tk.END)
        
        # Clear results container
        for widget in self.results_container.winfo_children():
            widget.destroy()
        
        self.status_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.confidence_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.priority_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.time_label.config(text="N/A", fg=ModernColors.TEXT_SECONDARY)
        self.file_label.config(text="📄 No file loaded", fg=ModernColors.TEXT_SECONDARY)
        
        self.update_status_bar("✅ Cleared", "ready")
        
    def select_all_code(self):
        """Select all code in editor"""
        self.code_text.tag_add(tk.SEL, "1.0", tk.END)
        self.code_text.event_generate("<<Copy>>")
        
    def update_status_bar(self, message, status_type="ready"):
        """Update status bar with styled message"""
        if status_type == "loading":
            bg = ModernColors.INFO
        elif status_type == "analyzing":
            bg = ModernColors.WARNING
        elif status_type == "error":
            bg = ModernColors.ERROR
        else:  # ready
            bg = ModernColors.PRIMARY_DARK
        
        self.status_bar.config(text=message, bg=bg)
        
    def show_about(self):
        """Show modern about dialog"""
        about_window = tk.Toplevel(self.root)
        about_window.title("About VulneraPred")
        about_window.geometry("500x400")
        about_window.resizable(False, False)
        
        # Header
        header = tk.Frame(about_window, bg=ModernColors.PRIMARY, height=60)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        header_label = tk.Label(header, text="🛡️ VulneraPred",
                               font=('Segoe UI', 18, 'bold'),
                               fg=ModernColors.TEXT_LIGHT,
                               bg=ModernColors.PRIMARY)
        header_label.pack(pady=15)
        
        # Content
        content = tk.Frame(about_window, bg=ModernColors.BG_SECONDARY)
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        info_text = """Version 1.0

A modern AI-powered security analysis tool that detects 
vulnerabilities in Python code using machine learning 
and static analysis.

FEATURES:
• ML-based vulnerability detection
• AST analysis for structural vulnerabilities
• Pattern matching for common security issues
• Urgency scoring and prioritization
• Detailed vulnerability reports
• Modern, intuitive user interface

TECHNOLOGY:
• Python Tkinter - Cross-platform GUI
• Machine Learning - Scikit-learn
• Static Analysis - AST parsing
• Real-time Analysis - Threading

Developed for CS Courses - Introduction to AI
Security & ML Integration Course"""
        
        text_widget = tk.Label(content, text=info_text,
                              font=('Segoe UI', 9),
                              fg=ModernColors.TEXT_PRIMARY,
                              bg=ModernColors.BG_SECONDARY,
                              justify=tk.LEFT,
                              wraplength=450)
        text_widget.pack()
        
        # Close button
        close_btn = tk.Button(about_window, text="Close",
                             bg=ModernColors.PRIMARY,
                             fg=ModernColors.TEXT_LIGHT,
                             font=('Segoe UI', 10, 'bold'),
                             relief=tk.FLAT,
                             padx=20,
                             pady=8,
                             command=about_window.destroy,
                             cursor="hand2",
                             activebackground=ModernColors.PRIMARY_DARK)
        close_btn.pack(pady=(0, 10))
        
    def show_documentation(self):
        """Show documentation dialog"""
        doc_window = tk.Toplevel(self.root)
        doc_window.title("Documentation - VulneraPred")
        doc_window.geometry("600x500")
        
        # Header
        header = tk.Frame(doc_window, bg=ModernColors.PRIMARY_LIGHT, height=50)
        header.pack(fill=tk.X)
        header.pack_propagate(False)
        
        header_label = tk.Label(header, text="📖 Documentation & Help",
                               font=('Segoe UI', 14, 'bold'),
                               fg=ModernColors.PRIMARY_DARK,
                               bg=ModernColors.PRIMARY_LIGHT)
        header_label.pack(pady=10)
        
        # Content
        content = tk.Frame(doc_window, bg=ModernColors.BG_SECONDARY)
        content.pack(fill=tk.BOTH, expand=True)
        
        doc_text = scrolledtext.ScrolledText(content,
                                            wrap=tk.WORD,
                                            font=('Segoe UI', 9),
                                            bg=ModernColors.BG_SECONDARY,
                                            fg=ModernColors.TEXT_PRIMARY,
                                            relief=tk.FLAT,
                                            borderwidth=0)
        doc_text.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)
        
        documentation = """GETTING STARTED

1. OPENING CODE
   • Click "📁 Open File" to select a Python file
   • Or paste code directly into the editor
   • Supported file types: .py, .txt, and others

2. ANALYZING CODE
   • Click "🔍 Analyze Code" to start analysis
   • The system will scan for vulnerabilities
   • Results appear in the right panel

3. INTERPRETING RESULTS
   Status Codes:
   🔴 VULNERABLE - Vulnerabilities detected
   🟢 SAFE - No vulnerabilities found
   
   Priority Levels:
   🔴 CRITICAL - Immediate action required
   🟠 HIGH - Should be fixed soon
   🟡 MEDIUM - Should be addressed
   🟢 LOW - Minor issues

4. SECURITY ANALYSIS
   The system checks for:
   • SQL Injection vulnerabilities
   • Command Injection risks
   • Use of dangerous functions (eval, exec)
   • Input validation issues
   • Code pattern anomalies
   • Risk factor calculations

5. KEYBOARD SHORTCUTS
   Ctrl+O - Open file
   Ctrl+L - Clear all
   Ctrl+Q - Exit
   Ctrl+A - Select all code

RECOMMENDATIONS
   • Review all CRITICAL vulnerabilities
   • Fix vulnerabilities promptly
   • Follow OWASP guidelines
   • Keep code clean and secure
   • Perform regular security audits"""
        
        doc_text.insert(1.0, documentation)
        doc_text.config(state=tk.DISABLED)


def main():
    """Main entry point"""
    root = tk.Tk()
    app = ModernVulnerabilityDetectorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
