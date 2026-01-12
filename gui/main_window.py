from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QFileDialog, QProgressBar,
    QTabWidget, QMessageBox, QTextEdit, QSplitter,
    QTreeWidget, QTreeWidgetItem, QTableWidget,
    QTableWidgetItem, QHeaderView, QGroupBox,
    QComboBox, QCheckBox, QLineEdit, QSpinBox,
    QApplication, QStyleFactory
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt6.QtGui import QFont, QPalette, QColor, QIcon
import os
import sys
from collections import Counter
from core.analyzer import PCAPAnalyzer
from gui.analysis_tab import AnalysisTabs
from utils.config import Config
from utils.logger import setup_logger
from datetime import datetime

class AnalysisThread(QThread):
    """Thread for running PCAP analysis"""
    progress_update = pyqtSignal(str, int, bool)
    analysis_complete = pyqtSignal(dict)
    analysis_error = pyqtSignal(str)
    
    def __init__(self, filename: str, quick_mode: bool = False, analysis_options: dict = None):
        super().__init__()
        self.filename = filename
        self.quick_mode = quick_mode
        self.analysis_options = analysis_options or {}
        self.analyzer = PCAPAnalyzer(verbose=True, quick_mode=quick_mode)
    
    def run(self):
        try:
            # Connect progress callback
            self.analyzer.set_progress_callback(self._progress_callback)
            
            # Run analysis
            results = self.analyzer.analyze(self.filename)
            
            if results:
                # Filter results based on options
                results = self._filter_results(results)
                self.analysis_complete.emit(results)
            else:
                self.analysis_error.emit("Analysis failed")
                
        except Exception as e:
            self.analysis_error.emit(str(e))
    
    def _filter_results(self, results: dict) -> dict:
        """Filter results based on analysis options"""
        # If DNS analysis is disabled, remove DNS results
        if not self.analysis_options.get('dns_analysis', True):
            results['dns_analysis'] = {
                'total_queries': 0,
                'total_responses': 0,
                'query_types': {},
                'response_codes': {},
                'tld_distribution': {},
                'suspicious_queries': [],
                'top_queried_domains': [],
                'dns_tunneling_suspects': [],
                'fast_flux_suspects': [],
                'query_length_stats': {},
                'unique_domains': 0,
                'domains_with_multiple_ips': []
            }
        
        # If HTTP analysis is disabled, remove HTTP results
        if not self.analysis_options.get('http_analysis', True):
            results['http_analysis'] = {
                'requests': [],
                'responses': [],
                'hosts': {},
                'user_agents': {},
                'status_codes': {},
                'methods': {},
                'suspicious_requests': []
            }
        
        # If security scan is disabled, remove security findings
        if not self.analysis_options.get('security_scan', True):
            results['suspicious_activities'] = {}
            results['beacon_analysis'] = []
        
        # Filter protocols based on TCP/UDP options
        if not self.analysis_options.get('tcp_analysis', True):
            results['ports']['tcp'] = Counter()
            results['tcp_flags'] = Counter()
        
        if not self.analysis_options.get('udp_analysis', True):
            results['ports']['udp'] = Counter()
        
        return results
    
    def _progress_callback(self, message: str, progress: int, is_error: bool = False):
        """Handle progress updates from analyzer"""
        self.progress_update.emit(message, progress, is_error)


class MainWindow(QMainWindow):
    """Main application window"""
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.logger = setup_logger()
        self.current_file = None
        self.analysis_results = None
        self.analysis_thread = None
        
        self.init_ui()
        self.apply_styles()
    
    def init_ui(self):
        """Initialize the user interface"""
        self.setWindowTitle("Advanced PCAP Analyzer v3.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Top toolbar
        toolbar = self.create_toolbar()
        main_layout.addWidget(toolbar)
        
        # Main content area
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left panel - file info and controls
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - analysis results
        self.tab_widget = AnalysisTabs()
        splitter.addWidget(self.tab_widget)
        
        splitter.setSizes([300, 1100])
        main_layout.addWidget(splitter)
        
        # Status bar
        self.status_bar = self.statusBar()
        self.progress_bar = QProgressBar()
        self.progress_bar.setMaximumWidth(200)
        self.progress_bar.setVisible(False)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        # Apply dark theme
        self.setStyleSheet(self.load_stylesheet())
    
    def create_toolbar(self):
        """Create the main toolbar"""
        toolbar = QWidget()
        layout = QHBoxLayout(toolbar)
        layout.setContentsMargins(5, 5, 5, 5)
        
        # File selection
        self.file_label = QLabel("No file selected")
        self.file_label.setStyleSheet("padding: 5px; border: 1px solid #444; border-radius: 3px;")
        
        browse_btn = QPushButton("📁 Browse PCAP")
        browse_btn.setFixedWidth(120)
        browse_btn.clicked.connect(self.browse_file)
        
        # Quick mode toggle
        self.quick_mode_cb = QCheckBox("Quick Mode")
        self.quick_mode_cb.setToolTip("Faster analysis with basic statistics")
        
        # Analysis button
        self.analyze_btn = QPushButton("🔍 Analyze")
        self.analyze_btn.setFixedWidth(100)
        self.analyze_btn.setEnabled(False)
        self.analyze_btn.clicked.connect(self.start_analysis)
        
        # Export button
        self.export_btn = QPushButton("💾 Export")
        self.export_btn.setFixedWidth(100)
        self.export_btn.setEnabled(False)
        self.export_btn.clicked.connect(self.export_results)
        
        layout.addWidget(QLabel("File:"))
        layout.addWidget(self.file_label, 1)
        layout.addWidget(browse_btn)
        layout.addWidget(self.quick_mode_cb)
        layout.addWidget(self.analyze_btn)
        layout.addWidget(self.export_btn)
        layout.addStretch()
        
        return toolbar
    
    def create_left_panel(self):
        """Create left panel with file info and analysis options"""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(10, 10, 10, 10)
        
        # File info group
        file_group = QGroupBox("File Information")
        file_layout = QVBoxLayout()
        
        self.file_info_tree = QTreeWidget()
        self.file_info_tree.setHeaderHidden(True)
        self.file_info_tree.setColumnCount(2)
        self.file_info_tree.setColumnWidth(0, 150)
        file_layout.addWidget(self.file_info_tree)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Analysis options group
        options_group = QGroupBox("Analysis Options")
        options_layout = QVBoxLayout()
        
        # Protocol selection
        self.tcp_cb = QCheckBox("TCP Analysis")
        self.tcp_cb.setChecked(True)
        self.udp_cb = QCheckBox("UDP Analysis")
        self.udp_cb.setChecked(True)
        self.dns_cb = QCheckBox("DNS Deep Analysis")
        self.dns_cb.setChecked(True)
        self.http_cb = QCheckBox("HTTP Analysis")
        self.http_cb.setChecked(True)
        self.security_cb = QCheckBox("Security Scan")
        self.security_cb.setChecked(True)
        
        options_layout.addWidget(self.tcp_cb)
        options_layout.addWidget(self.udp_cb)
        options_layout.addWidget(self.dns_cb)
        options_layout.addWidget(self.http_cb)
        options_layout.addWidget(self.security_cb)
        options_layout.addStretch()
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Statistics group
        stats_group = QGroupBox("Quick Stats")
        stats_layout = QVBoxLayout()
        
        self.stats_text = QTextEdit()
        self.stats_text.setReadOnly(True)
        self.stats_text.setMaximumHeight(200)
        self.stats_text.setStyleSheet("font-family: monospace;")
        
        stats_layout.addWidget(self.stats_text)
        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)
        
        layout.addStretch()
        
        return panel
    
    def browse_file(self):
        """Open file dialog to select PCAP file"""
        filename, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng *.cap);;All Files (*.*)"
        )
        
        if filename:
            self.current_file = filename
            self.file_label.setText(os.path.basename(filename))
            self.analyze_btn.setEnabled(True)
            self.update_file_info(filename)
    
    def update_file_info(self, filename):
        """Update file information display"""
        self.file_info_tree.clear()
        
        try:
            file_size = os.path.getsize(filename)
            file_stats = os.stat(filename)
            modified = datetime.fromtimestamp(file_stats.st_mtime)
            
            items = [
                ("Size", f"{file_size / (1024*1024):.2f} MB"),
                ("Modified", modified.strftime("%Y-%m-%d %H:%M:%S")),
                ("Path", filename)
            ]
            
            for key, value in items:
                item = QTreeWidgetItem([key, value])
                self.file_info_tree.addTopLevelItem(item)
                
        except Exception as e:
            self.logger.error(f"Error getting file info: {e}")
    
    def start_analysis(self):
        """Start PCAP analysis in separate thread"""
        if not self.current_file:
            QMessageBox.warning(self, "No File", "Please select a PCAP file first.")
            return
        
        # Disable UI during analysis
        self.analyze_btn.setEnabled(False)
        self.export_btn.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        
        # Clear previous results
        self.tab_widget.clear_all()
        self.stats_text.clear()

        analysis_options = {
            'tcp_analysis': self.tcp_cb.isChecked(),
            'udp_analysis': self.udp_cb.isChecked(),
            'dns_analysis': self.dns_cb.isChecked(),
            'http_analysis': self.http_cb.isChecked(),
            'security_scan': self.security_cb.isChecked()
        }
        
        # Start analysis thread
        self.analysis_thread = AnalysisThread(
            self.current_file,
            quick_mode=self.quick_mode_cb.isChecked(),
            analysis_options=analysis_options
        )
        
        self.analysis_thread.progress_update.connect(self.update_progress)
        self.analysis_thread.analysis_complete.connect(self.on_analysis_complete)
        self.analysis_thread.analysis_error.connect(self.on_analysis_error)
        
        self.analysis_thread.start()
        self.analysis_timeout = QTimer()
        self.analysis_timeout.setSingleShot(True)
        self.analysis_timeout.timeout.connect(self.on_analysis_error)
        self.analysis_timeout.start(300000)

    def on_analysis_timeout(self):
        """Handle analysis timeout"""
        if self.analysis_thread and self.analysis_thread.isRunning():
            reply = QMessageBox.question(
                self,
                "Analysis Taking Too Long",
                "The analysis is taking longer than expected. Do you want to continue waiting?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.No:
                self.analysis_thread.terminate()
                self.on_analysis_error("Analysis Cancelled by User")
            else:
                self.analysis_timeout.start(300000)    
    def update_progress(self, message: str, progress: int, is_error: bool = False):
        """Update progress bar and status"""
        self.progress_bar.setValue(progress)
        self.status_bar.showMessage(message)
        
        if is_error:
            self.status_bar.showMessage(f"Error: {message}", 5000)
    
    def on_analysis_complete(self, results):
        """Handle analysis completion"""
        if hasattr(self, 'analysis_timeout'):
            self.analysis_timeout.stop()
            
        self.analysis_results = results
        
        # Enable export button
        self.export_btn.setEnabled(True)
        
        # Reset progress
        self.progress_bar.setVisible(False)
        self.analyze_btn.setEnabled(True)
        
        # Update tabs with results
        self.tab_widget.update_all_tabs(results)
        
        # Show quick stats
        self.show_quick_stats(results)
        
        # Show completion message
        self.status_bar.showMessage(f"Analysis complete: {results['total_packets']:,} packets", 5000)
        
        # Log completion
        self.logger.info(f"Analysis completed for {self.current_file}")
    
    def on_analysis_error(self, error_message):
        """Handle analysis errors"""
        QMessageBox.critical(self, "Analysis Error", f"Error during analysis:\n{error_message}")
        
        # Reset UI
        self.analyze_btn.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_bar.showMessage(f"Error: {error_message}", 5000)
        
        self.logger.error(f"Analysis error: {error_message}")
    
    def show_quick_stats(self, results):
        """Display quick statistics"""
        stats_text = f"""
📊 QUICK STATISTICS
{'='*40}
Total Packets: {results['total_packets']:,}

Protocol Distribution:
{'-'*30}"""
        
        for proto, count in results['protocols'].most_common():
            percent = (count / results['total_packets']) * 100
            stats_text += f"\n  {proto}: {count:,} ({percent:.1f}%)"
        
        if results.get('timeline'):
            timeline = results['timeline']
            stats_text += f"\n\n⏰ Timeline:"
            stats_text += f"\n  Duration: {timeline.get('duration_seconds', 0):.2f}s"
            stats_text += f"\n  Rate: {timeline.get('packets_per_second', 0):.1f} pkt/s"
        
        if results.get('dns_analysis'):
            dns = results['dns_analysis']
            stats_text += f"\n\n🔍 DNS Analysis:"
            stats_text += f"\n  Queries: {dns.get('total_queries', 0):,}"
            stats_text += f"\n  Unique Domains: {dns.get('unique_domains', 0):,}"
        
        self.stats_text.setText(stats_text)
    
    def export_results(self):
        """Export analysis results"""
        if not self.analysis_results:
            QMessageBox.warning(self, "No Data", "No analysis results to export.")
            return
        
        # Get export format from user
        formats = ["JSON", "CSV", "HTML", "All"]
        format_dialog = QComboBox()
        format_dialog.addItems(formats)
        
        msg = QMessageBox(self)
        msg.setWindowTitle("Export Results")
        msg.setText("Select export format:")
        msg.layout().addWidget(format_dialog)
        msg.setStandardButtons(QMessageBox.StandardButton.Ok | QMessageBox.StandardButton.Cancel)
        
        if msg.exec() == QMessageBox.StandardButton.Ok:
            export_format = format_dialog.currentText()
            self.tab_widget.export_results(self.analysis_results, export_format, self.current_file)
    
    def load_stylesheet(self):
        """Load application stylesheet"""
        return """
        QMainWindow {
            background-color: #2b2b2b;
        }
        
        QWidget {
            background-color: #2b2b2b;
            color: #ffffff;
            font-family: 'Segoe UI', Arial;
        }
        
        QPushButton {
            background-color: #3c3c3c;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 8px 15px;
            font-weight: bold;
        }
        
        QPushButton:hover {
            background-color: #4a4a4a;
            border-color: #666;
        }
        
        QPushButton:pressed {
            background-color: #2a2a2a;
        }
        
        QPushButton:disabled {
            background-color: #333;
            color: #666;
        }
        
        QGroupBox {
            border: 2px solid #444;
            border-radius: 5px;
            margin-top: 10px;
            font-weight: bold;
        }
        
        QGroupBox::title {
            subcontrol-origin: margin;
            left: 10px;
            padding: 0 5px 0 5px;
            color: #4da6ff;
        }
        
        QTreeWidget, QTableWidget, QTextEdit {
            background-color: #1e1e1e;
            border: 1px solid #444;
            border-radius: 3px;
            color: #ffffff;
        }
        
        QHeaderView::section {
            background-color: #3c3c3c;
            padding: 5px;
            border: 1px solid #555;
        }
        
        QTabWidget::pane {
            border: 1px solid #444;
            background-color: #2b2b2b;
        }
        
        QTabBar::tab {
            background-color: #3c3c3c;
            padding: 8px 15px;
            margin-right: 2px;
            border: 1px solid #444;
            border-bottom: none;
        }
        
        QTabBar::tab:selected {
            background-color: #4da6ff;
            color: white;
        }
        
        QTabBar::tab:hover:!selected {
            background-color: #4a4a4a;
        }
        
        QProgressBar {
            border: 1px solid #444;
            border-radius: 3px;
            text-align: center;
        }
        
        QProgressBar::chunk {
            background-color: #4da6ff;
            border-radius: 2px;
        }
        
        QCheckBox {
            spacing: 8px;
        }
        
        QCheckBox::indicator {
            width: 16px;
            height: 16px;
        }
        
        QLabel {
            color: #ffffff;
        }
        
        QStatusBar {
            background-color: #3c3c3c;
            color: #aaaaaa;
        }
        """
    
    def apply_styles(self):
        """Apply application styles"""
        app = QApplication.instance()
        if app:
            app.setStyle(QStyleFactory.create("Fusion"))
            
            # Set palette for dark theme
            palette = QPalette()
            palette.setColor(QPalette.ColorRole.Window, QColor(43, 43, 43))
            palette.setColor(QPalette.ColorRole.WindowText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 30))
            palette.setColor(QPalette.ColorRole.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ToolTipBase, Qt.GlobalColor.black)
            palette.setColor(QPalette.ColorRole.ToolTipText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Text, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ColorRole.ButtonText, Qt.GlobalColor.white)
            palette.setColor(QPalette.ColorRole.BrightText, Qt.GlobalColor.red)
            palette.setColor(QPalette.ColorRole.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.ColorRole.HighlightedText, Qt.GlobalColor.black)
            
            app.setPalette(palette)