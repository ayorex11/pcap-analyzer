from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
    QProgressBar, QGroupBox, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QComboBox, QCheckBox, QSpinBox, QDoubleSpinBox, QLineEdit,
    QSplitter, QFrame, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette, QBrush
import pyqtgraph as pg


class CollapsibleGroupBox(QGroupBox):
    """A group box that can be collapsed/expanded"""
    
    def __init__(self, title="", parent=None):
        super().__init__(title, parent)
        self.setCheckable(True)
        self.setChecked(True)
        self.toggled.connect(self._on_toggled)
    
    def _on_toggled(self, checked):
        """Handle collapse/expand"""
        for child in self.children():
            if isinstance(child, QWidget) and child != self.findChild(QPushButton):
                child.setVisible(checked)


class ProgressWidget(QWidget):
    """Custom progress widget with label and bar"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        
        self.label = QLabel("Ready")
        self.progress = QProgressBar()
        
        layout.addWidget(self.label)
        layout.addWidget(self.progress, 1)
    
    def set_progress(self, value: int, text: str = None):
        """Update progress"""
        self.progress.setValue(value)
        if text:
            self.label.setText(text)


class ClickableLabel(QLabel):
    """Label that emits clicked signal"""
    
    clicked = pyqtSignal()
    
    def __init__(self, text="", parent=None):
        super().__init__(text, parent)
    
    def mousePressEvent(self, event):
        self.clicked.emit()
        super().mousePressEvent(event)


class EnhancedTableWidget(QTableWidget):
    """Enhanced table widget with sorting and styling"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        # Configure header
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionsMovable(True)
        
        # Set style
        self.setStyleSheet("""
            QTableWidget {
                border: 1px solid #444;
                border-radius: 3px;
                background-color: #1e1e1e;
                alternate-background-color: #252525;
            }
            QTableWidget::item {
                padding: 5px;
            }
            QTableWidget::item:selected {
                background-color: #4da6ff;
                color: white;
            }
        """)
    
    def add_row(self, data: list):
        """Add a row with data"""
        row = self.rowCount()
        self.insertRow(row)
        
        for col, value in enumerate(data):
            item = QTableWidgetItem(str(value))
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.setItem(row, col, item)
    
    def clear_table(self):
        """Clear all rows"""
        self.setRowCount(0)


class TreeTableWidget(QTreeWidget):
    """Tree widget with table-like columns"""
    
    def __init__(self, headers: list, parent=None):
        super().__init__(parent)
        self.setHeaderLabels(headers)
        self.setAlternatingRowColors(True)
        self.setColumnCount(len(headers))
        
        # Configure header
        header = self.header()
        header.setStretchLastSection(True)
        header.setSectionsMovable(True)
    
    def add_item(self, parent, data: list, icon=None):
        """Add an item with data"""
        item = QTreeWidgetItem(parent, data) if parent else QTreeWidgetItem(self, data)
        if icon:
            item.setIcon(0, icon)
        return item
    
    def clear_tree(self):
        """Clear all items"""
        self.clear()


class StatsWidget(QWidget):
    """Widget for displaying statistics with progress bars"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)
        
        self.stats = {}
    
    def add_stat(self, label: str, value: int, max_value: int = 100, color: str = "#3498db"):
        """Add a statistic with progress bar"""
        if label in self.stats:
            return
        
        stat_widget = QWidget()
        stat_layout = QHBoxLayout(stat_widget)
        stat_layout.setContentsMargins(0, 0, 0, 0)
        
        # Label
        label_widget = QLabel(label)
        label_widget.setFixedWidth(150)
        
        # Value
        value_widget = QLabel(str(value))
        value_widget.setFixedWidth(80)
        value_widget.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Progress bar
        progress = QProgressBar()
        progress.setMaximum(max_value)
        progress.setValue(value)
        progress.setTextVisible(False)
        progress.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #444;
                border-radius: 3px;
                background: #2c3e50;
            }}
            QProgressBar::chunk {{
                background-color: {color};
                border-radius: 2px;
            }}
        """)
        
        stat_layout.addWidget(label_widget)
        stat_layout.addWidget(value_widget)
        stat_layout.addWidget(progress, 1)
        
        self.stats[label] = {
            'widget': stat_widget,
            'progress': progress,
            'value': value_widget
        }
        
        self.layout.addWidget(stat_widget)
    
    def update_stat(self, label: str, value: int):
        """Update a statistic"""
        if label in self.stats:
            self.stats[label]['progress'].setValue(value)
            self.stats[label]['value'].setText(str(value))


class GraphWidget(QWidget):
    """Widget for displaying graphs"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        
        # Create plot widget
        self.plot_widget = pg.PlotWidget()
        self.plot_widget.setBackground('#1e1e1e')
        self.plot_widget.showGrid(x=True, y=True, alpha=0.3)
        
        # Set axis colors
        self.plot_widget.getAxis('left').setPen(pg.mkPen(color='#ffffff', width=1))
        self.plot_widget.getAxis('bottom').setPen(pg.mkPen(color='#ffffff', width=1))
        
        self.layout.addWidget(self.plot_widget)
    
    def plot_bar_chart(self, data: dict, title: str = ""):
        """Plot a bar chart"""
        self.plot_widget.clear()
        
        if not data:
            return
        
        keys = list(data.keys())
        values = list(data.values())
        
        # Create bar chart
        bg = pg.BarGraphItem(x=range(len(keys)), height=values, width=0.6, brush='#3498db')
        self.plot_widget.addItem(bg)
        
        # Set labels
        self.plot_widget.setTitle(title, color='#ffffff', size='12pt')
        self.plot_widget.setLabel('left', 'Count')
        self.plot_widget.setLabel('bottom', 'Category')
        
        # Set x-axis ticks
        self.plot_widget.getAxis('bottom').setTicks([[(i, str(keys[i])[:20]) for i in range(len(keys))]])
    
    def plot_line_chart(self, x_data: list, y_data: list, title: str = ""):
        """Plot a line chart"""
        self.plot_widget.clear()
        
        if not x_data or not y_data:
            return
        
        # Create line plot
        self.plot_widget.plot(x_data, y_data, pen=pg.mkPen(color='#e74c3c', width=2))
        
        # Set labels
        self.plot_widget.setTitle(title, color='#ffffff', size='12pt')
        self.plot_widget.setLabel('left', 'Value')
        self.plot_widget.setLabel('bottom', 'Time')


class ThreatIndicatorWidget(QWidget):
    """Widget for displaying threat indicators"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(5, 5, 5, 5)
        
        self.threats = {}
    
    def add_threat(self, category: str, count: int, severity: str = "MEDIUM"):
        """Add a threat indicator"""
        if category in self.threats:
            return
        
        threat_widget = QWidget()
        threat_layout = QHBoxLayout(threat_widget)
        threat_layout.setContentsMargins(10, 5, 10, 5)
        
        # Severity indicator
        indicator = QLabel("●")
        indicator.setFixedWidth(20)
        
        if severity == "HIGH":
            indicator.setStyleSheet("color: #e74c3c; font-size: 16px;")
        elif severity == "MEDIUM":
            indicator.setStyleSheet("color: #f39c12; font-size: 16px;")
        else:
            indicator.setStyleSheet("color: #27ae60; font-size: 16px;")
        
        # Category label
        category_label = QLabel(category.replace('_', ' ').title())
        category_label.setStyleSheet("font-weight: bold;")
        
        # Count badge
        count_label = QLabel(str(count))
        count_label.setStyleSheet("""
            background-color: #2c3e50;
            color: white;
            padding: 2px 8px;
            border-radius: 10px;
            font-weight: bold;
        """)
        count_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        count_label.setFixedWidth(40)
        
        threat_layout.addWidget(indicator)
        threat_layout.addWidget(category_label, 1)
        threat_layout.addWidget(count_label)
        
        self.threats[category] = threat_widget
        self.layout.addWidget(threat_widget)
    
    def clear_threats(self):
        """Clear all threat indicators"""
        for widget in self.threats.values():
            widget.deleteLater()
        self.threats.clear()


class FilterWidget(QWidget):
    """Widget for filtering data"""
    
    filter_changed = pyqtSignal(dict)
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        
        # Protocol filter
        self.protocol_filter = QComboBox()
        self.protocol_filter.addItems(["All", "TCP", "UDP", "ICMP", "DNS", "HTTP"])
        self.protocol_filter.currentTextChanged.connect(self._emit_filter)
        
        # IP filter
        self.ip_filter = QLineEdit()
        self.ip_filter.setPlaceholderText("Filter by IP...")
        self.ip_filter.textChanged.connect(self._emit_filter)
        
        # Port filter
        self.port_filter = QLineEdit()
        self.port_filter.setPlaceholderText("Filter by port...")
        self.port_filter.textChanged.connect(self._emit_filter)
        
        # Threat level filter
        self.threat_filter = QComboBox()
        self.threat_filter.addItems(["All", "High", "Medium", "Low"])
        self.threat_filter.currentTextChanged.connect(self._emit_filter)
        
        self.layout.addWidget(QLabel("Protocol:"))
        self.layout.addWidget(self.protocol_filter)
        self.layout.addWidget(QLabel("IP:"))
        self.layout.addWidget(self.ip_filter)
        self.layout.addWidget(QLabel("Port:"))
        self.layout.addWidget(self.port_filter)
        self.layout.addWidget(QLabel("Threat:"))
        self.layout.addWidget(self.threat_filter)
    
    def _emit_filter(self):
        """Emit filter changed signal"""
        filters = {
            'protocol': self.protocol_filter.currentText(),
            'ip': self.ip_filter.text(),
            'port': self.port_filter.text(),
            'threat': self.threat_filter.currentText()
        }
        self.filter_changed.emit(filters)
    
    def get_filters(self) -> dict:
        """Get current filter values"""
        return {
            'protocol': self.protocol_filter.currentText(),
            'ip': self.ip_filter.text(),
            'port': self.port_filter.text(),
            'threat': self.threat_filter.currentText()
        }