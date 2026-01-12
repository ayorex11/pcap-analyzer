import sys
import os
import argparse
from datetime import datetime

from core.analyzer import PCAPAnalyzer
from core.exporter import ReportExporter

# GUI imports
try:
    from PyQt6.QtWidgets import QApplication
    from gui.main_window import MainWindow
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False


def run_cli_analysis(args):
    """Run analysis in CLI mode"""
    print(f"\n{'='*80}")
    print(f"🔍 Starting PCAP Analysis v3.0 (CLI Mode)")
    print(f"{'='*80}")
    print(f"📁 File: {args.pcap_file}")
    
    analyzer = PCAPAnalyzer(args.pcap_file, verbose=args.verbose, quick_mode=args.quick)
    
    if not analyzer.load_packets():
        sys.exit(1)
    
    if args.verbose:
        print("\n🔬 Analyzing packets...")
    
    stats = analyzer.analyze()
    
    if not stats:
        print("❌ Error: Analysis failed")
        sys.exit(1)
    
    # Print statistics
    analyzer.print_statistics()
    
    if args.security_scan:
        analyzer.print_security_findings()
    
    # Export results
    if args.export:
        print(f"\n📤 Exporting results...")
        base_name = os.path.splitext(args.pcap_file)[0]
        exporter = ReportExporter(base_name)
        
        if args.export == 'all':
            exporter.export_json(stats)
            exporter.export_csv(stats)
            exporter.export_html(stats)
            plots_file = exporter.generate_plots(stats)
            if plots_file:
                print(f"📊 Generated plots: {plots_file}")
        elif args.export == 'json':
            exporter.export_json(stats)
        elif args.export == 'csv':
            exporter.export_csv(stats)
        elif args.export == 'html':
            exporter.export_html(stats)
    
    if args.generate_plots:
        print(f"\n📊 Generating visualizations...")
        base_name = os.path.splitext(args.pcap_file)[0]
        exporter = ReportExporter(base_name)
        plots_file = exporter.generate_plots(stats)
        if plots_file:
            print(f"📊 Generated plots: {plots_file}")
    
    if args.verbose:
        print(f"\n{'='*80}")
        print(f"✅ Analysis completed successfully!")
        print(f"{'='*80}\n")


def run_gui():
    """Run the GUI application"""
    if not PYQT_AVAILABLE:
        print("❌ PyQt6 is not installed. GUI mode is not available.")
        print("   Install it with: pip install PyQt6")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    app.setApplicationName("Advanced PCAP Analyzer")
    app.setApplicationVersion("3.0")
    
    window = MainWindow()
    window.show()
    
    sys.exit(app.exec())


def main():
    """Main entry point with both CLI and GUI support"""
    parser = argparse.ArgumentParser(
        description='Enhanced Advanced PCAP file analyzer v3.0 with GUI and CLI support',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # GUI Mode (default)
  python main.py
  
  # CLI Mode with basic analysis
  python main.py capture.pcap
  
  # CLI Mode with security scan and exports
  python main.py capture.pcap --security-scan --export all -v
  
  # Quick mode for large files
  python main.py large_capture.pcap --quick --export json
        '''
    )
    
    # Optional positional argument for CLI mode
    parser.add_argument(
        'pcap_file',
        nargs='?',
        help='Path to the PCAP file to analyze (CLI mode only)'
    )
    
    # CLI options
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output with progress indicators'
    )
    parser.add_argument(
        '--export',
        choices=['json', 'csv', 'html', 'all'],
        help='Export analysis results to specified format(s)'
    )
    parser.add_argument(
        '--security-scan',
        action='store_true',
        help='Enable comprehensive security pattern detection'
    )
    parser.add_argument(
        '--generate-plots',
        action='store_true',
        help='Generate visual plots and charts'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick mode - faster analysis with basic statistics only'
    )
    
    args = parser.parse_args()
    
    # Determine mode: GUI if no file specified, CLI if file specified
    if args.pcap_file:
        # CLI mode
        if not os.path.exists(args.pcap_file):
            print(f"❌ Error: File '{args.pcap_file}' not found")
            sys.exit(1)
        
        run_cli_analysis(args)
    else:
        # GUI mode
        run_gui()


if __name__ == "__main__":
    main()