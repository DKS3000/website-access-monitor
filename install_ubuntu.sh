#!/bin/bash
# Website Access Monitor - Complete Ubuntu Installation Script
# Run this on Ubuntu 20.04+ with sudo

set -e

echo "========================================"
echo "Website Access Monitor - Ubuntu Setup"
echo "========================================"
echo ""

# Step 1: Update system
echo "[1/10] Updating system packages..."
sudo apt update
sudo apt upgrade -y
echo "✓ System packages updated"
echo ""

# Step 2: Install Python and dependencies
echo "[2/10] Installing Python 3 and pip..."
sudo apt install -y python3 python3-pip python3-venv git curl wget
echo "✓ Python 3 installed"
python3 --version
echo ""

# Step 3: Create project directory
echo "[3/10] Creating project directory..."
PROJECT_DIR="$HOME/website-access-monitor"
if [ -d "$PROJECT_DIR" ]; then
    echo "✓ Project directory already exists: $PROJECT_DIR"
else
    mkdir -p "$PROJECT_DIR"
    echo "✓ Project directory created: $PROJECT_DIR"
fi
echo ""

# Step 4: Clone repository
echo "[4/10] Cloning repository..."
cd "$PROJECT_DIR"

if [ -f "monitor.py" ]; then
    echo "✓ Repository files already exist"
    git pull origin main 2>/dev/null || echo "(Not a git repo, skipping pull)"
else
    git clone https://github.com/DKS3000/website-access-monitor.git . 2>/dev/null || {
        echo "⚠ Git clone failed, downloading as ZIP..."
        wget -q https://github.com/DKS3000/website-access-monitor/archive/refs/heads/main.zip
        unzip -q main.zip
        mv website-access-monitor-main/* .
        rm -rf website-access-monitor-main main.zip
    }
fi
echo "✓ Repository ready at: $PROJECT_DIR"
echo ""

# Step 5: Create virtual environment
echo "[5/10] Creating Python virtual environment..."
if [ -d "venv" ]; then
    echo "✓ Virtual environment already exists"
else
    python3 -m venv venv
    echo "✓ Virtual environment created"
fi
echo ""

# Step 6: Activate virtual environment and install dependencies
echo "[6/10] Installing Python dependencies..."
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
echo "✓ Dependencies installed"
pip list | grep requests
echo ""

# Step 7: Create necessary directories
echo "[7/10] Creating directories..."
mkdir -p reports logs
echo "✓ Directories created: reports, logs"
echo ""

# Step 8: Verify installation
echo "[8/10] Verifying installation..."
python monitor.py --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "✓ Monitor script is working"
else
    echo "✗ Monitor script verification failed"
    exit 1
fi
echo ""

# Step 9: Create startup script
echo "[9/10] Creating startup script..."
cat > start_monitor.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
python monitor.py "$@"
EOF
chmod +x start_monitor.sh
echo "✓ Startup script created: start_monitor.sh"
echo ""

# Step 10: Create helper scripts
echo "[10/10] Creating helper scripts..."

# Quick test script
cat > quick_test.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "Testing direct connection to dgft.co.in..."
python monitor.py --target https://dgft.co.in --verbose
EOF
chmod +x quick_test.sh

# JSON report script
cat > run_json_report.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
echo "Generating JSON report..."
python monitor.py --target https://dgft.co.in --config routes.json --output reports/report_${TIMESTAMP}.json
echo "Report saved to: reports/report_${TIMESTAMP}.json"
EOF
chmod +x run_json_report.sh

# HTML report script
cat > run_html_report.sh << 'EOF'
#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
echo "Generating HTML report..."
python monitor.py --target https://dgft.co.in --config routes.json --html reports/report_${TIMESTAMP}.html
echo "Report saved to: reports/report_${TIMESTAMP}.html"
echo "Open it in browser: firefox reports/report_${TIMESTAMP}.html"
EOF
chmod +x run_html_report.sh

echo "✓ Helper scripts created"
echo ""

# Final summary
echo "========================================"
echo "✓ INSTALLATION COMPLETE!"
echo "========================================"
echo ""
echo "Project Location: $PROJECT_DIR"
echo ""
echo "Quick Start Commands:"
echo ""
echo "1. Test direct connection:"
echo "   cd $PROJECT_DIR"
echo "   ./quick_test.sh"
echo ""
echo "2. Generate JSON report:"
echo "   ./run_json_report.sh"
echo ""
echo "3. Generate HTML report:"
echo "   ./run_html_report.sh"
echo ""
echo "4. Manual command:"
echo "   source venv/bin/activate"
echo "   python monitor.py --target https://dgft.co.in --verbose"
echo ""
echo "5. View configuration:"
echo "   cat routes.json"
echo ""
echo "6. Edit configuration:"
echo "   nano routes.json"
echo ""
echo "Next Steps:"
echo "- Configure your VPN/proxy routes in routes.json"
echo "- Run quick_test.sh to verify setup"
echo "- Set up automated monitoring with cron"
echo ""
echo "For detailed guide, see: SETUP_UBUNTU.md"
echo ""
