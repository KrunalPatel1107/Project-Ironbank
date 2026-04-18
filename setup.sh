#!/bin/bash
# Iron Bank Training — One-command setup
# Usage: bash setup.sh

echo "🏦 Iron Bank Training — Setup"
echo ""

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 not found. Install it first:"
    echo "   Ubuntu: sudo apt install python3 python3-pip -y"
    echo "   macOS:  brew install python3"
    exit 1
fi

# Install MkDocs Material
echo "📦 Installing MkDocs Material..."
pip install mkdocs-material --break-system-packages 2>/dev/null || pip install mkdocs-material

# Create notes folders for each month
for i in $(seq -w 1 12); do
    mkdir -p notes/month${i}
done
mkdir -p scripts/{bash,python,terraform}
mkdir -p projects

echo ""
echo "✅ Setup complete!"
echo ""
echo "To start your dashboard:"
echo "  cd $(pwd)"
echo "  mkdocs serve"
echo "  Open http://localhost:8000"
echo ""
echo "To deploy to GitHub Pages:"
echo "  git init && git add . && git commit -m 'Initial commit'"
echo "  (create private repo on github.com)"
echo "  git remote add origin https://github.com/YOUR_USER/iron-bank-training.git"
echo "  git push -u origin main"
echo "  mkdocs gh-deploy --force"
