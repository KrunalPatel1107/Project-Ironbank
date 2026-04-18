#!/bin/bash
################################################################################
# Supply Chain Security Setup Script
# ==================================
# Automates:
#   1. SBOM (Software Bill of Materials) generation with syft
#   2. Vulnerability scanning with grype
#   3. Container image signing with cosign
#   4. Image verification in CI/CD
#
# Usage:
#   bash supply-chain-security-setup.sh --image ghcr.io/myapp:latest
#
# Author: Iron Bank Training
# License: MIT
################################################################################

set -euo pipefail

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
IMAGE=""
OUTPUT_DIR="./supply-chain-artifacts"
SKIP_SCAN=false
SKIP_SIGN=false

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --image)
                IMAGE="$2"
                shift 2
                ;;
            --output)
                OUTPUT_DIR="$2"
                shift 2
                ;;
            --skip-scan)
                SKIP_SCAN=true
                shift
                ;;
            --skip-sign)
                SKIP_SIGN=true
                shift
                ;;
            --help)
                print_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                print_help
                exit 1
                ;;
        esac
    done
}

# Print help message
print_help() {
    cat << EOF
${BLUE}Supply Chain Security Setup${NC}

Usage:
    bash supply-chain-security-setup.sh --image <IMAGE> [OPTIONS]

Required:
    --image <IMAGE>        Container image to scan (e.g., ghcr.io/myapp:latest)

Options:
    --output <DIR>         Output directory for artifacts (default: ./supply-chain-artifacts)
    --skip-scan            Skip vulnerability scanning
    --skip-sign            Skip image signing
    --help                 Print this help message

Examples:
    # Full supply chain security (SBOM + scan + sign)
    bash supply-chain-security-setup.sh --image ghcr.io/myapp:latest

    # SBOM generation only
    bash supply-chain-security-setup.sh --image ghcr.io/myapp:latest --skip-scan --skip-sign

    # Scan existing SBOM
    bash supply-chain-security-setup.sh --image ghcr.io/myapp:latest --skip-sign

EOF
}

# Log messages
log_info() {
    echo -e "${BLUE}[*]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    local missing_tools=()

    # Check syft (SBOM generation)
    if ! command -v syft &> /dev/null; then
        missing_tools+=("syft")
    fi

    # Check grype (vulnerability scanning)
    if ! command -v grype &> /dev/null; then
        missing_tools+=("grype")
    fi

    # Check cosign (image signing)
    if ! command -v cosign &> /dev/null; then
        missing_tools+=("cosign")
    fi

    # Check docker
    if ! command -v docker &> /dev/null; then
        missing_tools+=("docker")
    fi

    if [ ${#missing_tools[@]} -gt 0 ]; then
        log_error "Missing required tools: ${missing_tools[@]}"
        log_info "Install them with:"
        log_info "  pip install syft grype --break-system-packages"
        log_info "  wget https://github.com/sigstore/cosign/releases/latest/download/cosign-linux-amd64"
        exit 1
    fi

    log_success "All prerequisites met"
}

# Create output directory
setup_output_dir() {
    log_info "Creating output directory: $OUTPUT_DIR"
    mkdir -p "$OUTPUT_DIR"
    log_success "Output directory created"
}

# Generate SBOM (Software Bill of Materials)
generate_sbom() {
    log_info "Generating SBOM for image: $IMAGE"

    local sbom_file="$OUTPUT_DIR/sbom.json"
    local sbom_cyclonedx="$OUTPUT_DIR/sbom-cyclonedx.xml"

    # Generate SBOM in CycloneDX JSON format
    log_info "Generating CycloneDX JSON SBOM..."
    syft "$IMAGE" -o cyclonedx-json > "$sbom_file"
    log_success "SBOM saved to: $sbom_file"

    # Generate SBOM in CycloneDX XML format (for compliance)
    log_info "Generating CycloneDX XML SBOM..."
    syft "$IMAGE" -o cyclonedx-xml > "$sbom_cyclonedx"
    log_success "SBOM saved to: $sbom_cyclonedx"

    # Print summary
    log_info "SBOM Summary:"
    local component_count=$(grep -c '"name"' "$sbom_file" || echo "0")
    log_info "  Total components: $component_count"

    # Show top 10 dependencies
    log_info "  Top 10 components:"
    grep '"name"' "$sbom_file" | head -10 | sed 's/^/    /'

    echo "$sbom_file"
}

# Scan for vulnerabilities using Grype
scan_vulnerabilities() {
    local sbom_file="$1"
    log_info "Scanning for vulnerabilities..."

    local vuln_report="$OUTPUT_DIR/vulnerabilities.json"
    local vuln_table="$OUTPUT_DIR/vulnerabilities.txt"

    # Scan SBOM for CVEs
    log_info "Running Grype scan against $sbom_file..."
    grype "$sbom_file" -o json > "$vuln_report" || true
    grype "$sbom_file" -o table > "$vuln_table" || true

    # Parse results
    local critical_count=$(grep -c '"critical"' "$vuln_report" || echo "0")
    local high_count=$(grep -c '"high"' "$vuln_report" || echo "0")
    local medium_count=$(grep -c '"medium"' "$vuln_report" || echo "0")

    log_info "Vulnerability Summary:"
    log_info "  CRITICAL: $critical_count"
    log_info "  HIGH: $high_count"
    log_info "  MEDIUM: $medium_count"

    if [ "$critical_count" -gt 0 ]; then
        log_error "CRITICAL vulnerabilities found! Address before deployment."
        log_info "Detailed report: $vuln_report"
        log_info "Human-readable report: $vuln_table"
        return 1
    else
        log_success "No CRITICAL vulnerabilities found"
        return 0
    fi
}

# Setup Cosign keypair for image signing
setup_cosign_keys() {
    log_info "Setting up Cosign keypair for image signing..."

    local cosign_key="$OUTPUT_DIR/cosign.key"
    local cosign_pub="$OUTPUT_DIR/cosign.pub"

    # Check if keys already exist
    if [ -f "$cosign_key" ] && [ -f "$cosign_pub" ]; then
        log_warning "Cosign keys already exist, skipping generation"
        return
    fi

    # Generate new keypair
    # Note: In production, use a strong password or HSM
    log_info "Generating Cosign keypair..."
    log_warning "You will be prompted for a password to protect the private key"

    cosign generate-key-pair \
        --output-key-prefix "$OUTPUT_DIR/cosign" || {
        log_error "Failed to generate Cosign keypair"
        return 1
    }

    log_success "Cosign keypair generated:"
    log_success "  Private key: $cosign_key"
    log_success "  Public key: $cosign_pub"

    # Important security notice
    log_warning "IMPORTANT: Protect your private key!"
    log_warning "  1. Store cosign.key in a secure location (e.g., GitHub Secrets, HashiCorp Vault)"
    log_warning "  2. NEVER commit cosign.key to git"
    log_warning "  3. Rotate keys annually"
}

# Sign container image
sign_image() {
    local cosign_key="$OUTPUT_DIR/cosign.key"

    if [ ! -f "$cosign_key" ]; then
        log_error "Cosign private key not found: $cosign_key"
        log_info "Run setup_cosign_keys() first"
        return 1
    fi

    log_info "Signing image: $IMAGE"
    log_warning "You will be prompted for the Cosign key password"

    # Sign the image (requires authentication to registry)
    cosign sign \
        --key "$cosign_key" \
        "$IMAGE" || {
        log_error "Failed to sign image. Check that:"
        log_error "  1. You have push access to the registry"
        log_error "  2. IMAGE is in format: REGISTRY/REPO:TAG"
        log_error "  3. Image actually exists in the registry"
        return 1
    }

    log_success "Image signed successfully"

    # Save signature verification command
    log_info "To verify this image later, run:"
    log_info "  cosign verify --key $cosign_key/$IMAGE"
}

# Verify image signature
verify_image() {
    local cosign_pub="$OUTPUT_DIR/cosign.pub"

    if [ ! -f "$cosign_pub" ]; then
        log_error "Cosign public key not found: $cosign_pub"
        return 1
    fi

    log_info "Verifying image signature: $IMAGE"

    cosign verify \
        --key "$cosign_pub" \
        "$IMAGE" && {
        log_success "Image signature verified!"
        return 0
    } || {
        log_error "Image signature verification FAILED"
        return 1
    }
}

# Create CI/CD integration script
create_cicd_integration() {
    log_info "Creating CI/CD integration script..."

    local cicd_script="$OUTPUT_DIR/cicd-supply-chain.sh"

    cat > "$cicd_script" << 'CICD_EOF'
#!/bin/bash
# CI/CD Supply Chain Security Integration
# =======================================
# Add this to your GitHub Actions, GitLab CI, or Jenkins pipeline

set -euo pipefail

IMAGE="${1:?Image not specified}"
COSIGN_KEY="${2:?Cosign key not specified}"

echo "[*] Supply chain security checks for: $IMAGE"

# 1. Generate SBOM
echo "[*] Generating SBOM..."
syft "$IMAGE" -o cyclonedx-json > sbom.json

# 2. Scan for vulnerabilities
echo "[*] Scanning for vulnerabilities..."
grype sbom.json --fail-on high || exit 1

# 3. Verify image isn't already signed (prevent re-signing)
echo "[*] Checking image signature..."
if cosign verify --key cosign.pub "$IMAGE" 2>/dev/null; then
    echo "[!] Warning: Image already signed"
fi

# 4. Sign the image
echo "[*] Signing image..."
cosign sign --key "$COSIGN_KEY" "$IMAGE"

# 5. Verify signature
echo "[*] Verifying image signature..."
cosign verify --key cosign.pub "$IMAGE"

echo "[✓] All supply chain security checks passed!"

# Upload SBOM to compliance system (optional)
# curl -H "Authorization: Bearer $SBOM_TOKEN" \
#   -F sbom=@sbom.json \
#   https://compliance.example.com/sbom
CICD_EOF

    chmod +x "$cicd_script"
    log_success "CI/CD integration script created: $cicd_script"
}

# Create GitHub Actions workflow
create_github_actions_workflow() {
    log_info "Creating GitHub Actions workflow..."

    local workflow_dir=".github/workflows"
    local workflow_file="$workflow_dir/supply-chain-security.yml"

    mkdir -p "$workflow_dir"

    cat > "$workflow_file" << 'WORKFLOW_EOF'
name: Supply Chain Security

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  supply-chain-security:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write

    steps:
      - uses: actions/checkout@v3

      - name: Build container image
        run: docker build -t myapp:${{ github.sha }} .

      - name: Install syft
        run: pip install syft grype

      - name: Generate SBOM
        run: |
          syft myapp:${{ github.sha }} -o cyclonedx-json > sbom.json
          cat sbom.json

      - name: Scan for vulnerabilities
        run: |
          grype sbom.json --fail-on high

      - name: Install Cosign
        uses: sigstore/cosign-installer@v3

      - name: Sign image
        run: |
          cosign sign --key ${{ secrets.COSIGN_KEY }} \
            myapp:${{ github.sha }}

      - name: Verify signature
        run: |
          cosign verify --key ${{ secrets.COSIGN_PUB }} \
            myapp:${{ github.sha }}

      - name: Upload SBOM
        run: |
          curl -H "Authorization: Bearer ${{ secrets.SBOM_TOKEN }}" \
            -F sbom=@sbom.json \
            https://compliance.example.com/sbom
WORKFLOW_EOF

    log_success "GitHub Actions workflow created: $workflow_file"
    log_info "Don't forget to add secrets to GitHub:"
    log_info "  - COSIGN_KEY (base64-encoded private key)"
    log_info "  - COSIGN_PUB (public key)"
    log_info "  - SBOM_TOKEN (API token for compliance system)"
}

# Main execution
main() {
    # Validate inputs
    if [ -z "$IMAGE" ]; then
        log_error "Image not specified"
        print_help
        exit 1
    fi

    log_info "Starting supply chain security setup"
    log_info "Image: $IMAGE"

    # Execute steps
    check_prerequisites
    setup_output_dir

    # Generate SBOM
    local sbom_file=$(generate_sbom)

    # Scan for vulnerabilities
    if [ "$SKIP_SCAN" = false ]; then
        scan_vulnerabilities "$sbom_file" || log_warning "Vulnerabilities found (non-fatal)"
    fi

    # Setup signing
    if [ "$SKIP_SIGN" = false ]; then
        setup_cosign_keys
        sign_image
        verify_image
    fi

    # Create automation scripts
    create_cicd_integration
    create_github_actions_workflow

    log_success "Supply chain security setup complete!"
    log_info "Artifacts saved to: $OUTPUT_DIR"
    log_info "Next steps:"
    log_info "  1. Review SBOM: $OUTPUT_DIR/sbom.json"
    log_info "  2. Check vulnerabilities: $OUTPUT_DIR/vulnerabilities.txt"
    log_info "  3. Store Cosign key securely (GitHub Secrets, Vault)"
    log_info "  4. Add CI/CD integration to your pipeline"
}

# Run main function
parse_args "$@"
main
