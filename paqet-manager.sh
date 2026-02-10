#!/bin/bash
#=================================================
# Paqet Tunnel Manager
# Version: 5.1
# Raw packet-level tunneling for bypassing network restrictions
# GitHub: https://github.com/hanselime/paqet
# Design and development by: https://github.com/behzadea12 - https://t.me/behzad_developer
#=================================================
# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
ORANGE='\033[0;33m'
PURPLE='\033[0;35m'
NC='\033[0m'
# Configuration
SCRIPT_VERSION="5.1"
PAQET_VERSION="v1.0.0-alpha.15"
CONFIG_DIR="/etc/paqet"
SERVICE_DIR="/etc/systemd/system"
BIN_DIR="/usr/local/bin"
INSTALL_DIR="/opt/paqet"
GITHUB_REPO="hanselime/paqet"
SERVICE_NAME="paqet"
# Banner
show_banner() {
    clear
    echo -e "${MAGENTA}"
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                                                              ║"
    echo "║     ██████╗  █████╗  ██████╗ ███████╗████████╗               ║"
    echo "║     ██╔══██╗██╔══██╗██╔═══██╗██╔════╝╚══██╔══╝               ║"
    echo "║     ██████╔╝███████║██║   ██║█████╗     ██║                  ║"
    echo "║     ██╔═══╝ ██╔══██║██║▄▄ ██║██╔══╝     ██║                  ║"
    echo "║     ██║     ██║  ██║╚██████╔╝███████╗   ██║                  ║"
    echo "║     ╚═╝     ╚═╝  ╚═╝ ╚══▀▀═╝ ╚══════╝   ╚═╝                  ║"
    echo "║                                                              ║"
    echo "║          Raw Packet Tunnel - Firewall Bypass                 ║"
    echo "║                                 Manager v5.1                 ║"
    echo "║                                                              ║"
    echo "║          https://t.me/behzad_developer                       ║"
    echo "║          https://github.com/behzadea12                       ║"    
    echo "║                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Print functions
print_step() { echo -e "${BLUE}[*]${NC} $1"; }
print_success() { echo -e "${GREEN}[✓]${NC} $1"; }
print_error() { echo -e "${RED}[✗]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[!]${NC} $1"; }
print_info() { echo -e "${CYAN}[i]${NC} $1"; }
print_step() { echo -e "${BLUE}[*] $1${NC}"; }
print_menu() { echo -e "${PURPLE}[▶]${NC} $1"; }
print_input() { echo -e "${YELLOW}[?]${NC} $1"; }
# Check root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}
# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
    elif [ -f /etc/redhat-release ]; then
        OS="rhel"
    else
        OS=$(uname -s | tr '[:upper:]' '[:lower:]')
    fi
    echo "$OS"
}
# Detect architecture
detect_arch() {
    local arch
    arch=$(uname -m)
   
    case $arch in
        x86_64|x86-64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7l|armhf)
            echo "armv7"
            ;;
        i386|i686)
            echo "386"
            ;;
        *)
            print_error "Unsupported architecture: $arch"
            return 1
            ;;
    esac
}
# Get public IP
get_public_ip() {
    local ip=""
    local services=(
        "ifconfig.me"
        "icanhazip.com"
        "api.ipify.org"
        "checkip.amazonaws.com"
        "ipinfo.io/ip"
    )
   
    for service in "${services[@]}"; do
        ip=$(curl -4 -s --max-time 2 "$service" 2>/dev/null)
        if [ -n "$ip" ] && echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
            echo "$ip"
            return 0
        fi
    done

    ip=$(hostname -I | awk '{print $1}' 2>/dev/null)
    if [ -n "$ip" ] && echo "$ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "$ip"
        return 0
    fi
   
    echo "Not Detected"
}
# Get network information
get_network_info() {
    local interface
    local local_ip
    local gateway_ip
    local gateway_mac
   
    # Get default interface
    if command -v ip &> /dev/null; then
        interface=$(ip route | grep default | awk '{print $5}' | head -1)
    else
        interface="eth0"
    fi
   
    # Get local IP
    if [ -n "$interface" ]; then
        if command -v ip &> /dev/null; then
            local_ip=$(ip -4 addr show "$interface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
        elif command -v ifconfig &> /dev/null; then
            local_ip=$(ifconfig "$interface" 2>/dev/null | grep -oE 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -oE '([0-9]*\.){3}[0-9]*' | head -1)
        fi
    fi
   
    # Get gateway IP
    if command -v ip &> /dev/null; then
        gateway_ip=$(ip route | grep default | awk '{print $3}' | head -1)
    fi
   
    # Get gateway MAC
    if [ -n "$gateway_ip" ]; then
        # Try to ping to populate ARP cache
        ping -c 1 -W 1 "$gateway_ip" >/dev/null 2>&1 || true
       
        # Try ip neigh first
        gateway_mac=$(ip neigh show "$gateway_ip" 2>/dev/null | grep -oE '([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}' | head -1)
       
        # Fallback to arp
        if [ -z "$gateway_mac" ] && command -v arp &> /dev/null; then
            gateway_mac=$(arp -n "$gateway_ip" 2>/dev/null | awk '/^'$gateway_ip'/ {print $3}' | head -1)
        fi
    fi
   
    # Return values
    NETWORK_INTERFACE="$interface"
    LOCAL_IP="$local_ip"
    GATEWAY_IP="$gateway_ip"
    GATEWAY_MAC="$gateway_mac"
}
# Check if dependencies are installed
check_dependencies() {
    local missing_deps=()
    local os=$(detect_os)
   
    # Common dependencies
    local common_deps=("curl" "wget" "iptables" "lsof")
   
    case $os in
        ubuntu|debian)
            common_deps+=("libpcap-dev" "iproute2" "cron")
            ;;
        centos|rhel|fedora|rocky|almalinux)
            common_deps+=("libpcap-devel" "iproute" "cronie")
            ;;
    esac
   
    for dep in "${common_deps[@]}"; do
        if ! command -v "$dep" &> /dev/null && ! dpkg -l | grep -q "$dep" 2>/dev/null && ! rpm -q "$dep" &> /dev/null 2>&1; then
            missing_deps+=("$dep")
        fi
    done
   
    if [ ${#missing_deps[@]} -eq 0 ]; then
        return 0
    else
        echo "${missing_deps[@]}"
        return 1
    fi
}
# Validate IP address
validate_ip() {
    local ip=$1
    if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        local IFS='.'
        read -r -a octets <<< "$ip"
        for octet in "${octets[@]}"; do
            if [[ $octet -lt 0 || $octet -gt 255 ]]; then
                return 1
            fi
        done
        return 0
    fi
    return 1
}
# Validate port number
validate_port() {
    local port=$1
    if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
        return 0
    fi
    return 1
}
# Clean port list (remove spaces, commas, validate)
clean_port_list() {
    local ports="$1"
    ports=$(echo "$ports" | tr -d ' ')
    local cleaned_ports=""
    IFS=',' read -ra port_array <<< "$ports"
   
    for port in "${port_array[@]}"; do
        if validate_port "$port"; then
            if [ -z "$cleaned_ports" ]; then
                cleaned_ports="$port"
            else
                cleaned_ports="$cleaned_ports,$port"
            fi
        else
            print_warning "Invalid port '$port' removed from list"
        fi
    done
   
    echo "$cleaned_ports"
}
# Clean config name (only alphanumeric, dash, underscore)
clean_config_name() {
    local name="$1"
    name=$(echo "$name" | tr -cd '[:alnum:]-_')
    # If empty, set default
    if [ -z "$name" ]; then
        name="default"
    fi
    echo "$name"
}
# Check port conflict
check_port_conflict() {
    local port="$1"
   
    if ss -tuln 2>/dev/null | grep -q ":${port} "; then
        print_warning "Port $port is already in use!"
       
        local pid
        pid=$(lsof -t -i:$port 2>/dev/null | head -1)
        if [ -n "$pid" ]; then
            local pname
            pname=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
            print_info "Process: $pname (PID: $pid)"
           
            echo ""
            read -p "Kill this process? (y/N): " kill_choice
           
            if [[ "$kill_choice" =~ ^[Yy]$ ]]; then
                kill -9 "$pid" 2>/dev/null || true
                sleep 1
                print_success "Process killed"
            else
                print_error "Cannot continue with port in use"
                return 1
            fi
        fi
    fi
    return 0
}
# Install dependencies
install_dependencies() {
    print_step "Installing dependencies..."
   
    local os
    os=$(detect_os)
   
    case $os in
        ubuntu|debian)
            apt update -qq >/dev/null 2>&1 || true
            apt install -y curl wget libpcap-dev iptables lsof iproute2 cron >/dev/null 2>&1 || {
                print_warning "Some packages may have failed to install"
            }
            ;;
        centos|rhel|fedora|rocky|almalinux)
            yum install -y curl wget libpcap-devel iptables lsof iproute cronie >/dev/null 2>&1 || {
                print_warning "Some packages may have failed to install"
            }
            ;;
        *)
            print_warning "Unknown OS. Please install manually: libpcap iptables curl cron"
            ;;
    esac
   
    print_success "Dependencies installed"
}
# Generate secret key
generate_secret_key() {
    if command -v openssl &> /dev/null; then
        openssl rand -base64 32 | tr -dc 'a-zA-Z0-9' | head -c 32
    else
        cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 32
    fi
}
# Download and install Paqet binary
install_paqet() {
    print_step "Installing Paqet binary..."
   
    # Display system info
    echo -e "${YELLOW}System Information:${NC}"
    local os=$(detect_os)
    local arch=$(detect_arch)
    echo -e " OS: ${CYAN}$os${NC}"
    echo -e " Arch: ${CYAN}$arch${NC}"
    echo -e " Version: ${CYAN}$PAQET_VERSION${NC}"
    echo ""
   
    if [ $? -ne 0 ]; then
        return 1
    fi
   
    local os="linux"
    local version="$PAQET_VERSION"
   
    # Check for local files in /root/paqet
    local local_dir="/root/paqet"
   
    # Create directory if doesn't exist
    mkdir -p "$local_dir"
   
    # Display expected filename
    local expected_file="paqet-${os}-${arch}-${version}.tar.gz"
    echo -e "${YELLOW}Expected filename:${NC} ${CYAN}$expected_file${NC}"
    echo ""
   
    # Display options
    echo -e "${YELLOW}Installation Options:${NC}"
    echo -e " 1) ${GREEN}Download from GitHub (recommended)${NC}"
    echo -e " 2) ${CYAN}Use local file from $local_dir/${NC}"
    echo -e " 3) ${PURPLE}Download from custom URL${NC}"
    echo ""
   
    read -p "Choose option [1-3]: " install_choice
   
    case $install_choice in
        1)
            # Download from GitHub
            print_info "Downloading from GitHub for $os/$arch..."
            local archive_name="$expected_file"
            local download_url="https://github.com/${GITHUB_REPO}/releases/download/${version}/${archive_name}"
           
            if ! curl -fsSL "$download_url" -o "/tmp/paqet.tar.gz" 2>/dev/null; then
                print_error "Download failed from GitHub"
                print_info "URL: $download_url"
                print_info ""
                print_info "Please download manually:"
                print_info " URL: $download_url"
                print_info " Save to: $local_dir/$archive_name"
                print_info " Then run this installer again"
                return 1
            else
                print_success "Downloaded from GitHub"
                cp "/tmp/paqet.tar.gz" "$local_dir/$archive_name" 2>/dev/null && \
                print_info "Saved copy to $local_dir/$archive_name for future use"
            fi
            ;;
        2)
            # Use local file
            local local_files=()
            if [ -d "$local_dir" ]; then
                mapfile -t local_files < <(find "$local_dir" -name "*.tar.gz" -type f 2>/dev/null)
            fi
           
            if [ ${#local_files[@]} -eq 0 ]; then
                print_error "No local files found in $local_dir"
                return 1
            fi
           
            echo -e "${YELLOW}Found local paqet archives in $local_dir:${NC}"
            echo ""
           
            for i in "${!local_files[@]}"; do
                local filename=$(basename "${local_files[$i]}")
                local filesize=$(du -h "${local_files[$i]}" | cut -f1)

                if [[ "$filename" == *"$arch"* ]] && [[ "$filename" == *"$os"* ]]; then
                    echo -e " $((i+1)). ${GREEN}$filename${NC} (${filesize})"
                else
                    echo -e " $((i+1)). ${CYAN}$filename${NC} (${filesize})"
                fi
            done
           
            echo ""
            read -p "Select file [1-${#local_files[@]}]: " file_choice
           
            if [[ "$file_choice" -ge 1 ]] && [[ "$file_choice" -le ${#local_files[@]} ]]; then
                local selected_file="${local_files[$((file_choice-1))]}"
                print_success "Using local file: $(basename "$selected_file")"
                cp "$selected_file" "/tmp/paqet.tar.gz"
            else
                print_error "Invalid selection"
                return 1
            fi
            ;;
        3)
            # Download from custom URL
            echo ""
            echo -e "${YELLOW}Enter custom download URL:${NC}"
            read -p "URL: " custom_url
           
            if [ -z "$custom_url" ]; then
                print_error "URL cannot be empty"
                return 1
            fi
           
            print_info "Downloading from custom URL..."
            if ! curl -fsSL "$custom_url" -o "/tmp/paqet.tar.gz" 2>/dev/null; then
                print_error "Download failed from custom URL"
                return 1
            else
                print_success "Downloaded from custom URL"
            fi
            ;;
        *)
            print_error "Invalid choice"
            return 1
            ;;
    esac
   
    # Extract and install
    mkdir -p "$INSTALL_DIR"
   
    tar -xzf "/tmp/paqet.tar.gz" -C "$INSTALL_DIR" 2>/dev/null || {
        print_error "Failed to extract archive"
        rm -f "/tmp/paqet.tar.gz"
        return 1
    }
   
    # Find and install binary
    local extracted_binary="$INSTALL_DIR/paqet_${os}_${arch}"
    if [ -f "$extracted_binary" ]; then
        cp "$extracted_binary" "$BIN_DIR/paqet"
        chmod +x "$BIN_DIR/paqet"
        print_success "Paqet installed to $BIN_DIR/paqet"
    else
        local alt_binary=$(find "$INSTALL_DIR" -name "paqet" -type f | head -1)
        if [ -f "$alt_binary" ]; then
            cp "$alt_binary" "$BIN_DIR/paqet"
            chmod +x "$BIN_DIR/paqet"
            print_success "Paqet installed to $BIN_DIR/paqet"
        else
            print_error "Binary not found in archive"
            return 1
        fi
    fi
   
    rm -f "/tmp/paqet.tar.gz"
    return 0
}
# Configure iptables for port and protocol
configure_iptables() {
    local port="$1"
    local protocol="$2"
   
    print_step "Configuring iptables for port $port protocol $protocol..."
   
    if ! command -v iptables &> /dev/null; then
        print_warning "iptables not found, skipping"
        return 0
    fi
   
    # Determine protocols to configure
    local protocols=()
    if [ "$protocol" == "both" ]; then
        protocols=("tcp" "udp")
    else
        protocols=("$protocol")
    fi
   
    for proto in "${protocols[@]}"; do
        # Remove existing rules
        iptables -t raw -D PREROUTING -p $proto --dport "$port" -j NOTRACK 2>/dev/null || true
        iptables -t raw -D OUTPUT -p $proto --sport "$port" -j NOTRACK 2>/dev/null || true
        if [ "$proto" == "tcp" ]; then
            iptables -t mangle -D OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP 2>/dev/null || true
        fi
       
        # Add new rules
        iptables -t raw -A PREROUTING -p $proto --dport "$port" -j NOTRACK
        iptables -t raw -A OUTPUT -p $proto --sport "$port" -j NOTRACK
       
        # Only add TCP RST rule for TCP protocol
        if [ "$proto" == "tcp" ]; then
            iptables -t mangle -A OUTPUT -p tcp --sport "$port" --tcp-flags RST RST -j DROP
        fi
    done
   
    print_success "iptables configured for $protocol on port $port"
}
# Create systemd service
create_systemd_service() {
    local config_name="$1"
    local service_name="paqet-${config_name}"
   
    cat > "$SERVICE_DIR/${service_name}.service" << EOF
[Unit]
Description=Paqet Tunnel (${config_name})
After=network.target
StartLimitIntervalSec=0
[Service]
Type=simple
ExecStart=$BIN_DIR/paqet run -c $CONFIG_DIR/${config_name}.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF
   
    systemctl daemon-reload
    print_success "Service created: ${service_name}"
}

get_manual_kcp_settings() {
    local block_param="$1"
    local mtu_param="$2"
   
    local nodelay="1"
    while true; do
        read -p "[1] nodelay [0-2, default 1]: " input
        nodelay=${input:-1}
        [[ "$nodelay" =~ ^[0-2]$ ]] && break
        echo -e "${RED}Value must be 0, 1 or 2${NC}"
    done
    local interval="20"
    while true; do
        read -p "[2] interval (milliseconds) [default 20]: " input
        interval=${input:-20}
        [[ "$interval" =~ ^[0-9]+$ ]] && [ "$interval" -ge 5 ] && [ "$interval" -le 60000 ] && break
        echo -e "${RED}Suggested range: 5–60000 ms${NC}"
    done
    local resend="1"
    while true; do
        read -p "[3] resend [0-∞, default 1]: " input
        resend=${input:-1}
        [[ "$resend" =~ ^[0-9]+$ ]] && break
        echo -e "${RED}Must be non-negative integer${NC}"
    done
    local nocongestion="1"
    while true; do
        read -p "[4] nocongestion [0/1, default 1]: " input
        nocongestion=${input:-1}
        [[ "$nocongestion" =~ ^[01]$ ]] && break
        echo -e "${RED}Only 0 or 1 allowed${NC}"
    done
    local rcvwnd="2048"
    while true; do
        read -p "[5] rcvwnd [default 2048]: " input
        rcvwnd=${input:-2048}
        [[ "$rcvwnd" =~ ^[0-9]+$ ]] && [ "$rcvwnd" -ge 128 ] && break
        echo -e "${RED}Minimum recommended: 128${NC}"
    done
    local sndwnd="2048"
    while true; do
        read -p "[6] sndwnd [default 2048]: " input
        sndwnd=${input:-2048}
        [[ "$sndwnd" =~ ^[0-9]+$ ]] && [ "$sndwnd" -ge 128 ] && break
        echo -e "${RED}Minimum recommended: 128${NC}"
    done
    local wdelay="false"
    while true; do
        read -p "[7] wdelay (true/false) [default false]: " input
        case "${input,,}" in
            ""|false) wdelay="false"; break ;;
            true) wdelay="true"; break ;;
            *) echo -e "${RED}Only true or false${NC}" ;;
        esac
    done
    local acknodelay="true"
    while true; do
        read -p "[8] acknodelay (true/false) [default true]: " input
        case "${input,,}" in
            ""|true) acknodelay="true"; break ;;
            false) acknodelay="false"; break ;;
            *) echo -e "${RED}Only true or false${NC}" ;;
        esac
    done
    local mtu=""
    if [[ -n "$mtu_param" && "$mtu_param" != "0" ]]; then
        mtu="$mtu_param"
    else
        read -p "[9] MTU [default 1200, Enter or 0 to skip]: " mtu_input
        if [[ -n "$mtu_input" && "$mtu_input" != "0" ]]; then
            if [[ "$mtu_input" =~ ^[0-9]+$ ]] && [ "$mtu_input" -ge 576 ] && [ "$mtu_input" -le 9000 ]; then
                mtu="$mtu_input"
            fi
        fi
    fi
    local smuxbuf_input=""
    read -p "[10] smuxbuf [default 4194304, 0=skip]: " smuxbuf_input
    local smuxbuf=""
    if [[ -n "$smuxbuf_input" && "$smuxbuf_input" != "0" ]]; then
        smuxbuf="$smuxbuf_input"
    fi
    local streambuf_input=""
    read -p "[11] streambuf [default 2097152, 0=skip]: " streambuf_input
    local streambuf=""
    if [[ -n "$streambuf_input" && "$streambuf_input" != "0" ]]; then
        streambuf="$streambuf_input"
    fi
    local dshard_input=""
    read -p "[12] dshard (FEC data shards) [default 10, 0=skip/disable]: " dshard_input
    local dshard=""
    if [[ -n "$dshard_input" && "$dshard_input" != "0" ]]; then
        dshard="$dshard_input"
    fi
    local pshard_input=""
    read -p "[13] pshard (FEC parity shards) [default 3, 0=skip/disable]: " pshard_input
    local pshard=""
    if [[ -n "$pshard_input" && "$pshard_input" != "0" ]]; then
        pshard="$pshard_input"
    fi
    {
        echo "    mode: \"manual\""
        echo "    nodelay: $nodelay"
        echo "    interval: $interval"
        echo "    resend: $resend"
        echo "    nocongestion: $nocongestion"
        echo "    rcvwnd: $rcvwnd"
        echo "    sndwnd: $sndwnd"
        echo "    wdelay: $wdelay"
        echo "    acknodelay: $acknodelay"
        
        if [[ -n "$block_param" && "$block_param" != "none" && "$block_param" != "null" ]]; then
            echo "    block: \"$block_param\""
        fi
        
        [[ -n "$mtu" ]] && echo "    mtu: $mtu"
        [[ -n "$smuxbuf" ]] && echo "    smuxbuf: $smuxbuf"
        [[ -n "$streambuf" ]] && echo "    streambuf: $streambuf"
        [[ -n "$dshard" ]] && echo "    dshard: $dshard"
        [[ -n "$pshard" ]] && echo "    pshard: $pshard"
    }
}

# Add automatic restart cronjob for service
add_auto_restart_cronjob() {
    local service_name="$1"
    local cron_interval="$2"
   
    local cron_command="systemctl restart ${service_name}"
    local cron_line=""
   
    case $cron_interval in
        "1min")
            cron_line="*/1 * * * * $cron_command"
            ;;
        "5min")
            cron_line="*/5 * * * * $cron_command"
            ;;
        "15min")
            cron_line="*/15 * * * * $cron_command"
            ;;
        "30min")
            cron_line="*/30 * * * * $cron_command"
            ;;
        "1hour")
            cron_line="0 */1 * * * $cron_command"
            ;;
        "12hour")
            cron_line="0 */12 * * * $cron_command"
            ;;
        "1day")
            cron_line="0 0 * * * $cron_command"
            ;;
        *)
            print_error "Invalid cron interval"
            return 1
            ;;
    esac
   
    # Check if cronjob already exists
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        # Remove existing cronjob
        crontab -l 2>/dev/null | grep -v "$cron_command" | crontab -
    fi
   
    # Add new cronjob
    (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
   
    if [ $? -eq 0 ]; then
        print_success "Cronjob added: $cron_interval restart for $service_name"
        return 0
    else
        print_error "Failed to add cronjob"
        return 1
    fi
}
# Remove cronjob for service
remove_cronjob() {
    local service_name="$1"
    local cron_command="systemctl restart ${service_name}"
   
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        crontab -l 2>/dev/null | grep -v "$cron_command" | crontab -
        print_success "Cronjob removed for $service_name"
        return 0
    else
        print_info "No cronjob found for $service_name"
        return 1
    fi
}
# View cronjob for service
view_cronjob() {
    local service_name="$1"
    local cron_command="systemctl restart ${service_name}"
   
    echo -e "${YELLOW}Cronjobs for $service_name:${NC}"
    echo ""
   
    if crontab -l 2>/dev/null | grep -q "$cron_command"; then
        crontab -l 2>/dev/null | grep "$cron_command"
    else
        print_info "No cronjob found for $service_name"
    fi
}
# Cronjob menu for service
manage_cronjob() {
    local service_name="$1"
    local display_name="$2"
   
    while true; do
        show_banner
        echo -e "${YELLOW}Manage Cronjob for: $display_name${NC}"
        echo ""
       
        echo -e "${CYAN}Current cronjob:${NC}"
        view_cronjob "$service_name"
        echo ""
       
        echo -e "${CYAN}Add/Change Cronjob:${NC}"
        echo -e " 1. 1 minute"
        echo -e " 2. 5 minutes"
        echo -e " 3. 15 minutes"
        echo -e " 4. 30 minutes"
        echo -e " 5. 1 hour"
        echo -e " 6. 12 hours"
        echo -e " 7. 1 day"
        echo -e " 8. Remove cronjob"
        echo -e " 9. Back to service menu"
        echo ""
       
        read -p "Choose option [1-9]: " cron_choice
       
        case $cron_choice in
            1)
                add_auto_restart_cronjob "$service_name" "1min"
                read -p "Press Enter to continue..."
                ;;
            2)
                add_auto_restart_cronjob "$service_name" "5min"
                read -p "Press Enter to continue..."
                ;;
            3)
                add_auto_restart_cronjob "$service_name" "15min"
                read -p "Press Enter to continue..."
                ;;
            4)
                add_auto_restart_cronjob "$service_name" "30min"
                read -p "Press Enter to continue..."
                ;;
            5)
                add_auto_restart_cronjob "$service_name" "1hour"
                read -p "Press Enter to continue..."
                ;;
            6)
                add_auto_restart_cronjob "$service_name" "12hour"
                read -p "Press Enter to continue..."
                ;;
            7)
                add_auto_restart_cronjob "$service_name" "1day"
                read -p "Press Enter to continue..."
                ;;
            8)
                remove_cronjob "$service_name"
                read -p "Press Enter to continue..."
                ;;
            9)
                return
                ;;
            *)
                print_error "Invalid choice"
                ;;
        esac
    done
}
# ──────────────────────────────────────────────────────────────
# Configure as Server (Abroad/Kharej)
# ──────────────────────────────────────────────────────────────
configure_server() {
    while true; do
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Configure as Server (Abroad/Kharej) ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        get_network_info
        local public_ip=$(get_public_ip)
        echo -e "${YELLOW}Detected Network Information${NC}"
        echo -e "┌──────────────────────────────────────────────────────────────┐"
        printf "│ %-12s : %-44s │\n" "Interface" "${NETWORK_INTERFACE:-Not found}"
        printf "│ %-12s : %-44s │\n" "Local IP" "${LOCAL_IP:-Not found}"
        printf "│ %-12s : %-44s │\n" "Public IP" "${public_ip}"
        printf "│ %-12s : %-44s │\n" "Gateway MAC" "${GATEWAY_MAC:-Not found}"
        echo -e "└──────────────────────────────────────────────────────────────┘"
        echo ""
        echo -e "${CYAN}Server Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        # [1/13] Service Name
        echo -en "${YELLOW}[1/13] Service Name (e.g: myserver) : ${NC}"
        read -r config_name
        config_name="${config_name:-server}"
        config_name=$(clean_config_name "$config_name")
        echo -e "[1/13] Service Name : ${CYAN}$config_name${NC}"
        if [ -f "$CONFIG_DIR/${config_name}.yaml" ]; then
            print_warning "Config '$config_name' already exists!"
            read -p "Overwrite? (y/N): " ow
            [[ ! "$ow" =~ ^[Yy]$ ]] && continue
        fi
        # [2/13] Listen Port
        echo -en "${YELLOW}[2/13] Listen Port (e.g: 443 or 8443) : ${NC}"
        read -r port
        port="${port:-8888}"
        if ! validate_port "$port"; then
            print_error "Invalid port"; sleep 1.5; continue
        fi
        echo -e "[2/13] Listen Port : ${CYAN}$port${NC}"
        if ! check_port_conflict "$port"; then
            read -p "Press Enter to retry..." ; continue
        fi
        # [3/13] Secret Key
        local secret_key=$(generate_secret_key)
        echo -e "${YELLOW}[3/13] Secret Key : ${GREEN}$secret_key${NC} (press Enter for auto-generate)"
        read -p "Use this key? (Y/n): " use
        if [[ "$use" =~ ^[Nn]$ ]]; then
            echo -en "${YELLOW}[3/13] Secret Key : ${NC}"
            read -r secret_key
            [ ${#secret_key} -lt 8 ] && { print_error "Too short (min 8)"; continue; }
        fi
        echo -e "[3/13] Secret Key : ${GREEN}$secret_key${NC}"
        # ── KCP Mode Selection ──
        echo ""
        echo -e "${CYAN}KCP Mode Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo " [0/4] normal - Normal speed / Normal latency / Low usage"
        echo " [1/4] fast - Balanced speed / Low latency / Normal usage (default)"
        echo " [2/4] fast2 - High speed / Lower latency / Medium usage"
        echo " [3/4] fast3 - Max speed / Very low latency / High CPU"
        echo " [4/4] manual - Advanced settings"
        echo ""
        local mode_choice=1
        read -p "[4/13] Choose KCP mode [0-4] (default 1): " mc
        [[ -n "$mc" ]] && mode_choice="$mc"
        local mode_name
        case $mode_choice in
            0) mode_name="normal" ;;
            1) mode_name="fast" ;;
            2) mode_name="fast2" ;;
            3) mode_name="fast3" ;;
            4) mode_name="manual" ;;
            *) mode_name="fast" ;;
        esac
        echo -e "[4/13] KCP Mode : ${CYAN}$mode_name${NC}"
        # conn
        local conn_input=""
        local conn_display=""
        read -p "[5/13] Connections [1-32, 0=skip] (default 1): " conn_input
        if [ -z "$conn_input" ]; then
            conn_input="1"
            conn_display="1 (default)"
            conn="1"
        elif [ "$conn_input" = "0" ]; then
            conn=""
            conn_display="- (skipped)"
        else
            if [[ "$conn_input" =~ ^[1-9][0-9]?$ ]] && [ "$conn_input" -ge 1 ] && [ "$conn_input" -le 32 ]; then
                conn="$conn_input"
                conn_display="$conn_input"
            else
                echo -e "${YELLOW}Invalid value, using default 1${NC}"
                conn="1"
                conn_display="1 (corrected)"
            fi
        fi
        echo -e "[5/13] Connections (conn) : ${CYAN}$conn_display${NC}"
        # MTU
        local mtu_input=""
        local mtu_display=""
        read -p "[6/13] MTU [100-9000, 0=skip] (default 1350): " mtu_input
        if [ -z "$mtu_input" ]; then
            mtu_input="1350"
            mtu_display="1350 (default)"
            mtu="1350"
        elif [ "$mtu_input" = "0" ]; then
            mtu=""
            mtu_display="- (skipped)"
        else
            if [[ "$mtu_input" =~ ^[0-9]+$ ]] && [ "$mtu_input" -ge 100 ] && [ "$mtu_input" -le 9000 ]; then
                mtu="$mtu_input"
                mtu_display="$mtu_input"
            else
                echo -e "${YELLOW}Invalid value, using default 1350${NC}"
                mtu="1350"
                mtu_display="1350 (corrected)"
            fi
        fi
        echo -e "[6/13] MTU : ${CYAN}$mtu_display${NC}"
        # Encryption
        echo ""
        echo -e "${CYAN}Encryption Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo " [1/7] aes-128-gcm - Very high security / Very fast / Recommended (default)"
        echo " [2/7] aes - High security / Medium speed / General use"
        echo " [3/7] aes-128 - High security / Fast / Low CPU usage"
        echo " [4/7] aes-192 - Very high security / Medium speed / Moderate CPU usage"
        echo " [5/7] aes-256 - Maximum security / Slower / Higher CPU usage"
        echo " [6/7] none - No encryption / Max speed / Insecure"
        echo " [7/7] null - No encryption / Max speed / Insecure"
        echo ""
        local enc_choice=1
        read -p "[7/13] Choose encryption [1-7] (default 1): " ec
        [[ -n "$ec" ]] && enc_choice="$ec"
        local block
        case $enc_choice in
            1) block="aes-128-gcm" ;;
            2) block="aes" ;;
            3) block="aes-128" ;;
            4) block="aes-192" ;;
            5) block="aes-256" ;;
            6) block="none" ;;
            7) block="null" ;;
            *) block="aes-128-gcm" ;;
        esac
        echo -e "[7/13] Encryption : ${CYAN}$block${NC}"
        # pcap sockbuf (default for server: 8388608)
        local pcap_sockbuf_input=""
        local pcap_sockbuf_display=""
        read -p "[8/13] pcap sockbuf [default 8388608, 0=skip]: " pcap_sockbuf_input
        if [ -z "$pcap_sockbuf_input" ]; then
            pcap_sockbuf_input="8388608"
            pcap_sockbuf_display="8388608 (default)"
            pcap_sockbuf="8388608"
        elif [ "$pcap_sockbuf_input" = "0" ]; then
            pcap_sockbuf=""
            pcap_sockbuf_display="- (skipped)"
        else
            pcap_sockbuf="$pcap_sockbuf_input"
            pcap_sockbuf_display="$pcap_sockbuf_input"
        fi
        echo -e "[8/13] pcap sockbuf : ${CYAN}$pcap_sockbuf_display${NC}"
        # transport tcpbuf
        local transport_tcpbuf_input=""
        local transport_tcpbuf_display=""
        read -p "[9/13] transport tcpbuf [default 8192, 0=skip]: " transport_tcpbuf_input
        if [ -z "$transport_tcpbuf_input" ]; then
            transport_tcpbuf_input="8192"
            transport_tcpbuf_display="8192 (default)"
            transport_tcpbuf="8192"
        elif [ "$transport_tcpbuf_input" = "0" ]; then
            transport_tcpbuf=""
            transport_tcpbuf_display="- (skipped)"
        else
            transport_tcpbuf="$transport_tcpbuf_input"
            transport_tcpbuf_display="$transport_tcpbuf_input"
        fi
        echo -e "[9/13] transport tcpbuf : ${CYAN}$transport_tcpbuf_display${NC}"
        # transport udpbuf
        local transport_udpbuf_input=""
        local transport_udpbuf_display=""
        read -p "[10/13] transport udpbuf [default 4096, 0=skip]: " transport_udpbuf_input
        if [ -z "$transport_udpbuf_input" ]; then
            transport_udpbuf_input="4096"
            transport_udpbuf_display="4096 (default)"
            transport_udpbuf="4096"
        elif [ "$transport_udpbuf_input" = "0" ]; then
            transport_udpbuf=""
            transport_udpbuf_display="- (skipped)"
        else
            transport_udpbuf="$transport_udpbuf_input"
            transport_udpbuf_display="$transport_udpbuf_input"
        fi
        echo -e "[10/13] transport udpbuf : ${CYAN}$transport_udpbuf_display${NC}"
        # ── Manual parameters only if manual mode selected ──
        local kcp_fragment=""
        if [ "$mode_name" = "manual" ]; then
            echo ""
            echo -e "${YELLOW}Manual KCP Advanced Parameters${NC}"
            echo -e "────────────────────────────────────────────────────────────────"
            kcp_fragment=$(get_manual_kcp_settings "$block" "$mtu")
        else
            kcp_fragment="    mode: \"$mode_name\""$'\n'"    block: \"$block\""
            [ -n "$mtu" ] && kcp_fragment+=$'\n'"    mtu: $mtu"
        fi
        # [11/13] V2Ray Ports
        echo -en "${YELLOW}[11/13] V2Ray Ports (comma separated [e.g 333 or 333,444,555]) : ${NC}"
        read -r inbound_ports
        inbound_ports="${inbound_ports:-9090}"
        inbound_ports=$(clean_port_list "$inbound_ports")
        [ -z "$inbound_ports" ] && { print_error "No valid ports"; continue; }
        echo -e "[11/13] V2Ray Ports : ${CYAN}$inbound_ports${NC}"
        # ── Applying ──
        echo ""
        echo -e "${CYAN}Applying Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        if [ ! -f "$BIN_DIR/paqet" ]; then
            install_paqet || { print_error "Paqet binary install failed"; continue; }
        fi
        echo -e "[+] Configuring iptables (tcp / port $port)"
        configure_iptables "$port" "tcp"
        echo -e "[+] Firewall rules applied"
        mkdir -p "$CONFIG_DIR"
        # Build server config
        {
            echo "# Paqet Server Configuration"
            echo "role: \"server\""
            echo "log:"
            echo "  level: \"info\""
            echo "listen:"
            echo "  addr: \":$port\""
            echo "network:"
            echo "  interface: \"$NETWORK_INTERFACE\""
            echo "  ipv4:"
            echo "    addr: \"$LOCAL_IP:$port\""
            echo "    router_mac: \"$GATEWAY_MAC\""
            echo "  tcp:"
            echo "    local_flag: [\"PA\"]"
            # PCAP settings (optional)
            if [[ -n "$pcap_sockbuf" ]]; then
            echo "    pcap:"
            echo "      sockbuf: $pcap_sockbuf"
            fi
            echo "transport:"
            echo "  protocol: \"kcp\""
            [[ -n "$conn" ]] && echo "  conn: $conn"
            [[ -n "$transport_tcpbuf" ]] && \
                echo "  tcpbuf: $transport_tcpbuf"
            [[ -n "$transport_udpbuf" ]] && \
                echo "  udpbuf: $transport_udpbuf"
            echo "  kcp:"
            echo "    key: \"$secret_key\""
            if [ -n "$kcp_fragment" ]; then
                echo "$kcp_fragment"
            fi
        } > "$CONFIG_DIR/${config_name}.yaml"
        echo -e "[+] Configuration saved : ${CYAN}$CONFIG_DIR/${config_name}.yaml${NC}"
        create_systemd_service "$config_name"
        local svc="paqet-${config_name}"
        systemctl enable "$svc" --now >/dev/null 2>&1
        echo -e "[+] Service created : ${CYAN}$svc${NC}"
        echo -e "[+] Service enabled (systemd)"
        if systemctl is-active --quiet "$svc"; then
            echo -e "[+] Server started successfully"
            add_auto_restart_cronjob "$svc" "15min" >/dev/null 2>&1
            echo -e "[+] Auto-restart enabled : every 15 minutes"
            echo ""
            echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║ Server Ready ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "${YELLOW}Server Information${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Public IP" "$public_ip"
            printf "│ %-14s : %-44s │\n" "Listen Port" "$port"
            printf "│ %-14s : %-44s │\n" "V2Ray Ports" "$inbound_ports"
            printf "│ %-14s : %-44s │\n" "Connections" "${conn:-1}"
            printf "│ %-14s : %-44s │\n" "Auto Restart" "Every 15 minutes"
            echo -e "└──────────────────────────────────────────────────────────────┘"
            echo ""
            echo -e "${YELLOW}Secret Key (Client Configuration)${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-60s │\n" "$secret_key"
            echo -e "└──────────────────────────────────────────────────────────────┘"
            echo ""
            echo -e "${YELLOW}KCP Configuration${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Mode" "$mode_name"
            printf "│ %-14s : %-44s │\n" "Encryption" "$block"
            printf "│ %-14s : %-44s │\n" "MTU" "${mtu:-1350}"
            echo -e "└──────────────────────────────────────────────────────────────┘"
        else
            print_error "Service failed to start"
            systemctl status "$svc" --no-pager -l
        fi
        echo ""
        read -p "Press Enter to return to menu..."
        return 0
    done
}
# ──────────────────────────────────────────────────────────────
# Configure as Client (Iran/Domestic)
# ──────────────────────────────────────────────────────────────
configure_client() {
    while true; do
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Configure as Client (Iran/Domestic) ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        get_network_info
        local public_ip=$(get_public_ip)
        echo -e "${YELLOW}Detected Network Information${NC}"
        echo -e "┌──────────────────────────────────────────────────────────────┐"
        printf "│ %-12s : %-44s │\n" "Interface" "${NETWORK_INTERFACE:-Not found}"
        printf "│ %-12s : %-44s │\n" "Local IP" "${LOCAL_IP:-Not found}"
        printf "│ %-12s : %-44s │\n" "Public IP" "${public_ip}"
        printf "│ %-12s : %-44s │\n" "Gateway MAC" "${GATEWAY_MAC:-Not found}"
        echo -e "└──────────────────────────────────────────────────────────────┘"
        echo ""
        echo -e "${CYAN}Client Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        # [1/15] Service Name
        echo -en "${YELLOW}[1/15] Service Name (e.g: myserver) : ${NC}"
        read -r config_name
        config_name="${config_name:-client}"
        config_name=$(clean_config_name "$config_name")
        echo -e "[1/15] Service Name : ${CYAN}$config_name${NC}"
        if [ -f "$CONFIG_DIR/${config_name}.yaml" ]; then
            print_warning "Config already exists!"
            read -p "Overwrite? (y/N): " ow
            [[ ! "$ow" =~ ^[Yy]$ ]] && continue
        fi
        # [2/15] Server IP
        echo -en "${YELLOW}[2/15] Server IP (kharej e.g: 45.76.123.89) : ${NC}"
        read -r server_ip
        [ -z "$server_ip" ] && { print_error "Server IP required"; continue; }
        validate_ip "$server_ip" || { print_error "Invalid IP format"; continue; }
        echo -e "[2/15] Server IP : ${CYAN}$server_ip${NC}"
        # [3/15] Server Port
        echo -en "${YELLOW}[3/15] Server Port (e.g: 443) : ${NC}"
        read -r server_port
        server_port="${server_port:-8888}"
        validate_port "$server_port" || { print_error "Invalid port"; continue; }
        echo -e "[3/15] Server Port : ${CYAN}$server_port${NC}"
        # [4/15] Secret Key
        echo -en "${YELLOW}[4/15] Secret Key (e.g: xY7pK9mN2qR4sT6wV8yZ0) : ${NC}"
        read -r secret_key
        [ -z "$secret_key" ] && { print_error "Secret key required"; continue; }
        echo -e "[4/15] Secret Key : ${GREEN}$secret_key${NC}"
        # KCP Mode (same as server)
        echo ""
        echo -e "${CYAN}KCP Mode Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo " [0/4] normal - Normal speed / Normal latency / Low usage"
        echo " [1/4] fast - Balanced speed / Low latency / Normal usage (default)"
        echo " [2/4] fast2 - High speed / Lower latency / Medium usage"
        echo " [3/4] fast3 - Max speed / Very low latency / High CPU"
        echo " [4/4] manual - Advanced settings"
        echo ""
        local mode_choice=1
        read -p "[5/15] Choose KCP mode [0-4] (default 1): " mc
        [[ -n "$mc" ]] && mode_choice="$mc"
        local mode_name
        case $mode_choice in
            0) mode_name="normal" ;;
            1) mode_name="fast" ;;
            2) mode_name="fast2" ;;
            3) mode_name="fast3" ;;
            4) mode_name="manual" ;;
            *) mode_name="fast" ;;
        esac
        echo -e "[5/15] KCP Mode : ${CYAN}$mode_name${NC}"
        # conn
        local conn_input=""
        local conn_display=""
        read -p "[6/15] Connections (conn) [1-32, 0=skip] (default 1): " conn_input
        if [ -z "$conn_input" ]; then
            conn_input="1"
            conn_display="1 (default)"
            conn="1"
        elif [ "$conn_input" = "0" ]; then
            conn=""
            conn_display="- (skipped)"
        else
            if [[ "$conn_input" =~ ^[1-9][0-9]?$ ]] && [ "$conn_input" -ge 1 ] && [ "$conn_input" -le 32 ]; then
                conn="$conn_input"
                conn_display="$conn_input"
            else
                echo -e "${YELLOW}Invalid value, using default 1${NC}"
                conn="1"
                conn_display="1 (corrected)"
            fi
        fi
        echo -e "[6/15] Connections (conn) : ${CYAN}$conn_display${NC}"
        # MTU
        local mtu_input=""
        local mtu_display=""
        read -p "[7/15] MTU [100-9000, 0=skip] (default 1350): " mtu_input
        if [ -z "$mtu_input" ]; then
            mtu_input="1350"
            mtu_display="1350 (default)"
            mtu="1350"
        elif [ "$mtu_input" = "0" ]; then
            mtu=""
            mtu_display="- (skipped)"
        else
            if [[ "$mtu_input" =~ ^[0-9]+$ ]] && [ "$mtu_input" -ge 100 ] && [ "$mtu_input" -le 9000 ]; then
                mtu="$mtu_input"
                mtu_display="$mtu_input"
            else
                echo -e "${YELLOW}Invalid value, using default 1350${NC}"
                mtu="1350"
                mtu_display="1350 (corrected)"
            fi
        fi
        echo -e "[7/15] MTU : ${CYAN}$mtu_display${NC}"
        # Encryption (same list as server)
        echo ""
        echo -e "${CYAN}Encryption Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo " [1/7] aes-128-gcm - Very high security / Very fast / Recommended (default)"
        echo " [2/7] aes - High security / Medium speed / General use"
        echo " [3/7] aes-128 - High security / Fast / Low CPU usage"
        echo " [4/7] aes-192 - Very high security / Medium speed / Moderate CPU usage"
        echo " [5/7] aes-256 - Maximum security / Slower / Higher CPU usage"
        echo " [6/7] none - No encryption / Max speed / Insecure"
        echo " [7/7] null - No encryption / Max speed / Insecure"
        echo ""
        local enc_choice=1
        read -p "[8/15] Choose encryption [1-7] (default 1): " ec
        [[ -n "$ec" ]] && enc_choice="$ec"
        local block
        case $enc_choice in
            1) block="aes-128-gcm" ;;
            2) block="aes" ;;
            3) block="aes-128" ;;
            4) block="aes-192" ;;
            5) block="aes-256" ;;
            6) block="none" ;;
            7) block="null" ;;
            *) block="aes-128-gcm" ;;
        esac
        echo -e "[8/15] Encryption : ${CYAN}$block${NC}"
        # pcap sockbuf (default for client: 4194304)
        local pcap_sockbuf_input=""
        local pcap_sockbuf_display=""
        read -p "[9/15] pcap sockbuf [default 4194304, 0=skip]: " pcap_sockbuf_input
        if [ -z "$pcap_sockbuf_input" ]; then
            pcap_sockbuf_input="4194304"
            pcap_sockbuf_display="4194304 (default)"
            pcap_sockbuf="4194304"
        elif [ "$pcap_sockbuf_input" = "0" ]; then
            pcap_sockbuf=""
            pcap_sockbuf_display="- (skipped)"
        else
            pcap_sockbuf="$pcap_sockbuf_input"
            pcap_sockbuf_display="$pcap_sockbuf_input"
        fi
        echo -e "[9/15] pcap sockbuf : ${CYAN}$pcap_sockbuf_display${NC}"
        # transport tcpbuf
        local transport_tcpbuf_input=""
        local transport_tcpbuf_display=""
        read -p "[10/15] transport tcpbuf [default 8192, 0=skip]: " transport_tcpbuf_input
        if [ -z "$transport_tcpbuf_input" ]; then
            transport_tcpbuf_input="8192"
            transport_tcpbuf_display="8192 (default)"
            transport_tcpbuf="8192"
        elif [ "$transport_tcpbuf_input" = "0" ]; then
            transport_tcpbuf=""
            transport_tcpbuf_display="- (skipped)"
        else
            transport_tcpbuf="$transport_tcpbuf_input"
            transport_tcpbuf_display="$transport_tcpbuf_input"
        fi
        echo -e "[10/15] transport tcpbuf : ${CYAN}$transport_tcpbuf_display${NC}"
        # transport udpbuf
        local transport_udpbuf_input=""
        local transport_udpbuf_display=""
        read -p "[11/15] transport udpbuf [default 4096, 0=skip]: " transport_udpbuf_input
        if [ -z "$transport_udpbuf_input" ]; then
            transport_udpbuf_input="4096"
            transport_udpbuf_display="4096 (default)"
            transport_udpbuf="4096"
        elif [ "$transport_udpbuf_input" = "0" ]; then
            transport_udpbuf=""
            transport_udpbuf_display="- (skipped)"
        else
            transport_udpbuf="$transport_udpbuf_input"
            transport_udpbuf_display="$transport_udpbuf_input"
        fi
        echo -e "[11/15] transport udpbuf : ${CYAN}$transport_udpbuf_display${NC}"
        # ── Manual parameters only if manual mode selected ──
        local kcp_fragment=""
        if [ "$mode_name" = "manual" ]; then
            echo ""
            echo -e "${YELLOW}Manual KCP Advanced Parameters${NC}"
            echo -e "────────────────────────────────────────────────────────────────"
            kcp_fragment=$(get_manual_kcp_settings "$block" "$mtu")
        else
            kcp_fragment="    mode: \"$mode_name\""$'\n'"    block: \"$block\""
            [ -n "$mtu" ] && kcp_fragment+=$'\n'"    mtu: $mtu"
        fi
        # [12/15] Forward Ports
        echo -en "${YELLOW}[12/15] Forward Ports (comma separated [e.g 333 or 333,444,555]) : ${NC}"
        read -r forward_ports
        forward_ports="${forward_ports:-9090}"
        forward_ports=$(clean_port_list "$forward_ports")
        [ -z "$forward_ports" ] && { print_error "No valid ports"; continue; }
        echo -e "[12/15] Forward Ports : ${CYAN}$forward_ports${NC}"
        # Protocol per port
        echo ""
        echo -e "${CYAN}Protocol Selection${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        echo " [1/3] tcp - TCP only (default)"
        echo " [2/3] udp - UDP only"
        echo " [3/3] tcp/udp - Both (TCP + UDP)"
        echo ""
        local forward_entries=()
        local display_ports=""
        IFS=',' read -ra PORTS <<< "$forward_ports"
        for p in "${PORTS[@]}"; do
            p=$(echo "$p" | tr -d '[:space:]')
            echo -en "${YELLOW}Port $p → protocol [1-3] : ${NC}"
            read -r proto_choice
            proto_choice="${proto_choice:-1}"
            case $proto_choice in
                1) # TCP only
                    forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                    display_ports+=" $p (TCP)"
                    configure_iptables "$p" "tcp"
                    ;;
                2) # UDP only
                    forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"udp\"")
                    display_ports+=" $p (UDP)"
                    configure_iptables "$p" "udp"
                    ;;
                3) # Both TCP + UDP
                    forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                    forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"udp\"")
                    display_ports+=" $p (TCP+UDP)"
                    configure_iptables "$p" "both"
                    ;;
                *)
                    forward_entries+=("  - listen: \"0.0.0.0:$p\"\n    target: \"127.0.0.1:$p\"\n    protocol: \"tcp\"")
                    display_ports+=" $p (TCP)"
                    configure_iptables "$p" "tcp"
                    ;;
            esac
        done
        echo -e "[12/15] Protocol(s) : ${CYAN}${display_ports# }${NC}"
        # ── Applying ──
        echo ""
        echo -e "${CYAN}Applying Configuration${NC}"
        echo -e "────────────────────────────────────────────────────────────────"
        if [ ! -f "$BIN_DIR/paqet" ]; then
            install_paqet || continue
        fi
        echo -e "[+] Configuring iptables for forwarded ports"
        echo -e "[+] Firewall rules applied"
        mkdir -p "$CONFIG_DIR"
        {
            echo "# Paqet Client Configuration"
            echo "role: \"client\""
            echo "log:"
            echo "  level: \"info\""
            echo "forward:"
            for line in "${forward_entries[@]}"; do
                echo -e "$line"
            done
            echo "network:"
            echo "  interface: \"$NETWORK_INTERFACE\""
            echo "  ipv4:"
            echo "    addr: \"$LOCAL_IP:0\""
            echo "    router_mac: \"$GATEWAY_MAC\""
            echo "  tcp:"
            echo "    local_flag: [\"PA\"]"
            echo "    remote_flag: [\"PA\"]"

            # PCAP settings (optional)
            if [[ -n "$pcap_sockbuf" ]]; then
            echo "    pcap:"
            echo "      sockbuf: $pcap_sockbuf"
            fi
            echo "server:"
            echo "  addr: \"$server_ip:$server_port\""
            echo "transport:"
            echo "  protocol: \"kcp\""
            [[ -n "$conn" ]] && echo "  conn: $conn"
            [[ -n "$transport_tcpbuf" ]] && \
                echo "  tcpbuf: $transport_tcpbuf"
            [[ -n "$transport_udpbuf" ]] && \
                echo "  udpbuf: $transport_udpbuf"
            echo "  kcp:"
            echo "    key: \"$secret_key\""
            if [ -n "$kcp_fragment" ]; then
                echo "$kcp_fragment"
            fi
        } > "$CONFIG_DIR/${config_name}.yaml"
        echo -e "[+] Configuration saved : ${CYAN}$CONFIG_DIR/${config_name}.yaml${NC}"
        create_systemd_service "$config_name"
        local svc="paqet-${config_name}"
        systemctl enable "$svc" --now >/dev/null 2>&1
        echo -e "[+] Service created : ${CYAN}$svc${NC}"
        echo -e "[+] Service enabled (systemd)"
        if systemctl is-active --quiet "$svc"; then
            echo -e "[+] Client started successfully"
            add_auto_restart_cronjob "$svc" "15min" >/dev/null 2>&1
            echo -e "[+] Auto-restart enabled : every 15 minutes"
            echo ""
            echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
            echo -e "${GREEN}║ Client Ready ║${NC}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            echo -e "${YELLOW}Client Information${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-16s : %-42s │\n" "This Server" "$public_ip"
            printf "│ %-16s : %-42s │\n" "Remote Server" "$server_ip:$server_port"
            printf "│ %-16s : %-42s │\n" "Forward Ports" "${display_ports# }"
            printf "│ %-16s : %-42s │\n" "Connections" "${conn:-1}"
            printf "│ %-16s : %-42s │\n" "Auto Restart" "Every 15 minutes"
            echo -e "└──────────────────────────────────────────────────────────────┘"
            echo ""
            echo -e "${YELLOW}Client Connection${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Connect To" "$public_ip"
            printf "│ %-14s : %-44s │\n" "Ports" "${display_ports# }"
            echo -e "└──────────────────────────────────────────────────────────────┘"
            echo ""
            echo -e "${YELLOW}KCP Configuration${NC}"
            echo -e "┌──────────────────────────────────────────────────────────────┐"
            printf "│ %-14s : %-44s │\n" "Mode" "$mode_name"
            printf "│ %-14s : %-44s │\n" "Encryption" "$block"
            printf "│ %-14s : %-44s │\n" "MTU" "${mtu:-1350}"
            echo -e "└──────────────────────────────────────────────────────────────┘"
        else
            print_error "Client failed to start"
            systemctl status "$svc" --no-pager -l
        fi
        echo ""
        read -p "Press Enter to return to menu..."
        return 0
    done
}

# ──────────────────────────────────────────────────────────────
# Test Connection
# ──────────────────────────────────────────────────────────────
test_connection() {
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Test Paqet Connection                                     ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    echo -e "${CYAN}Connection Test Options:${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    echo " 1. Test Paqet tunnel connection (server to server)"
    echo " 2. Test internet connectivity"
    echo " 3. Test DNS resolution"
    echo " 4. Back to Main Menu"
    echo ""
    
    while true; do
        read -p "Choose option [1-4]: " test_choice
        
        case $test_choice in
            1)
                test_paqet_tunnel
                break
                ;;
            2)
                test_internet_connectivity
                break
                ;;
            3)
                test_dns_resolution
                break
                ;;
            4)
                return
                ;;
            *)
                print_error "Invalid choice. Please enter 1-4."
                ;;
        esac
    done
}

# Test internet connectivity
test_internet_connectivity() {
    echo ""
    echo -e "${YELLOW}Internet Connectivity Test${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    print_step "Testing internet connectivity..."
    echo ""
    
    # List of reliable test servers
    local test_hosts=(
        "8.8.8.8"       # Google DNS
        "1.1.1.1"       # Cloudflare DNS
        "208.67.222.222" # OpenDNS
    )
    
    local success_count=0
    local total_tests=${#test_hosts[@]}
    
    for host in "${test_hosts[@]}"; do
        echo -n "   Testing connection to $host: "
        if ping -c 2 -W 1 "$host" &>/dev/null; then
            echo -e "${GREEN}✓ CONNECTED${NC}"
            ((success_count++))
        else
            echo -e "${RED}✗ FAILED${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}Test Results:${NC}"
    
    if [ "$success_count" -eq "$total_tests" ]; then
        print_success "✅ Internet connectivity: EXCELLENT (${success_count}/${total_tests} successful)"
    elif [ "$success_count" -ge $((total_tests / 2)) ]; then
        print_warning "⚠️  Internet connectivity: PARTIAL (${success_count}/${total_tests} successful)"
    else
        print_error "❌ Internet connectivity: POOR (${success_count}/${total_tests} successful)"
    fi
    
    # Test download speed if connected
    if [ "$success_count" -gt 0 ]; then
        echo ""
        print_step "Testing download speed (small test)..."
        
        # Try to download a test file (small size)
        local speed_test=$(timeout 10 curl -o /dev/null -w "%{speed_download}" --max-filesize 10485760 https://speedtest.ftp.otenet.gr/files/test10Mb.db 2>/dev/null || echo "0")
        
        if [ "$speed_test" != "0" ] && [ ! -z "$speed_test" ]; then
            # Check if bc is available
            if command -v bc >/dev/null 2>&1; then
                local speed_mbps=$(echo "scale=2; $speed_test * 8 / 1000000" | bc 2>/dev/null || echo "0")
                
                if (( $(echo "$speed_mbps > 10" | bc -l 2>/dev/null) )); then
                    echo -e "   ${GREEN}✅ Download speed: ${speed_mbps} Mbps${NC}"
                elif (( $(echo "$speed_mbps > 1" | bc -l 2>/dev/null) )); then
                    echo -e "   ${YELLOW}⚠️  Download speed: ${speed_mbps} Mbps${NC}"
                else
                    echo -e "   ${RED}❌ Download speed: ${speed_mbps} Mbps${NC}"
                fi
            else
                # Simple calculation without bc
                local speed_mbps_int=$(( (${speed_test%.*} * 8) / 1000000 ))
                if [ "$speed_mbps_int" -gt 10 ]; then
                    echo -e "   ${GREEN}✅ Download speed: ~${speed_mbps_int} Mbps${NC}"
                elif [ "$speed_mbps_int" -gt 1 ]; then
                    echo -e "   ${YELLOW}⚠️  Download speed: ~${speed_mbps_int} Mbps${NC}"
                else
                    echo -e "   ${RED}❌ Download speed: ~${speed_mbps_int} Mbps${NC}"
                fi
            fi
        else
            echo -e "   ${YELLOW}⚠️  Speed test failed or timed out${NC}"
        fi
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    test_connection
}

# Test DNS resolution
test_dns_resolution() {
    echo ""
    echo -e "${YELLOW}DNS Resolution Test${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    print_step "Testing DNS resolution..."
    echo ""
    
    # List of test domains
    local test_domains=(
        "google.com"
        "github.com"
        "cloudflare.com"
        "wikipedia.org"
    )
    
    local dns_servers=(
        "8.8.8.8"       # Google DNS
        "1.1.1.1"       # Cloudflare DNS
        "208.67.222.222" # OpenDNS
        "system"        # System DNS
    )
    
    echo -e "${CYAN}Testing domain resolution:${NC}"
    echo ""
    
    local resolved_count=0
    local total_domains=${#test_domains[@]}
    
    for domain in "${test_domains[@]}"; do
        echo -n "   $domain: "
        if timeout 3 dig +short "$domain" &>/dev/null; then
            echo -e "${GREEN}✓ RESOLVED${NC}"
            ((resolved_count++))
        else
            echo -e "${RED}✗ FAILED${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}Testing DNS servers:${NC}"
    echo ""
    
    for dns in "${dns_servers[@]}"; do
        echo -n "   $dns: "
        
        if [ "$dns" = "system" ]; then
            # Test with system DNS
            if timeout 3 nslookup google.com &>/dev/null; then
                echo -e "${GREEN}✓ WORKING${NC}"
            else
                echo -e "${RED}✗ FAILED${NC}"
            fi
        else
            # Test with specific DNS server
            if timeout 3 dig +short google.com @"$dns" &>/dev/null; then
                echo -e "${GREEN}✓ WORKING${NC}"
            else
                echo -e "${RED}✗ FAILED${NC}"
            fi
        fi
    done
    
    echo ""
    echo -e "${CYAN}Summary:${NC}"
    
    if [ "$resolved_count" -eq "$total_domains" ]; then
        print_success "✅ DNS resolution: PERFECT (${resolved_count}/${total_domains} domains resolved)"
    elif [ "$resolved_count" -ge $((total_domains / 2)) ]; then
        print_warning "⚠️  DNS resolution: PARTIAL (${resolved_count}/${total_domains} domains resolved)"
    else
        print_error "❌ DNS resolution: POOR (${resolved_count}/${total_domains} domains resolved)"
        
        echo ""
        echo -e "${YELLOW}Troubleshooting tips:${NC}"
        echo "   1. Check /etc/resolv.conf configuration"
        echo "   2. Try changing DNS servers to 8.8.8.8 or 1.1.1.1"
        echo "   3. Check firewall rules for DNS (port 53)"
        echo "   4. Ensure systemd-resolved is running (if applicable)"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
    test_connection
}

compare_floats() {
    local value=$1
    local threshold=$2
    local comparison=$3
    
    if ! command -v bc >/dev/null 2>&1; then
        local value_int=${value%.*}
        local threshold_int=${threshold%.*}
        
        case $comparison in
            "lt") [[ "$value_int" -lt "$threshold_int" ]] ;;
            "le") [[ "$value_int" -le "$threshold_int" ]] ;;
            "gt") [[ "$value_int" -gt "$threshold_int" ]] ;;
            "ge") [[ "$value_int" -ge "$threshold_int" ]] ;;
            *) return 1 ;;
        esac
        return $?
    fi
    
    case $comparison in
        "lt")
            result=$(echo "$value < $threshold" | bc -l 2>/dev/null || echo "0")
            [[ "$result" -eq 1 ]]
            ;;
        "le")
            result=$(echo "$value <= $threshold" | bc -l 2>/dev/null || echo "0")
            [[ "$result" -eq 1 ]]
            ;;
        "gt")
            result=$(echo "$value > $threshold" | bc -l 2>/dev/null || echo "0")
            [[ "$result" -eq 1 ]]
            ;;
        "ge")
            result=$(echo "$value >= $threshold" | bc -l 2>/dev/null || echo "0")
            [[ "$result" -eq 1 ]]
            ;;
        *)
            return 1
            ;;
    esac
}

# Helper function to extract ping statistics
extract_ping_stats() {
    local ping_output="$1"
    local min="" avg="" max="" mdev=""
    local rtt_line=$(echo "$ping_output" | grep "rtt min/avg/max/mdev")
    
    if [ -n "$rtt_line" ]; then
        local stats=$(echo "$rtt_line" | sed 's/.*= //' | sed 's/ ms//')
        IFS='/' read -ra stat_array <<< "$stats"
        
        min="${stat_array[0]}"
        avg="${stat_array[1]}"
        max="${stat_array[2]}"
        mdev="${stat_array[3]}"
    fi
    
    echo "$min,$avg,$max,$mdev"
}

test_paqet_tunnel() {
    echo ""
    echo -e "${YELLOW}Test Paqet Tunnel Connection${NC}"
    echo -e "────────────────────────────────────────────────────────────────"
    
    echo -e "${CYAN}This test will check if you can establish a Paqet tunnel between two servers.${NC}"
    echo ""
    
    echo -en "${YELLOW}Remote Server IP Address: ${NC}"
    read -r remote_ip
    [ -z "$remote_ip" ] && { print_error "IP address required"; test_paqet_tunnel; return; }
    
    if ! validate_ip "$remote_ip"; then
        print_error "Invalid IP address format"
        test_paqet_tunnel
        return
    fi
    
    echo ""
    print_step "Starting comprehensive Paqet tunnel test to $remote_ip..."
    echo ""
    
    # 1. First check basic connectivity
    print_step "1. Testing basic ICMP connectivity..."
    
    local ping_output ping_stats avg_ping packet_loss sent received loss_percent
    ping_output=$(ping -c 5 -W 2 "$remote_ip" 2>&1)
    
    if [ $? -eq 0 ] || echo "$ping_output" | grep -q "transmitted"; then
        ping_stats=$(echo "$ping_output" | tail -2)
        packet_loss=$(echo "$ping_stats" | grep -o "[0-9]*% packet loss" | grep -o "[0-9]*" || echo "0")
        
        if echo "$ping_output" | grep -q "rtt min/avg/max/mdev"; then
            avg_ping=$(echo "$ping_output" | grep "rtt min/avg/max/mdev" | awk -F'/' '{print $5}')
        else
            avg_ping=""
        fi
        
        print_success "✅ Basic ICMP connectivity: SUCCESS"
        echo -e "   ${CYAN}Details:${NC} Avg RTT: ${avg_ping:-N/A} ms, Packet loss: ${packet_loss}%"
    else
        print_warning "⚠️  Basic ICMP: FAILED (server may block ICMP, this is normal for some hosts)"
        avg_ping=""
        packet_loss="100"
    fi
    
    # 2. Test common Paqet ports
    echo ""
    print_step "2. Testing common Paqet ports..."
    
    local common_ports=("443" "80")
    local paqet_ports_found=0
    
    for port in "${common_ports[@]}"; do
        echo -n "   Port $port: "
        if timeout 3 bash -c "</dev/tcp/$remote_ip/$port" 2>/dev/null; then
            echo -e "${GREEN}OPEN${NC}"
            ((paqet_ports_found++))
        else
            echo -e "${CYAN}Closed/Filtered${NC}"
        fi
        sleep 0.1
    done
    
    if [ $paqet_ports_found -eq 0 ]; then
        print_warning "⚠️  No common Paqet ports found open"
        echo -e "${CYAN}Note:${NC} You may need to know the specific port your Paqet server is using"
    else
        print_success "✅ Found $paqet_ports_found open port(s) suitable for Paqet"
    fi
    
    # 3. Test firewall/routing
    echo ""
    print_step "3. Testing firewall and routing..."
    
    local can_connect_any=false
    local test_ports=("80" "443" "22" "53")
    
    for port in "${test_ports[@]}"; do
        if timeout 3 bash -c "</dev/tcp/$remote_ip/$port" 2>/dev/null; then
            can_connect_any=true
            echo -e "   ${CYAN}Port $port:${NC} OPEN (general TCP works)"
            break
        fi
    done
    
    if [ "$can_connect_any" = true ]; then
        print_success "✅ General TCP connectivity: OK (firewall allows some traffic)"
    else
        print_warning "⚠️  General TCP connectivity: RESTRICTED (firewall may be strict)"
    fi
    
    # 4. Advanced MTU testing with packet loss analysis
    echo ""
    print_step "4. Advanced MTU and packet loss analysis..."
    
    local mtu_tests=(
        "1500"
        "1470"
        "1400"
        "1350"
        "1300"
        "1200"
        "1100"
    )
    
    local best_mtu=""
    local best_loss=100
    local best_ping=9999
    
    echo -e "${CYAN}Testing different MTU sizes (10 packets each):${NC}"
    echo ""
    
    for mtu in "${mtu_tests[@]}"; do
        local payload_size=$((mtu - 28))
        
        if [ $payload_size -lt 0 ]; then
            continue
        fi
        
        echo -n "   MTU $mtu: "
        
        # Send packets with specific size
        local ping_output=$(ping -c 10 -W 1 -M do -s $payload_size "$remote_ip" 2>&1)
        
        if echo "$ping_output" | grep -q "transmitted"; then
            sent=$(echo "$ping_output" | grep transmitted | awk '{print $1}')
            received=$(echo "$ping_output" | grep transmitted | awk '{print $4}')
            loss_percent=$(( (sent - received) * 100 / sent ))
            local stats=$(extract_ping_stats "$ping_output")
            IFS=',' read -r min avg max mdev <<< "$stats"
            
            if [ "$received" -eq "$sent" ]; then
                echo -e "${GREEN}PERFECT${NC} - 0% loss"
                if [ -z "$best_mtu" ] || ( [ -n "$avg" ] && compare_floats "$avg" "$best_ping" "lt" ); then
                    best_mtu="$mtu"
                    best_loss=0
                    best_ping="$avg"
                fi
            elif [ "$loss_percent" -le 10 ]; then
                echo -e "${GREEN}GOOD${NC} - ${loss_percent}% loss (${received}/${sent} packets)"
                if [ "$loss_percent" -lt "$best_loss" ] || 
                   ([ "$loss_percent" -eq "$best_loss" ] && [ -n "$avg" ] && compare_floats "$avg" "$best_ping" "lt" ); then
                    best_mtu="$mtu"
                    best_loss="$loss_percent"
                    best_ping="$avg"
                fi
            elif [ "$loss_percent" -le 30 ]; then
                echo -e "${YELLOW}FAIR${NC} - ${loss_percent}% loss (${received}/${sent} packets)"
            else
                echo -e "${RED}POOR${NC} - ${loss_percent}% loss (${received}/${sent} packets)"
            fi

            if [ -n "$min" ] && [ -n "$avg" ] && [ -n "$max" ]; then
                echo -e "        Min/Avg/Max: ${min}/${avg}/${max} ms"
            fi
        else
            echo -e "${RED}FAILED${NC} - No response"
        fi
    done
    
    # 5. Summary and recommendations
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Test Summary & Recommendations                             ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Connection quality assessment
    echo -e "${CYAN}Connection Quality Assessment:${NC}"
    
    if [ -n "$avg_ping" ]; then
        if compare_floats "$avg_ping" "50" "lt"; then
            echo -e "   ${GREEN}✅ Latency: EXCELLENT (< 50ms)${NC}"
        elif compare_floats "$avg_ping" "150" "lt"; then
            echo -e "   ${GREEN}✅ Latency: GOOD (< 150ms)${NC}"
        elif compare_floats "$avg_ping" "300" "lt"; then
            echo -e "   ${YELLOW}⚠️  Latency: FAIR (< 300ms)${NC}"
        else
            echo -e "   ${YELLOW}⚠️  Latency: HIGH (> 300ms)${NC}"
        fi
    else
        echo -e "   ${YELLOW}⚠️  Latency: UNKNOWN${NC}"
    fi
    
    if [ -n "$packet_loss" ]; then
        if [ "$packet_loss" -eq 0 ]; then
            echo -e "   ${GREEN}✅ Packet Loss: EXCELLENT (0%)${NC}"
        elif [ "$packet_loss" -le 5 ]; then
            echo -e "   ${GREEN}✅ Packet Loss: GOOD (≤ 5%)${NC}"
        elif [ "$packet_loss" -le 15 ]; then
            echo -e "   ${YELLOW}⚠️  Packet Loss: FAIR (≤ 15%)${NC}"
        else
            echo -e "   ${RED}❌ Packet Loss: HIGH (> 15%)${NC}"
        fi
    else
        echo -e "   ${YELLOW}⚠️  Packet Loss: UNKNOWN${NC}"
    fi
    
    # MTU recommendations
    echo ""
    echo -e "${CYAN}MTU Analysis Results:${NC}"
    
    if [ -n "$best_mtu" ]; then
        if [ "$best_loss" -eq 0 ]; then
            echo -e "   ${GREEN}✅ Best MTU: $best_mtu (0% packet loss)"
            if [ -n "$best_ping" ]; then
                if compare_floats "$best_ping" "100" "lt"; then
                    echo -e "        Ping performance: ${GREEN}EXCELLENT${NC} (${best_ping}ms)"
                elif compare_floats "$best_ping" "200" "lt"; then
                    echo -e "        Ping performance: ${GREEN}GOOD${NC} (${best_ping}ms)"
                else
                    echo -e "        Ping performance: ${YELLOW}ACCEPTABLE${NC} (${best_ping}ms)"
                fi
            fi
        else
            echo -e "   ${YELLOW}⚠️  Best MTU: $best_mtu (${best_loss}% packet loss)"
            echo -e "        Consider using MTU 1200 for better stability"
        fi
        
        # Show MTU recommendations
        echo ""
        echo -e "${CYAN}Recommended Paqet MTU Settings:${NC}"
        
        if [ "$best_mtu" -ge 1400 ]; then
            echo -e "   ${GREEN}• Primary: 1400${NC} (optimal for speed)"
            echo -e "   ${GREEN}• Secondary: 1350${NC} (balanced)"
            echo -e "   ${CYAN}• Fallback: 1300${NC} (stable)"
        elif [ "$best_mtu" -ge 1300 ]; then
            echo -e "   ${GREEN}• Primary: 1350${NC} (balanced)"
            echo -e "   ${GREEN}• Secondary: 1300${NC} (stable)"
            echo -e "   ${CYAN}• Fallback: 1200${NC} (reliable)"
        else
            echo -e "   ${YELLOW}• Primary: 1200${NC} (most reliable)"
            echo -e "   ${YELLOW}• Secondary: 1100${NC} (ultra stable)"
            echo -e "   ${CYAN}• Fallback: 1000${NC} (guaranteed)"
        fi
    else
        echo -e "   ${RED}❌ Could not determine optimal MTU${NC}"
        echo -e "   ${CYAN}Recommendation:${NC} Use MTU 1200 as default"
    fi
    
    # General recommendations
    echo ""
    echo -e "${CYAN}General Paqet Configuration Advice:${NC}"
    
    if [ -n "$packet_loss" ] && [ "$packet_loss" -gt 10 ]; then
        echo -e "   ${YELLOW}• Enable FEC (Forward Error Correction) in manual mode${NC}"
        echo -e "   ${YELLOW}• Use KCP mode 'fast' or 'normal' instead of 'fast3'${NC}"
        echo -e "   ${YELLOW}• Increase 'resend' parameter to 2-3${NC}"
    fi
    
    if [ -n "$avg_ping" ] && compare_floats "$avg_ping" "200" "gt"; then
        echo -e "   ${YELLOW}• Use KCP mode 'fast2' for better latency handling${NC}"
        echo -e "   ${YELLOW}• Increase 'rcvwnd' and 'sndwnd' to 4096${NC}"
        echo -e "   ${YELLOW}• Consider lower encryption like 'aes' instead of 'aes-256'${NC}"
    fi
    
    echo -e "   ${CYAN}• Always test with actual data after configuration${NC}"
    echo -e "   ${CYAN}• Monitor logs: journalctl -u paqet-<service_name> -f${NC}"
    
    echo ""
    echo -e "${GREEN}Ready to configure Paqet! 🚀${NC}"
    
    echo ""
    read -p "Press Enter to continue..."
    test_connection
}

# ──────────────────────────────────────────────────────────────
# Restart All Paqet Services
# ──────────────────────────────────────────────────────────────
restart_all_services() {
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Restart All Paqet Services                                 ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    # Get all paqet services
    local services=()
    mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                          grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
    
    if [[ ${#services[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No Paqet services found.${NC}"
        echo ""
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${CYAN}Found ${#services[@]} Paqet service(s):${NC}"
    echo ""
    
    local i=1
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        local status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
        
        printf " %2d. %-25s [%s]\n" "$i" "$display_name" "$status"
        ((i++))
    done
    
    echo ""
    read -p "Are you sure you want to restart ALL services? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Operation cancelled.${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo ""
    print_step "Restarting all Paqet services..."
    
    local success_count=0
    local fail_count=0
    
    for svc in "${services[@]}"; do
        local service_name="${svc%.service}"
        local display_name="${service_name#paqet-}"
        
        echo -n "  Restarting $display_name... "
        
        if systemctl restart "$svc" >/dev/null 2>&1; then
            sleep 1
            if systemctl is-active --quiet "$svc" 2>/dev/null; then
                echo -e "${GREEN}✅ SUCCESS${NC}"
                ((success_count++))
            else
                echo -e "${RED}❌ FAILED (not running after restart)${NC}"
                ((fail_count++))
            fi
        else
            echo -e "${RED}❌ FAILED${NC}"
            ((fail_count++))
        fi
    done
    
    echo ""
    echo -e "${CYAN}Results:${NC}"
    echo -e "  ${GREEN}✅ Success:${NC} $success_count service(s)"
    echo -e "  ${RED}❌ Failed:${NC} $fail_count service(s)"
    echo ""
    
    if [ $fail_count -eq 0 ]; then
        print_success "All services restarted successfully!"
    elif [ $success_count -eq 0 ]; then
        print_error "All services failed to restart!"
    else
        print_warning "Some services failed to restart"
    fi
    
    echo ""
    read -p "Press Enter to continue..."
}

# Get service details
get_service_details() {
    local service_name="$1"
    local config_name="${service_name#paqet-}"
    local config_file="$CONFIG_DIR/$config_name.yaml"
   
    local type="unknown"
    local mode="fast"
    local mtu="-"
    local conn="-"
    local cron="No"
   
    # Get type
    if [ -f "$config_file" ]; then
        type=$(grep "^role:" "$config_file" 2>/dev/null | awk '{print $2}' | tr -d '"' || echo "unknown")
       
        # Get KCP mode
        mode_line=$(grep "mode:" "$config_file" 2>/dev/null | head -1)
        if [ -n "$mode_line" ]; then
            mode=$(echo "$mode_line" | awk '{print $2}' | tr -d '"')
        fi
       
        # Get MTU - check if MTU exists in config
        if grep -q "mtu:" "$config_file" 2>/dev/null; then
            mtu_line=$(grep "mtu:" "$config_file" 2>/dev/null | head -1)
            if [ -n "$mtu_line" ]; then
                mtu=$(echo "$mtu_line" | awk '{print $2}' | tr -d '"')
            fi
        else
            mtu="-"
        fi
       
        # Get conn - check if conn exists in config
        if grep -q "conn:" "$config_file" 2>/dev/null; then
            conn_line=$(grep "conn:" "$config_file" 2>/dev/null | head -1)
            if [ -n "$conn_line" ]; then
                conn=$(echo "$conn_line" | awk '{print $2}' | tr -d '"')
            fi
        fi
    fi
   
    # Check cronjob
    if crontab -l 2>/dev/null | grep -q "^.*systemctl restart $service_name$"; then
        cron="Yes"
    elif crontab -l 2>/dev/null | grep -q "^[^#].*systemctl restart $service_name$"; then
        cron="Yes"
    fi
   
    # Return as space-separated string
    echo "$type $mode $mtu $conn $cron"
}

# Manage services with list view
manage_services() {
    while true; do
        show_banner
        echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                                           Paqet Services - Manage                                         ║${NC}"
        echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        local services=()
        mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                              grep -E '^paqet-.*\.service' | awk '{print $1}' || true)

        if [[ ${#services[@]} -eq 0 ]]; then
            echo -e "${YELLOW}No Paqet services found.${NC}"
            echo ""
            read -p "Press Enter to continue..." || true
            return
        fi

        echo -e "${CYAN}┌─────┬──────────────────────────┬─────────────┬───────────┬────────────────┬────────────┬──────────┬────────┐${NC}"
        echo -e "${CYAN}│  #  │      Service Name        │   Status    │   Type    │  Auto Restart  │    Mode    │   MTU    │  Conn  │${NC}"
        echo -e "${CYAN}├─────┼──────────────────────────┼─────────────┼───────────┼────────────────┼────────────┼──────────┼────────┤${NC}"

        local i=1
        for svc in "${services[@]}"; do
            local service_name="${svc%.service}"
            local display_name="${service_name#paqet-}"
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")

            local details
            details=$(get_service_details "$service_name")
            local type=$(echo "$details" | awk '{print $1}')
            local mode=$(echo "$details" | awk '{print $2}')
            local mtu=$(echo "$details" | awk '{print $3}')
            local conn=$(echo "$details" | awk '{print $4}')
            local cron=$(echo "$details" | awk '{print $5}')

            local status_color=""
            case "$status" in
                active)   status_color="${GREEN}" ;;
                failed)   status_color="${RED}"   ;;
                inactive) status_color="${YELLOW}" ;;
                *)        status_color="${WHITE}" ;;
            esac

            local mode_color=""
            case "$mode" in
                normal) mode_color="${CYAN}"    ;;
                fast)   mode_color="${GREEN}"   ;;
                fast2)  mode_color="${ORANGE}"  ;;
                fast3)  mode_color="${PURPLE}"  ;;
                manual) mode_color="${RED}"     ;;
                *)      mode_color="${WHITE}"   ;;
            esac

            local col_num=$(printf "%3d" $i)
            local col_name=$(printf "%-24s" "${display_name:0:24}")
            local col_status=$(printf "%-11s" "$status")
            local col_type=$(printf "%-9s" "${type:-unknown}")
            local col_cron=$(printf "%-14s" "${cron:-No}")
            local col_mode=$(printf "%-10s" "${mode:-fast}")
            local col_mtu=$(printf "%-8s" "${mtu:--}")
            local col_conn=$(printf "%-6s" "${conn:--}")

            echo -e "${CYAN}│${NC} ${WHITE}$col_num${NC} ${CYAN}│${NC} ${WHITE}$col_name${NC} ${CYAN}│${NC} ${status_color}$col_status${NC} ${CYAN}│${NC} ${WHITE}$col_type${NC} ${CYAN}│${NC} ${WHITE}$col_cron${NC} ${CYAN}│${NC} ${mode_color}$col_mode${NC} ${CYAN}│${NC} ${WHITE}$col_mtu${NC} ${CYAN}│${NC} ${WHITE}$col_conn${NC} ${CYAN}│${NC}"

            ((i++))
        done

        echo -e "${CYAN}└─────┴──────────────────────────┴─────────────┴───────────┴────────────────┴────────────┴──────────┴────────┘${NC}"
        echo ""

        echo -e "${YELLOW}Options:${NC}"
        echo -e "  0. ↩️  Back to Main Menu"
        echo -e "  1–${#services[@]}   Select a service to manage"
        echo ""

        read -p "Enter choice (0 to cancel): " choice

        [[ "$choice" == "0" || -z "$choice" ]] && return

        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#services[@]} )); then
            print_error "Invalid selection"
            sleep 1.5
            continue
        fi

        local selected_service="${services[$((choice-1))]}"
        local service_name="${selected_service%.service}"
        local display_name="${service_name#paqet-}"

        while true; do
            local short_name="${display_name:0:32}"
            [ ${#display_name} -gt 32 ] && short_name="${short_name}..."

            echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
            printf "${GREEN}║ Managing: %-50s ║${NC}\n" "${short_name}"
            echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
            echo ""
            local status=$(systemctl is-active "$selected_service" 2>/dev/null || echo "unknown")

            echo -e "${CYAN}Status:${NC} "
            case "$status" in
                active)   echo -e "${GREEN}🟢 Active${NC}"   ;;
                failed)   echo -e "${RED}🔴 Failed${NC}"    ;;
                inactive) echo -e "${YELLOW}🟡 Inactive${NC}" ;;
                *)        echo -e "${WHITE}⚪ Unknown${NC}"   ;;
            esac

            local details=$(get_service_details "$service_name")
            local type=$(echo "$details" | awk '{print $1}')
            local mode=$(echo "$details" | awk '{print $2}')
            local mtu=$(echo "$details" | awk '{print $3}')
            local conn=$(echo "$details" | awk '{print $4}')
            local cron=$(echo "$details" | awk '{print $5}')

            echo ""
            echo -e "${CYAN}Details:${NC}"
            echo -e "${CYAN}┌──────────────────────────────────────────────┐${NC}"
            printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Type"         "${type:-unknown}"
            printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "KCP Mode"     "${mode:-fast}"
            printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "MTU"          "${mtu:--}"
            printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Conn"         "${conn:--}"
            printf "${CYAN}│${NC} %-16s ${CYAN}:${NC} %-25s ${CYAN}│${NC}\n" "Auto-Restart" "${cron:-No}"
            echo -e "${CYAN}└──────────────────────────────────────────────┘${NC}"
            echo ""

            echo -e "${CYAN}Actions${NC}"
            echo " 1. 🟢  Start"
            echo " 2. 🔴  Stop"
            echo " 3. 🔄  Restart"
            echo " 4. 📊  Show Status"
            echo " 5. 📝  View Recent Logs"
            echo " 6. ✏️ Edit Configuration File"
            echo " 7. ⚙️  View Configuration File"
            echo " 8. ⏰  Cronjob Management"
            echo " 9. 🗑️  Delete This Service"
            echo " 10. ↩️  Back to Services List"
            echo ""

            read -p "Choose action [1-10]: " action

            case "$action" in
                1) systemctl start   "$selected_service" >/dev/null 2>&1; sleep 1.5 ;;
                2) systemctl stop    "$selected_service" >/dev/null 2>&1; sleep 1.5 ;;
                3) systemctl restart "$selected_service" >/dev/null 2>&1; sleep 1.5 ;;
                4)
                    echo ""
                    systemctl status "$selected_service" --no-pager -l
                    echo ""
                    read -p "Press Enter to continue..." || true
                    ;;
                5)
                    echo ""
                    journalctl -u "$selected_service" -n 25 --no-pager
                    echo ""
                    read -p "Press Enter to continue..." || true
                    ;;
                6)
                    local cfg="$CONFIG_DIR/${display_name}.yaml"
                    if [ -f "$cfg" ]; then
                        echo -e "\n${YELLOW}Opening configuration file for editing...${NC}"
                        echo -e "${CYAN}File path:${NC} $cfg"
                        echo -e "${CYAN}After editing, save with Ctrl+O → Enter → Ctrl+X in nano${NC}"
                        echo ""

                        if command -v nano >/dev/null 2>&1; then
                            nano "$cfg"
                        elif command -v vim >/dev/null 2>&1; then
                            vim "$cfg"
                        elif command -v vi >/dev/null 2>&1; then
                            vi "$cfg"
                        else
                            print_error "No text editor (nano / vim / vi) found on the system!"
                            print_info "Suggestion: install one of them:"
                            echo "   apt update && apt install nano     (Ubuntu/Debian)"
                            echo "   yum install nano                   (CentOS/RHEL)"
                            echo "   or install vim / vi"
                            read -p "Press Enter to continue..."
                            continue
                        fi

                        echo -e "\n${GREEN}File saved.${NC}"
                        echo ""

                        # Ask to restart the service
                        read -p "Do you want to restart the service to apply changes? (y/N): " restart_choice
                        if [[ "$restart_choice" =~ ^[Yy]$ ]]; then
                            echo -e "${YELLOW}Restarting service ${display_name} ...${NC}"
                            systemctl restart "$selected_service" >/dev/null 2>&1
                            sleep 2

                            if systemctl is-active --quiet "$selected_service"; then
                                print_success "Service restarted successfully"
                            else
                                print_error "Service failed to start after restart!"
                                echo "Service status:"
                                systemctl status "$selected_service" --no-pager -l
                            fi
                        else
                            print_info "Service not restarted. Changes will apply on next start."
                        fi
                    else
                        print_error "Configuration file not found!"
                        echo "Expected path: $cfg"
                    fi

                    echo ""
                    read -p "Press Enter to return to menu..."
                    ;;                    
                7)
                    local cfg="$CONFIG_DIR/$display_name.yaml"
                    if [ -f "$cfg" ]; then
                        echo -e "\n${CYAN}Configuration file:${NC} $cfg\n"
                        cat "$cfg"
                        echo ""
                    else
                        print_error "Config file not found"
                    fi
                    read -p "Press Enter to continue..." || true
                    ;;
                8) manage_cronjob "$service_name" "$display_name" ;;
                9)
                    read -p "Delete this service? (y/N): " confirm
                    if [[ "$confirm" =~ ^[Yy]$ ]]; then
                        remove_cronjob "$service_name" 2>/dev/null || true
                        systemctl stop    "$selected_service" 2>/dev/null || true
                        systemctl disable "$selected_service" 2>/dev/null || true
                        rm -f "$SERVICE_DIR/$selected_service"     2>/dev/null || true
                        rm -f "$CONFIG_DIR/$display_name.yaml"     2>/dev/null || true
                        systemctl daemon-reload 2>/dev/null || true
                        print_success "Service and config removed"
                        read -p "Press Enter to continue..." || true
                        break
                    fi
                    ;;
                10) break ;;
                *) print_error "Invalid choice"; sleep 1 ;;
            esac
        done
    done
}
# Install BBR
install_bbr() {
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install BBR Optimizer                                    ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
   
    echo -e "${YELLOW}BBR is a TCP congestion control algorithm developed by Google.${NC}"
    echo -e "${YELLOW}It can significantly improve network performance and speed.${NC}"
    echo ""
   
    read -p "Do you want to install BBR? (y/N): " confirm
   
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}BBR installation cancelled.${NC}"
        return
    fi
   
    print_step "Downloading and installing BBR..."
   
    # Download BBR installer script
    if wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh -O /tmp/bbr.sh 2>/dev/null; then
        chmod +x /tmp/bbr.sh
        print_success "BBR installer downloaded"
       
        echo ""
        echo -e "${YELLOW}The BBR installer will now run.${NC}"
        echo -e "${YELLOW}Follow the on-screen instructions.${NC}"
        echo ""
        echo -e "${CYAN}Note: This may require a system reboot.${NC}"
        echo ""
       
        read -p "Press Enter to continue with BBR installation..."
       
        # Run BBR installer
        /tmp/bbr.sh
       
        echo ""
        print_success "✅ BBR installation completed!"
        echo ""
        echo -e "${YELLOW}If the installer requested a reboot, please restart your server.${NC}"
        echo -e "${YELLOW}After reboot, BBR will be active and optimizing your network.${NC}"
       
        # Clean up
        rm -f /tmp/bbr.sh
    else
        print_error "Failed to download BBR installer"
        echo ""
        echo -e "${YELLOW}You can install BBR manually with:${NC}"
        echo -e "${CYAN}wget --no-check-certificate https://github.com/teddysun/across/raw/master/bbr.sh && chmod +x bbr.sh && ./bbr.sh${NC}"
    fi
   
    echo ""
    read -p "Press Enter to return to menu..."
}
# Install DNS Finder
install_dns_finder() {
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install DNS Finder                                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
   
    echo -e "${YELLOW}This tool finds the best DNS servers for Iran by testing latency.${NC}"
    echo -e "${YELLOW}It will help improve your internet speed and connectivity.${NC}"
    echo ""
   
    read -p "Do you want to find the best DNS servers? (y/N): " confirm
   
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}DNS Finder installation cancelled.${NC}"
        return
    fi
   
    print_step "Downloading and running DNS Finder..."
   
    # Download and run DNS Finder script
    if bash <(curl -Ls https://github.com/alinezamifar/IranDNSFinder/raw/refs/heads/main/dns.sh); then
        print_success "✅ DNS Finder completed successfully!"
        echo ""
        echo -e "${YELLOW}The tool has tested various DNS servers and shown the best options.${NC}"
        echo -e "${YELLOW}You can now configure your system to use the recommended DNS servers.${NC}"
    else
        print_error "Failed to run DNS Finder"
        echo ""
        echo -e "${YELLOW}You can run DNS Finder manually with:${NC}"
        echo -e "${CYAN}bash <(curl -Ls https://github.com/alinezamifar/IranDNSFinder/raw/refs/heads/main/dns.sh)${NC}"
    fi
   
    echo ""
    read -p "Press Enter to return to menu..."
}
# Install Mirror Selector
install_mirror_selector() {
    show_banner
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║ Install Mirror Selector                                  ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
   
    # Check if system is Ubuntu/Debian based
    local os=$(detect_os)
    if [[ "$os" != "ubuntu" ]] && [[ "$os" != "debian" ]]; then
        echo -e "${RED}This tool is only for Ubuntu/Debian based systems.${NC}"
        echo -e "${YELLOW}Your OS is: $os${NC}"
        echo ""
        read -p "Press Enter to return to menu..."
        return
    fi
   
    echo -e "${YELLOW}This tool finds the fastest apt repository mirror for your location.${NC}"
    echo -e "${YELLOW}It will significantly improve package download speeds.${NC}"
    echo ""
   
    read -p "Do you want to find the fastest apt mirror? (y/N): " confirm
   
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}Mirror Selector installation cancelled.${NC}"
        return
    fi
   
    print_step "Downloading and running Mirror Selector..."
   
    # Download and run Mirror Selector script
    if bash <(curl -Ls https://github.com/alinezamifar/DetectUbuntuMirror/raw/refs/heads/main/DUM.sh); then
        print_success "✅ Mirror Selector completed successfully!"
        echo ""
        echo -e "${YELLOW}The tool has tested various mirrors and selected the fastest one.${NC}"
        echo -e "${YELLOW}Your apt sources have been updated with the fastest mirror.${NC}"
    else
        print_error "Failed to run Mirror Selector"
        echo ""
        echo -e "${YELLOW}You can run Mirror Selector manually with:${NC}"
        echo -e "${CYAN}bash <(curl -Ls https://github.com/alinezamifar/DetectUbuntuMirror/raw/refs/heads/main/DUM.sh)${NC}"
    fi
   
    echo ""
    read -p "Press Enter to return to menu..."
}
# Server Optimization Menu
optimize_server() {
    while true; do
        show_banner
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Server Optimization Tools                                ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
       
        echo -e "${CYAN}1.${NC} ${GREEN}BBR${NC} - TCP Congestion Control Optimizer"
        echo -e "${CYAN}2.${NC} ${PURPLE}DNS Finder${NC} - Find the best DNS servers for Iran"
        echo -e "${CYAN}3.${NC} ${ORANGE}Mirror Selector${NC} - Find the fastest apt repository mirror"
        echo -e "${CYAN}4.${NC} ↩️ Back to Main Menu"
        echo ""
       
        read -p "Select option [1-4]: " choice
       
        case $choice in
            1)
                install_bbr
                ;;
            2)
                install_dns_finder
                ;;
            3)
                install_mirror_selector
                ;;
            4)
                return
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
    done
}
# Uninstall Paqet
uninstall_paqet() {
    show_banner
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║ Uninstall Paqet                                          ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
   
    read -p "Are you sure? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi
   
    print_step "Stopping services..."
   
    # Stop and disable all paqet services
    local services=()
    mapfile -t services < <(systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null |
                          grep -E '^paqet-.*\.service' | awk '{print $1}' || true)
   
    for service in "${services[@]}"; do
        systemctl stop "$service" 2>/dev/null || true
        systemctl disable "$service" 2>/dev/null || true
        rm -f "$SERVICE_DIR/$service" 2>/dev/null || true
    done
   
    # Remove all cronjobs
    for service in "${services[@]}"; do
        local service_name="${service%.service}"
        remove_cronjob "$service_name"
    done
   
    systemctl daemon-reload
   
    # Remove files
    print_step "Removing files..."
    rm -f "$BIN_DIR/paqet" 2>/dev/null || true
   
    read -p "Remove configuration files? (y/N): " remove_configs
    if [[ "$remove_configs" =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR" 2>/dev/null || true
        rm -rf "$INSTALL_DIR" 2>/dev/null || true
        print_success "All files removed"
    else
        print_info "Configuration preserved in $CONFIG_DIR/"
    fi
   
    print_success "✅ Paqet uninstalled"
    echo ""
    read -p "Press Enter to continue..."
}
# Main menu
main_menu() {
    while true; do
        show_banner
       
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║ Main Menu                                                ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
        echo ""
       
        # Check if Paqet is installed
        if [ -f "$BIN_DIR/paqet" ]; then
            echo -e "${GREEN}✅ Paqet is installed${NC}"
        else
            echo -e "${YELLOW}⚠️ Paqet not installed${NC}"
        fi
       
        # Check if dependencies are installed
        local missing_deps
        missing_deps=$(check_dependencies)
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✅ Dependencies are installed${NC}"
        else
            echo -e "${YELLOW}⚠️ Missing dependencies: $missing_deps${NC}"
        fi
       
        echo ""
        echo -e "${CYAN}0.${NC}⚙️  Install Paqet Binary Only"
        echo -e "${CYAN}1.${NC}📦 Install Dependencies"
        echo -e "${CYAN}2.${NC}🌍 Configure as Server (kharej)"
        echo -e "${CYAN}3.${NC}🇮🇷 Configure as Client (Iran)"
        echo -e "${CYAN}4.${NC}🛠️  Manage Services"
        echo -e "${CYAN}5.${NC}📊 Test Connection(basic)"
        echo -e "${CYAN}6.${NC}🔄 Restart All Services"
        echo -e "${CYAN}7.${NC}🚀 Optimize Server"
        echo -e "${CYAN}8.${NC}🗑️  Uninstall Paqet"
        echo -e "${CYAN}9.${NC}🚪 Exit"
        echo ""
       
        read -p "Select option [0-9]: " choice
       
        case $choice in
            0)
                install_paqet
                ;;
            1)
                install_dependencies
                ;;
            2)
                configure_server
                ;;
            3)
                configure_client
                ;;
            4)
                manage_services
                ;;
            5)
                test_connection
                ;;
            6)
                restart_all_services
                ;;
            7)
                optimize_server
                ;;
            8)
                uninstall_paqet
                ;;
            9)
                echo ""
                echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
                echo -e "${GREEN} Goodbye! ${NC}"
                echo -e "${GREEN}══════════════════════════════════════════════════════════════${NC}"
                echo ""
                exit 0
                ;;
            *)
                print_error "Invalid option"
                ;;
        esac
       
        echo ""
    done
}
# Initialize
check_root
main_menu
