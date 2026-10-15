#!/bin/bash

# ==========================================
# NetFend Pro — ADVANCED INSTALLER
# ==========================================

echo "[NetFend Pro] Installing system dependencies..."
sudo apt-get update -y
sudo apt-get install -y iproute2 net-tools arptables psmisc python3-scapy python3-psutil python3-netifaces python3-colorama python3-termcolor

# Create data directory
echo "[NetFend Pro] Setting up data directory..."
sudo mkdir -p /var/lib/netfend

# Copy the Python package to the destination locations
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "[NetFend Pro] Installing Core Engine package..."
sudo cp -r "$SCRIPT_DIR/netfend" /usr/local/bin/netfend 2>/dev/null || true
sudo cp "$SCRIPT_DIR/net_defender.py" /usr/local/bin/net_defender.py
sudo chmod +x /usr/local/bin/net_defender.py

# ==================================
# Command 1: net_watch  (ARP Monitor)
# ==================================
sudo bash -c "cat >/usr/local/bin/net_watch" <<'EOF'
#!/bin/bash
echo "[NetFend Pro] ARP Monitor (live)"
watch -n 1 "arp -an"
EOF
sudo chmod +x /usr/local/bin/net_watch

# ==================================
# Command 2: net_protect  (Defense Engine)
# ==================================
sudo bash -c "cat >/usr/local/bin/net_protect" <<'EOF'
#!/bin/bash
echo "[NetFend Pro] Launching Advanced Defense Engine..."
sudo PYTHONPATH=/usr/local/bin python3 /usr/local/bin/net_defender.py "$@"
EOF
sudo chmod +x /usr/local/bin/net_protect

# ==================================
# Command 3: net_reset  (Disable Defense)
# ==================================
sudo bash -c "cat >/usr/local/bin/net_reset" <<'EOF'
#!/bin/bash

echo "[NetFend Pro] Stopping active defender..."
pkill -f "net_defender.py" 2>/dev/null

echo "[NetFend Pro] Clearing arptables rules..."
arptables -F 2>/dev/null || true

IFACE=$(ip route | awk '/default/ {print $5}')
GW_IP=$(ip route | awk '/default/ {print $3}')

if [ -n "$GW_IP" ] && [ -n "$IFACE" ]; then
    echo "[NetFend Pro] Restoring normal ARP cache..."
    ip neigh replace $GW_IP dev $IFACE nud reachable 2>/dev/null
    ip neigh flush dev $IFACE 2>/dev/null
    ip link set $IFACE down
    sleep 1
    ip link set $IFACE up
fi

echo "[NetFend Pro] Protection disabled. Network restored."
EOF
sudo chmod +x /usr/local/bin/net_reset

# ==================================
# Command 4: net_blacklist  (Manage Blacklist)
# ==================================
sudo bash -c "cat >/usr/local/bin/net_blacklist" <<'EOF'
#!/bin/bash
PYTHONPATH=/usr/local/bin python3 /usr/local/bin/net_defender.py --blacklist "$@"
EOF
sudo chmod +x /usr/local/bin/net_blacklist

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║    NetFend Pro — Installation Complete       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  Available commands:"
echo "    net_protect              Start the defense engine"
echo "    net_protect -i wlan0     Start on a specific interface"
echo "    net_watch                Monitor ARP table live"
echo "    net_reset                Stop defense, restore network"
echo "    net_blacklist            View the dynamic blacklist"
echo ""
echo "  Client management commands:"
echo "    net_protect --list-devices            List all discovered local hosts"
echo "    net_protect --authorize MAC           Whitelists target client device"
echo "    net_protect --deauthorize MAC         Blocks target client device"
echo ""
echo "  Data stored in: /var/lib/netfend/"
echo ""
echo "  → Run 'sudo net_protect' to activate!"
echo ""
