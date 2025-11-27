#!/bin/bash
set -e

# Logging
exec > >(tee -a /var/log/vpn-setup.log)
exec 2>&1

echo "=== WireGuard VPN Setup Started at $(date) ==="

# Update system
echo "Updating system packages..."
apt-get update
apt-get upgrade -y

# Install WireGuard
echo "Installing WireGuard..."
apt-get install -y wireguard qrencode curl

# Enable IP forwarding (idempotent)
echo "Enabling IP forwarding..."
# FIX: Removed space in 'net.ipv4. ip_forward'
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Detect primary network interface dynamically
PRIMARY_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Detected primary network interface: $PRIMARY_INTERFACE"
# Enable IP forwarding
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf

# Add iptables NAT rule for VPN clients
iptables -t nat -A POSTROUTING -s 10.200.200.0/24 -o $PRIMARY_INTERFACE -j MASQUERADE

# Make iptables persistent
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y iptables-persistent
netfilter-persistent save

# Verify forwarding is enabled
sysctl net.ipv4. ip_forward

# Test ping to workstation
ping -c 3 10.0.20.82

# Generate server keys
echo "Generating WireGuard server keys..."
cd /etc/wireguard
umask 077
# FIX: Removed space in 'server_private. key'
wg genkey | tee server_private.key | wg pubkey > server_public.key

SERVER_PRIVATE_KEY=$(cat server_private.key)
SERVER_PUBLIC_KEY=$(cat server_public.key)

# Get the server's private IP
SERVER_IP=$(ip -4 addr show "$PRIMARY_INTERFACE" | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "Server private IP: $SERVER_IP"

# Create server configuration
echo "Creating WireGuard server configuration..."
cat > /etc/wireguard/wg0.conf <<WGCONF
[Interface]
Address = 10.200.200.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE_KEY
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o $PRIMARY_INTERFACE -j MASQUERADE
WGCONF

# Generate client configurations
echo "Generating client configurations..."
mkdir -p /etc/wireguard/clients

for i in {1..${vpn_client_count}}; do
  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
  CLIENT_IP=$((i+1))
  
  echo "  Creating client $i config..."
  
  # Add client to server config
  cat >> /etc/wireguard/wg0.conf <<PEER

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.200.$CLIENT_IP/32
PEER
  
  # Create client config
  cat > /etc/wireguard/clients/client$i.conf <<CLIENT
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.200.200.$CLIENT_IP/24
DNS = ${dns_ip_1}, ${dns_ip_2}

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = ENDPOINT_PLACEHOLDER:51820
AllowedIPs = 10.0.0.0/16, 10.200.200.0/24
PersistentKeepalive = 25
CLIENT
  
  # Generate QR code for mobile clients
  qrencode -t ansiutf8 < /etc/wireguard/clients/client$i.conf > /etc/wireguard/clients/client$i-qr.txt
done

# Enable and start WireGuard
echo "Enabling and starting WireGuard service..."
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Get VPN public IP and update client configs
VPN_PUBLIC_IP=$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4)
echo "VPN Public IP: $VPN_PUBLIC_IP"

for i in {1..${vpn_client_count}}; do
  sed -i "s|ENDPOINT_PLACEHOLDER|$VPN_PUBLIC_IP|g" /etc/wireguard/clients/client$i.conf
done

# Display summary
echo "=== WireGuard VPN Setup Complete!  ==="
echo "Server Public Key: $SERVER_PUBLIC_KEY"
echo "VPN Public IP: $VPN_PUBLIC_IP"
echo "Primary Interface: $PRIMARY_INTERFACE"
echo "Client configs available in /etc/wireguard/clients/"
echo "Setup completed at $(date)"

# Verify service is running
systemctl status wg-quick@wg0 --no-pager