#!/bin/bash
set -e

# Update system
apt-get update
apt-get upgrade -y

# Install WireGuard
apt-get install -y wireguard qrencode

# Enable IP forwarding (idempotent)
grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf || echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
grep -q "net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf || echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
sysctl -p

# Generate server keys
cd /etc/wireguard
umask 077
wg genkey | tee server_private.key | wg pubkey > server_public.key

SERVER_PRIVATE_KEY=$(cat server_private.key)
SERVER_PUBLIC_KEY=$(cat server_public.key)

# Get the server's private IP (for reference)
SERVER_IP=$(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
echo "Server private IP: $SERVER_IP"

# Create server configuration
cat > /etc/wireguard/wg0.conf <<'WGCONF'
[Interface]
Address = 10.200.200.1/24
ListenPort = 51820
PrivateKey = SERVER_PRIVATE_KEY_PLACEHOLDER
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
WGCONF

# Replace placeholder with actual key
sed -i "s|SERVER_PRIVATE_KEY_PLACEHOLDER|$SERVER_PRIVATE_KEY|g" /etc/wireguard/wg0.conf

# Generate client configurations
mkdir -p /etc/wireguard/clients

for i in {1..${vpn_client_count}}; do
  CLIENT_PRIVATE_KEY=$(wg genkey)
  CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
  CLIENT_IP=$((i+1))
  
  # Add client to server config directly
  cat >> /etc/wireguard/wg0.conf <<PEER

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = 10.200.200.$CLIENT_IP/32
PEER
  
  # Create client config directly with variables
  cat > /etc/wireguard/clients/client$i.conf <<CLIENT
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = 10.200.200.$CLIENT_IP/24
DNS = ${dns_ip_1}, ${dns_ip_2}

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = VPN_PUBLIC_IP_PLACEHOLDER:51820
AllowedIPs = 10.0.20.0/24, 10.0.21.0/24, 10.200.200.0/24
PersistentKeepalive = 25
CLIENT
  
  # Generate QR code for mobile clients
  qrencode -t ansiutf8 < /etc/wireguard/clients/client$i.conf > /etc/wireguard/clients/client$i-qr.txt
done

# Enable and start WireGuard
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

# Create a script to update client configs with the actual EIP
cat > /usr/local/bin/update-vpn-configs.sh <<'UPDATESCRIPT'
#!/bin/bash
# This script updates client configs with the actual public IP
# Run this after the EIP is associated

if [ -z "$1" ]; then
  echo "Usage: $0 <public_ip>"
  exit 1
fi

PUBLIC_IP=$1

for conf in /etc/wireguard/clients/client*.conf; do
  if [ -f "$conf" ]; then
    sed -i "s|VPN_PUBLIC_IP_PLACEHOLDER|$PUBLIC_IP|g" "$conf"
    # Regenerate QR code
    base_name="${conf%.conf}"
    qrencode -t ansiutf8 < "$conf" > "${base_name}-qr.txt"
  fi
done

echo "Updated all client configurations with public IP: $PUBLIC_IP"
UPDATESCRIPT

chmod +x /usr/local/bin/update-vpn-configs.sh

echo "VPN setup complete. Server public key: $SERVER_PUBLIC_KEY"
