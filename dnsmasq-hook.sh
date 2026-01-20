#!/bin/bash
set -e

# Get directory where this script lives
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Generate flattened dnsmasq config
FLAT_CONFIG=$(mktemp "${SCRIPT_DIR}/.tmp.flat-config.XXXXXX")
trap "rm -f '$FLAT_CONFIG'" EXIT

python3 "$SCRIPT_DIR/dnsmasq_flatten_config.py" > "$FLAT_CONFIG"

# Extract auth-server (last wins, take just the zone name before any comma)
AUTH_ZONE=$(grep '^auth-server=' "$FLAT_CONFIG" | tail -1 | cut -d= -f2 | cut -d, -f1)

# Extract auth-sec-servers (all values, space-separated)
AUTH_SEC_SERVERS=$(grep '^auth-sec-servers=' "$FLAT_CONFIG" | cut -d= -f2 | tr '\n' ' ' | sed 's/ $//')

# Find public IPv4 listen-address (exclude private ranges)
PUBLIC_IPV4=$(grep '^listen-address=' "$FLAT_CONFIG" | cut -d= -f2 | \
    grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | \
    grep -v '^127\.' | \
    grep -v '^10\.' | \
    grep -v '^172\.\(1[6-9]\|2[0-9]\|3[01]\)\.' | \
    grep -v '^192\.168\.' | \
    head -1) || true

# Validate required values
if [ -z "$AUTH_ZONE" ]; then
    echo "ERROR: No auth-server found in dnsmasq config" >&2
    exit 1
fi
if [ -z "$AUTH_SEC_SERVERS" ]; then
    echo "ERROR: No auth-sec-servers found in dnsmasq config" >&2
    exit 1
fi
if [ -z "$PUBLIC_IPV4" ]; then
    echo "ERROR: No public IPv4 listen-address found in dnsmasq config" >&2
    exit 1
fi

echo "Discovered dnsmasq config:"
echo "  Zone: $AUTH_ZONE"
echo "  Secondary servers: $AUTH_SEC_SERVERS"
echo "  Public IPv4: $PUBLIC_IPV4"

# Create the ACME challenge TXT record
cat <<EOF > /etc/dnsmasq.d/dnsmasq.acme.$CERTBOT_DOMAIN.conf
dns-rr=$CERTBOT_DOMAIN.,257,000569737375656C657473656E63727970742E6F7267
txt-record=_acme-challenge.$CERTBOT_DOMAIN.,$CERTBOT_VALIDATION
EOF

dnsmasq --test 2>&1 || exit 1

systemctl restart dnsmasq
systemctl status dnsmasq

echo "Local TXT record:"
dig @localhost TXT _acme-challenge.$CERTBOT_DOMAIN +short

# Verify local server has the correct record
LOCAL_TXT=$(dig @localhost TXT _acme-challenge.$CERTBOT_DOMAIN +short | tr -d '"')
if [ "$LOCAL_TXT" != "$CERTBOT_VALIDATION" ]; then
    echo "ERROR: Local DNS does not have correct TXT record"
    echo "Expected: $CERTBOT_VALIDATION"
    echo "Got: $LOCAL_TXT"
    exit 1
fi

# Send NOTIFY to secondaries to trigger zone transfer
# Use -I for IPv4 source address (required for ns2 which rejects IPv6 notify)
echo "Sending NOTIFY to secondaries..."
ldns-notify -I "$PUBLIC_IPV4" -z "$AUTH_ZONE" $AUTH_SEC_SERVERS

# Wait for secondaries to have the correct TXT record
MAX_WAIT=120
INTERVAL=5
WAITED=0

# Convert space-separated servers to array for iteration
read -ra SERVERS <<< "$AUTH_SEC_SERVERS"

echo "Waiting for secondaries to sync (max ${MAX_WAIT}s)..."
while [ $WAITED -lt $MAX_WAIT ]; do
    sleep $INTERVAL
    WAITED=$((WAITED + INTERVAL))

    # Check all secondaries
    ALL_SYNCED=true
    STATUS_LINE="  ${WAITED}s:"
    for server in "${SERVERS[@]}"; do
        SERVER_TXT=$(dig "@$server" TXT _acme-challenge.$CERTBOT_DOMAIN +short | tr -d '"')
        STATUS_LINE="$STATUS_LINE $server='${SERVER_TXT}'"
        if [ "$SERVER_TXT" != "$CERTBOT_VALIDATION" ]; then
            ALL_SYNCED=false
        fi
    done
    echo "$STATUS_LINE"

    if [ "$ALL_SYNCED" = true ]; then
        echo "All secondaries synced successfully!"
        exit 0
    fi
done

echo "WARNING: Secondaries may not have synced in time"
exit 0
