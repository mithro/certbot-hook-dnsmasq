#!/bin/bash

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
ldns-notify -I 87.121.95.37 -z welland.mithis.com ns1.rollernet.us ns2.rollernet.us

# Wait for secondaries to have the correct TXT record
MAX_WAIT=120
INTERVAL=5
WAITED=0

echo "Waiting for secondaries to sync (max ${MAX_WAIT}s)..."
while [ $WAITED -lt $MAX_WAIT ]; do
    sleep $INTERVAL
    WAITED=$((WAITED + INTERVAL))

    # Check both secondaries
    NS1_TXT=$(dig @ns1.rollernet.us TXT _acme-challenge.$CERTBOT_DOMAIN +short | tr -d '"')
    NS2_TXT=$(dig @ns2.rollernet.us TXT _acme-challenge.$CERTBOT_DOMAIN +short | tr -d '"')

    echo "  ${WAITED}s: ns1='${NS1_TXT}' ns2='${NS2_TXT}'"

    if [ "$NS1_TXT" = "$CERTBOT_VALIDATION" ] && [ "$NS2_TXT" = "$CERTBOT_VALIDATION" ]; then
        echo "Both secondaries synced successfully!"
        exit 0
    fi
done

echo "WARNING: Secondaries may not have synced in time"
exit 0
