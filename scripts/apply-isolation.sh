#!/usr/bin/env bash
# Apply PhantomNet host-level isolation rules (run as root after `docker compose up`).
#
# Defense in depth only: ALSO enforce these rules on your router/firewall.
#
#  * Decoy bridge (pn-decoy0): containers may answer inbound connections but may
#    not open NEW connections anywhere — not production, not management, not the
#    internet, not the host itself.
#  * Alert bridge (pn-alert0): only DNS and the alert ports (HTTPS/SMTP) to
#    public addresses, or only ALERT_EGRESS_CIDRS when set. Private ranges are
#    always denied unless listed in ALERT_EGRESS_CIDRS.
#  * Backend bridge (pn-backend0) is a Docker internal network (no egress).
#
# Rules live in dedicated chains (PHANTOMNET-FWD, PHANTOMNET-IN) so they can be
# removed cleanly with scripts/remove-isolation.sh.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run as root (sudo)" >&2; exit 1; }
command -v iptables >/dev/null || { echo "iptables not found" >&2; exit 1; }

DECOY_IF=${DECOY_IF:-pn-decoy0}
ALERT_IF=${ALERT_IF:-pn-alert0}
ALERT_PORTS=${ALERT_PORTS:-443,465,587}
ALERT_EGRESS_CIDRS=${ALERT_EGRESS_CIDRS:-}   # e.g. "203.0.113.10/32 198.51.100.0/24"
PRIVATE_RANGES="10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16"

for ifc in "$DECOY_IF" "$ALERT_IF"; do
  ip link show "$ifc" >/dev/null 2>&1 || { echo "interface $ifc not found — is PhantomNet running?" >&2; exit 1; }
done
iptables -nL DOCKER-USER >/dev/null 2>&1 || { echo "DOCKER-USER chain missing — is Docker running?" >&2; exit 1; }

reset_chain() {
  iptables -N "$1" 2>/dev/null || iptables -F "$1"
}

# --- forwarded traffic (containers -> anywhere) -------------------------------
reset_chain PHANTOMNET-FWD
iptables -A PHANTOMNET-FWD -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# Decoys: allow traffic within the decoy bridge only; deny every new outbound flow.
iptables -A PHANTOMNET-FWD -i "$DECOY_IF" -o "$DECOY_IF" -j RETURN
iptables -A PHANTOMNET-FWD -i "$DECOY_IF" -m limit --limit 6/min -j LOG --log-prefix "phantomnet-decoy-egress: "
iptables -A PHANTOMNET-FWD -i "$DECOY_IF" -j DROP
# Alert path.
if [[ -n "$ALERT_EGRESS_CIDRS" ]]; then
  for c in $ALERT_EGRESS_CIDRS; do
    iptables -A PHANTOMNET-FWD -i "$ALERT_IF" -d "$c" -p tcp -m multiport --dports "$ALERT_PORTS" -j RETURN
  done
fi
for c in $PRIVATE_RANGES; do
  iptables -A PHANTOMNET-FWD -i "$ALERT_IF" ! -o "$ALERT_IF" -d "$c" -j DROP
done
iptables -A PHANTOMNET-FWD -i "$ALERT_IF" -p udp --dport 53 -j RETURN
iptables -A PHANTOMNET-FWD -i "$ALERT_IF" -p tcp --dport 53 -j RETURN
if [[ -z "$ALERT_EGRESS_CIDRS" ]]; then
  iptables -A PHANTOMNET-FWD -i "$ALERT_IF" -p tcp -m multiport --dports "$ALERT_PORTS" -j RETURN
fi
iptables -A PHANTOMNET-FWD -i "$ALERT_IF" ! -o "$ALERT_IF" -j DROP
iptables -A PHANTOMNET-FWD -j RETURN

iptables -C DOCKER-USER -j PHANTOMNET-FWD 2>/dev/null || iptables -I DOCKER-USER 1 -j PHANTOMNET-FWD

# --- traffic to the host itself (containers -> host sshd, etc.) --------------
reset_chain PHANTOMNET-IN
iptables -A PHANTOMNET-IN -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
iptables -A PHANTOMNET-IN -i "$DECOY_IF" -j DROP
iptables -A PHANTOMNET-IN -i "$ALERT_IF" -p udp --dport 53 -j RETURN
iptables -A PHANTOMNET-IN -i "$ALERT_IF" -p tcp --dport 53 -j RETURN
iptables -A PHANTOMNET-IN -i "$ALERT_IF" -j DROP
iptables -A PHANTOMNET-IN -j RETURN
iptables -C INPUT -j PHANTOMNET-IN 2>/dev/null || iptables -I INPUT 1 -j PHANTOMNET-IN

echo "PhantomNet isolation rules applied:"
iptables -S PHANTOMNET-FWD
iptables -S PHANTOMNET-IN
echo
echo "Next: run scripts/verify-isolation.sh, and mirror these rules on the network firewall."
