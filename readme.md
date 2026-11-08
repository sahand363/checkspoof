# CheckSpoof — Two-Server IP Spoofing & Egress Filtering Diagnostic Tool

CheckSpoof is a two-server Linux diagnostic tool written in Go that measures whether packets with a spoofed source IPv4 address actually leave a sender server (`Server A`) and arrive intact at an independently controlled receiver server (`Server B`).

## Strict Separation of Local Outbound IP vs. Public IP

CheckSpoof strictly separates local routing interface addresses from public IPv4 addresses:

- **`LocalOutboundIP` & `LocalInterface`**: Determined via `ip route get <destination>`, extracting both the actual outgoing network interface (`dev`) and kernel source address (`src`) for the specific target route.
- **`PublicIP` (`MANUAL`, `DISCOVERED`, or `UNKNOWN`)**: Never assumed from the local interface address. If public IP discovery is unavailable, returns a private/CGNAT address, or yields conflicting results, `PublicIP` is explicitly reported as `UNKNOWN` rather than guessing.
- **Manual Public IP Override**: Supported via `-public-ip <IPv4>`, the `PUBLIC_IP` environment variable, or the `/api/admin/public-ip` dashboard setting for servers behind NAT.

## Strict Spoofing Verification Stages

1. **`RECEIVER_LISTENER_READY`**: Server B has bound the target UDP (`:5555`) or raw ICMP (`ip4:icmp`) socket and confirmed readiness over the TLS 1.3 control channel.
2. **`SNAT_RULE_INSTALLED`**: Server A created an isolated temporary `iptables` NAT chain (`CSPF_<ID>`) on the destination-specific outgoing interface and hooked it into `POSTROUTING`.
3. **`LOCAL_PACKET_GENERATION_SUCCESS`**: Server A wrote the signed test packets to its local socket.
4. **`LOCAL_FIREWALL_RULE_MATCHED`**: The kernel netfilter counter in `CSPF_<ID>` incremented.
5. **`SPOOF_SUCCESS`**: Reported **only** when real OS commands are executed, addresses are non-loopback, the spoofed source IP differs from both Server A's local outbound IP and public IP, and Server B receives and cryptographically validates packets whose observed source IP matches the requested spoofed IP.

---

## Running & Configuring Public IP

```bash
# Automatic discovery (reports UNKNOWN if behind NAT without external discovery):
sudo checkspoof -port 8085

# Explicit manual public IP (recommended for NAT/cloud environments):
sudo checkspoof -port 8085 -public-ip 203.0.113.50
