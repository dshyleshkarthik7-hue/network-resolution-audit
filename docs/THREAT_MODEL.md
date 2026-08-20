# Threat Model – Network Resolution Audit

## Assets

- Integrity of IP-to-MAC mappings on the local L2 segment
- Correctness of DNS resolution for critical hosts
- Audit trail of observed changes

## Adversaries

- Local network attacker (same broadcast domain)
- Compromised device that begins answering for another IP
- Misconfigured DHCP / network equipment

## Attack Scenarios & Mitigations

### 1. ARP Spoofing / Cache Poisoning

**Attack:** Attacker sends gratuitous ARP or answers ARP requests with its own MAC.

**Detection:** Baseline comparison flags the IP with a new MAC as **HIGH**.

**Limitations:** Tool only sees the host’s own neighbor table. If the host never communicates with the target IP, the entry may not appear. Active scanners or continuous ping can help populate the table.

### 2. Rogue Gateway

**Attack:** Attacker claims the default gateway IP.

**Detection:** Same HIGH finding on the gateway IP.

**Response:** Investigate immediately; consider static ARP entries for critical infrastructure.

### 3. DHCP Churn / Legitimate Device Replacement

**Attack:** None – false positive risk.

**Mitigation:** Use `--ignore-missing` on dynamic segments; rotate baselines on a known schedule; document expected device changes.

### 4. DNS Poisoning

**Attack:** Resolver returns unexpected addresses.

**Detection:** Manual comparison of A/AAAA results against known-good values (tool itself does not maintain a DNS baseline yet).

**Future:** Optional DNS baseline support is a planned enhancement.

## Assumptions

- Baseline is created on a trusted network state.
- Operator reviews HIGH findings rather than treating them as automatic alerts for automated blocking.
- Tool is run with sufficient privileges to read the neighbor table (usually no special privileges required).

## Out of Scope

- Active network scanning
- Packet injection or ARP reply generation
- Windows / macOS neighbor table support
- Real-time continuous monitoring daemon (use external scheduler)
