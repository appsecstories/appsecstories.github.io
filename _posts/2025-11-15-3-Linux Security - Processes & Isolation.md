---
layout: post
title: "Linux Security - Processes & Isolation"
date: 2025-11-15 10:00:00 +0000
categories: [linux-security]
tags: [linux-security]
author: Application Security Engineer
comments: true
excerpt: "Linux secures processes through strict isolation enforced by the kernel, preventing one process from directly accessing another’s memory or resources."
---

# Linux Security Internals: Processes & Isolation

## 1. The Fundamental Unit: The Process
In Linux, everything running is a **Process**. A container is **not** a real physical object; it is simply a process with restricted views of the system.

### Core Attributes
* **PID (Process ID):** Unique identifier.
    * **PID 1 (init/systemd):** The first process started by the kernel. It manages all other processes. If PID 1 dies, the system crashes (kernel panic).
* **PPID (Parent PID):** The ID of the process that spawned this one.
* **UID/GID:** The user and group the process is running as.
* **File Descriptors (FD):** Pointers to open files, sockets, or pipes.

### The `/proc` Filesystem (The Gold Mine)
Linux exposes kernel data about processes as files in the `/proc` directory. This is critical for forensics and reviews.

| Path | Description | Security Value |
| :--- | :--- | :--- |
| `/proc/[pid]/cmdline` | The full command used to start the process. | Identify suspicious flags or arguments. |
| `/proc/[pid]/environ` | Environment variables. | **Secrets Leakage:** Look for AWS_KEYS, DB_PASSWORDS here. |
| `/proc/[pid]/cwd` | Symlink to the process's working directory. | See where malware is executing from. |
| `/proc/[pid]/exe` | Symlink to the actual binary file. | Recover deleted malware binaries (if still running). |
| `/proc/[pid]/fd/` | List of open files/sockets. | See who the malware is talking to (network sockets). |


## 2. Process Isolation: Namespaces


If you run `top` on a host, you see everything. How do containers (like Docker) stop a process from seeing other processes? **Namespaces**.

Namespaces wrap a global system resource in an abstraction that makes it appear to the processes within the namespace that they have their own isolated instance of the global resource.

### The "Big 6" Namespaces

| Namespace | Resource Isolated | Security Implication |
| :--- | :--- | :--- |
| **PID** | Process IDs | Process thinks it is PID 1. It cannot see or kill processes on the host. |
| **MNT** | Mount points | Process has its own `/` (root) filesystem. It can't see `/home` or `/etc` of the host unless mounted. |
| **NET** | Network stack | Process has its own IP, `lo` interface, and firewall rules. |
| **USER** | User IDs | **User Mapping:** A process can be "root" (UID 0) inside the container but "nobody" (UID 65534) on the host. |
| **UTS** | Hostname | Process can have its own hostname (e.g., `web-server-01`). |
| **IPC** | Inter-Process Comm | Prevents shared memory attacks between host and container. |

### ❓ Q&A: Is a Container a VM?
**Q: Is a container just a lightweight Virtual Machine?**
**A: No.**
* **VM:** Has its own Kernel and virtual hardware.
* **Container:** Shares the **Host Kernel**. It is just a Linux process with Namespaces (blindfolds) and Cgroups (handcuffs).
* **Security Risk:** If a containerized process exploits a Kernel Vulnerability (e.g., Dirty COW), it compromises the **entire Host**.


## 3. Resource Control: Cgroups (Control Groups)
While Namespaces control what a process can *see*, Cgroups control what a process can *use*.

### Why it matters
Without Cgroups, a single compromised web server process could consume 100% of the CPU and RAM, crashing the entire server (Denial of Service).

### What Cgroups Limit
1.  **CPU:** "You get 0.5 cores."
2.  **Memory:** "You get 512MB RAM. If you exceed it -> OOM Kill."
3.  **PIDs:** "You can only spawn 100 children" (Prevents Fork Bombs).
4.  **BlkIO:** "You can only read disk at 10MB/s."

## 4. Container Security & "Privileged" Mode
In Docker/Kubernetes reviews, checking for `--privileged` is step #1.

### What `--privileged` actually does
It essentially turns off all the safety mechanisms we just discussed.
1.  **Caps:** Grants **all** Capabilities.
2.  **Devices:** Grants access to all `/dev/` devices (can wipe the hard drive).
3.  **AppArmor/SELinux:** Disables them.

**The Equation:**
> Privileged Container = Root on Host (with extra steps).

### The "Docker Socket" Risk
If you find `/var/run/docker.sock` mounted inside a container, that container has full control over the Docker daemon on the host. It can spin up a *new* container, mount the host's root directory to it, and edit `/etc/shadow`.


## 5. Audit & Hunting Commands

**1. List all Namespaces:**
See which processes are isolated.
```bash
lsns
```

2. Check Process Environment (Hunting for Secrets):

# Replace [PID] with target process ID
```bash
cat /proc/[PID]/environ | tr '\0' '\n'
```

3. Tree View of Processes: Visualize the parent-child relationship (useful to spot spawning malware).

```bash
ps auxf
```

4. Check for Container Breakouts (Host View): Check if any container processes are running as actual Root (UID 0) on the host.

```bash
# Look for processes with UID 0 that look like container workloads (java, python, node)
ps -ef | grep "^root"
```

6. Review Checklist
Secrets: Are processes running with environment variables containing keys? (Check /proc).

Isolation: Are critical services running in their own Namespaces?

Privilege: Are any containers running as --privileged?

User Mapping: Are container processes running as UID 0 (Root) inside the container? (Ideally, they should be a non-root user).
