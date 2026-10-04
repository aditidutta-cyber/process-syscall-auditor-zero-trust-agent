# Process Syscall Auditor & Zero-Trust Behavioral Agent

## Domain
**Domain 4: Cybersecurity, Observability & Forensics**

## Project Overview

The Process Syscall Auditor & Zero-Trust Behavioral Agent is a Linux-based security monitoring prototype that observes process execution events at the kernel level and analyzes them in user space.

The system uses a Linux kernel module with a Kprobe attached to the `execve` system-call path. Execution events are exposed through the `/dev/process_auditor` character device and consumed by a C++17 behavioral analysis agent.

The C++ agent matches observed events against security profiles, calculates a risk score, determines a risk level, and produces a security decision.

## Architecture

```text
Running Processes
        |
        v
   execve() event
        |
        v
+----------------------+
| Linux Kernel Module  |
|   process_auditor    |
|       Kprobe         |
+----------------------+
        |
        v
 /dev/process_auditor
        |
        v
+----------------------+
| C++17 Behavioral     |
| Analysis Agent       |
+----------------------+
        |
        v
 Security Profile
        |
        v
 Risk Score / Level
        |
        v
 ALLOW / MONITOR / ALERT
        |
        v
     audit.log
