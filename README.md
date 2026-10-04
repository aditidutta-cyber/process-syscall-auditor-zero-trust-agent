# Process Syscall Auditor & Zero-Trust Behavioral Agent

## 1. Project Overview

Process Syscall Auditor & Zero-Trust Behavioral Agent is a Linux-based security monitoring project developed using C and C++.

The system monitors process execution activity inside the Linux kernel and sends captured event information to a user-space C++ security agent.

The C++ agent performs basic behavioral analysis, assigns a risk score, determines a risk level, and stores the result in an audit log.

## 2. Objectives

- Monitor process execution activity in Linux.
- Capture process information from the kernel.
- Demonstrate Linux kernel module concepts.
- Provide a user-space C++ security agent.
- Apply basic zero-trust behavioral rules.
- Generate risk levels for observed events.
- Maintain an audit log.

## 3. System Architecture

```text
Linux Process
      |
      v
   execve()
      |
      v
+-----------------------+
| Linux Kernel Module   |
| process_auditor       |
+-----------+-----------+
            |
            v
 /dev/process_auditor
            |
            v
+-----------------------+
| C++ Security Agent   |
| auditor_agent        |
+-----------+-----------+
            |
            v
   Behavioral Analysis
            |
            v
       Risk Score
            |
      +-----+------+
      |            |
      v            v
    ALLOW        MONITOR
      |            |
      +-----+------+
            |
            v
        audit.log
