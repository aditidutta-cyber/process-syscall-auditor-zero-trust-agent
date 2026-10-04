# Process Syscall Auditor & Zero-Trust Behavioral Agent

## Domain

**Domain 4: Cybersecurity, Observability & Forensics**

## Project Overview

The **Process Syscall Auditor & Zero-Trust Behavioral Agent** is a Linux-based cybersecurity prototype designed to monitor process execution activity at the kernel level and analyze the observed behavior in user space.

The system uses a **Linux Kernel Module** with a **Kprobe** attached to the `execve` system-call path. Process execution events are captured by the kernel component and exposed through the `/dev/process_auditor` character device.

A **C++17 Behavioral Analysis Agent** reads these events and evaluates them against predefined security profiles. Based on the observed behavior, the agent calculates a risk score, assigns a risk level, and generates a security decision.

## System Architecture

```text
                    LINUX SYSTEM
                         |
                         v
                 Running Processes
                         |
                         v
                    execve() Event
                         |
                         v
              +----------------------+
              |  Linux Kernel Module |
              |   process_auditor    |
              |       Kprobe         |
              +----------+-----------+
                         |
                         v
                 /dev/process_auditor
                         |
                         v
              +----------------------+
              | C++17 Behavioral     |
              | Analysis Agent       |
              +----------+-----------+
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
```
## Main Components
1. Kernel Monitoring Module
Source: process_auditor.c
The kernel component is responsible for monitoring process execution events.
Responsibilities:
- Linux Kernel Module implementation
- Kprobe-based monitoring of the execve system-call path
- Capturing process execution information
- Providing the /dev/process_auditor character device
- Generating EXEC_EVENT records
Captured Information:
- PID
- PPID
- UID
- Process command name (COMM)
2. C++ Behavioral Analysis Agent
Source: auditor_agent.cpp
The C++17 agent acts as the user-space security analysis component.
Responsibilities:
- Reading events from /dev/process_auditor
- Matching events against security profiles
- Calculating behavioral risk scores
- Assigning risk levels
- Generating security decisions
- Recording audit results in audit.log
Security Profiles:
- NORMAL_EXECUTION
- PRIVILEGED_EXECUTION
- SHELL_EXECUTION
- SUSPICIOUS_UTILITY
3. Demonstration Program
Source: process_demo.c
A simple Linux C program used to generate process execution activity for testing and demonstration of the monitoring system.
## Risk Model
The prototype uses lightweight behavioral rules to calculate a risk score.
Observed Behavior	Risk Contribution
UID 0 / Privileged Execution	+20
bash / sh / zsh Execution	+20
nc / ncat / nmap / netcat	+40


Risk Classification
Risk Score	Risk Level	Decision
0–19	LOW	ALLOW
20–49	MEDIUM	MONITOR
50+	HIGH	ALERT


## Example Output
========================================
 Process Syscall Auditor
 Zero-Trust Behavioral Agent
========================================

[SYSCALL AUDIT]
System Call: execve
Event      : EXEC_EVENT PID=12506 PPID=12505 UID=0 COMM=sudo

[SECURITY PROFILE]
Profile : PRIVILEGED_EXECUTION

[BEHAVIOR ANALYSIS]
Risk Score: 20
Risk Level: MEDIUM
Decision  : MONITOR

Audit record saved to audit.log

## Technologies Used
- Linux
- C
- C++17
- Linux Kernel Module
- Kprobes
- System Call Monitoring
- Character Device Interface
- GCC / G++
- Make
- Git & GitHub
## Project Structure
process-syscall-auditor-zero-trust-agent/
│
├── README.md
├── Makefile
├── process_auditor.c
├── auditor_agent.cpp
├── process_demo.c
└── .gitignore

## Requirements
- Ubuntu / Linux
- GCC
- G++
- Linux Kernel Headers
- Make
- Root / sudo access for loading the kernel module
## Build and Run
Build the Kernel Module
make

Load the Kernel Module
sudo insmod process_auditor.ko

Verify the Module
lsmod | grep process_auditor

Run the Behavioral Agent
sudo ./auditor_agent

View Audit Log
cat audit.log

Remove the Kernel Module
sudo rmmod process_auditor

## Project Status
The project is implemented as a working Linux prototype demonstrating:
- Kernel-level process execution monitoring
- Kprobe-based syscall observation
- Kernel-to-user-space event communication
- C++17 behavioral analysis
- Security profile classification
- Risk-based decision-making
- Audit logging
