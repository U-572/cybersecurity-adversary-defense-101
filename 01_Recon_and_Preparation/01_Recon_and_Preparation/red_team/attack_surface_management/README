# Autonomous Attack Surface Management (ASM) Pipeline

## Overview

This project demonstrates an automated reconnaissance architecture for identifying and tracking an organization's externally visible infrastructure.

The pipeline combines multiple intelligence sources and enumeration techniques into a modular reconnaissance workflow.

## Layman's Explanation

Organizations expose information about their internet-facing systems through sources such as DNS records, routing information, and public certificate records.

Instead of manually checking these sources one at a time, this project demonstrates how Python can collect and organize that information automatically.

Think of it as building a continuously updated map of an organization's publicly visible digital footprint.

## Strategic Value

Attack-surface management helps security teams and authorized security testers understand what infrastructure is externally visible.

The project demonstrates several cybersecurity engineering concepts:

- Passive reconnaissance
- Certificate Transparency monitoring
- ASN/BGP infrastructure discovery
- Subdomain analysis
- Asynchronous Python
- Event-driven intelligence collection
- Automated attack-surface management

## Architecture

The project is divided into several logical modules:

### Module 1 — ASN/BGP Discovery

Identifies network ranges associated with the organization.

### Module 2 — Certificate Transparency Monitoring

Observes publicly issued TLS certificates to identify newly exposed infrastructure.

### Module 3 — Predictive Permutation

Analyzes discovered naming conventions and generates candidate infrastructure names for further research.

### Module 4 — Wildcard Certificate Handling

Identifies wildcard certificates and adjusts the discovery workflow accordingly.

## Files

- `asm_pipeline.py` — primary Python implementation.
- `README.md` — architecture and portfolio documentation.

## Portfolio Status

**Prototype**

The current implementation demonstrates the architecture and event-processing workflow. Some external integrations are represented as prototype or (new hack-work) abstracted components.
