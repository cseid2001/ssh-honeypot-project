
# Cowrie SSH Honeypot + Wazuh SIEM Stack Project

## Table of Contents

- [Project Overview](#project-overview)
- [Architecture](#architecture)
- [Setup](#setup)
- [Logs and Analysis](#logs-and-analysis)
- [Conclusion](#conclusion)


## **Project Overview**

This project involves deploying and monitoring a medium-interaction SSH honeypot using Cowrie, integrated with a full observability and detection stack. The goal is to capture and analyze malicious SSH activity in real time, understand attacker behavior, and build a scalable detection and visualization pipeline using modern cybersecurity tools.

## **Architecture**
The project infrastructure is hosted on a **cloud-based OVH bare metal server** running **Proxmox** as the hypervisor. The internal environment includes:

- A **Cowrie SSH honeypot VM** running on Ubuntu Server, with limited outbound traffic allowed only over essential ports (e.g., SSH).
- A **Wazuh stack server VM** running the **Wazuh All-in-One Docker deployment**, which includes Wazuh Manager, Elasticsearch, Logstash, and Filebeat.
- A **management VM** running on Ubuntu Desktop for access to the Wazuh Dashboard and Grafana interface.
- A **pfSense firewall VM** controlling internal traffic flow to ensure the honeypot remains isolated except for required communication between the Wazuh agent and manager.

### **Honeypot Configuration**
The honeypot uses **Cowrie**, a medium-to-high interaction SSH honeypot designed to emulate a shell environment. It is configured to:

- **Log both failed and successful login attempts**
- Record attacker-entered **usernames, passwords, and post-authentication commands**
- Capture **source IP addresses** for every attempt to enable geolocation and behavioral tracking

### **Wazuh Stack**
The detection stack is deployed using the **Wazuh All-in-One** Docker installer. This containerized setup includes:

- **Wazuh Manager** for rule-based alerting
- **Elasticsearch** for log indexing and storage
- **Logstash** for log enrichment and filtering
- **Filebeat** for forwarding alerts

A custom ruleset was created to detect:
- Failed login attempts
- Successful logins (using Cowrie-accepted credentials)
- Command execution after login

### **Log Pipeline**
Logs follow this path:

1. Cowrie generates JSON logs
2. Wazuh Agent forwards logs to Wazuh Manager
3. Filebeat ships alert data to Logstash
4. Logstash enriches logs with GeoIP metadata
5. Logs are indexed in Elasticsearch for query and visualization

This enrichment allows for geographic and behavioral analysis of attacker IPs directly in both Grafana and the Wazuh Dashboard.

### **Visualization in Grafana**
Instead of Kibana, this project uses **Grafana** with the **Elasticsearch plugin** to create real-time dashboards. Visualizations include:

- Successful vs. failed login attempts
- Top attempted usernames
- Commands entered by attackers
- Geolocation map of source IPs
- Time-series analysis of login activity
- Attack volume by country
- Unique IPs per region

---

## **Attacker Behavior & Investigation**

The honeypot has been running for one week (currently on day 4), capturing live attack data. In this section, I will investigate specific IP addresses, analyze command sequences, and attempt to infer attacker intent based on behavior.

### Initial Findings
One attacker session has stood out due to its depth and reconnaissance techniques:

- Attempted to identify whether the system was a **router**, **SMS server**, or **crypto mining node**
- Searched for pre-existing malware or mining processes
- Issued a command to test if the environment was a **real shell**
- Upon realizing it was likely simulated, the attacker disconnected

The next sections will dive deeper into:
- Command breakdowns by attacker
- Source IP enrichment and geo-profiling
- Potential goals behind each interaction
