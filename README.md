
# Cowrie SSH Honeypot + Wazuh SIEM Stack Project

![Map](traffic-map.png)

## Table of Contents

- [Project Overview](#project-overview)
- [Lab Environment](#lab-environment)
- [Attacker Behavior & Investigation](#attacker-behavior-&-investigation)
- [Conclusion](#conclusion)


## **Project Overview**

This project involves deploying and monitoring a medium-interaction SSH honeypot using Cowrie, integrated with a centralized security monitoring and log analysis stack based on Wazuh and the Elastic Stack. The goal is to capture and analyze malicious SSH activity in real time, understand attacker behavior, and build a scalable detection and visualization pipeline using modern cybersecurity tools.

## **Lab Environment**
The project infrastructure is hosted on a **cloud-based OVH bare metal server** running **Proxmox** as the hypervisor. The internal environment includes:

- A **Cowrie SSH honeypot VM** running on Ubuntu-24.04 Live Server, with limited outbound traffic allowed only over essential ports (e.g., SSH).
- A **Wazuh stack server VM** running the Wazuh All-in-One Docker deployment, which includes Wazuh Manager, Elasticsearch, Logstash, and Filebeat.
- A **management VM** running on Ubuntu-24.04 Desktop for access to the Wazuh Dashboard and Grafana interface.
- A **pfSense firewall VM** controlling internal traffic flow to ensure the honeypot remains isolated except for required communication between the Wazuh agent and manager.

### **Honeypot Configuration**
The honeypot uses **Cowrie**, a medium-to-high interaction SSH honeypot designed to emulate a shell environment. It logs attacker activity such as:

- Both failed and successful login attempts
- Attempted usernames, passwords, and post-authentication commands
- Source IP addresses** for every attempt

### **Wazuh Stack**

The detection and monitoring system is deployed using the **Wazuh All-in-One Docker installer**, which sets up a complete SIEM stack in a containerized environment. This stack integrates components from the **Wazuh platform** and the **Elastic Stack**, providing centralized log collection, enrichment, alerting, storage, and visualization.

- **Wazuh Manager** – Collects log data from agents, applies decoders and rules, and generates alerts.  
- **Elasticsearch** – Stores structured log and alert data for search, correlation, and visualization.  
- **Filebeat** – Forwards alert data from Wazuh Manager to Logstash.
- **Logstash** – Enriches log data before indexing it in Elasticsearch.
- **Wazuh Dashboard** – Web interface built on Kibana for visualizing alerts, agent status, and logs.
- **Grafana** *(Added to replace Kibana)* – Used to build real-time custom dashboards with data from Elasticsearch.

A custom ruleset was created to ingest logs according to:
- Failed login attempts
- Successful logins (using Cowrie-accepted credentials)
- Command execution after login

### **Log Pipeline**
Logs follow this path:

1. Cowrie generates structured logs that record all activity.
2. The Wazuh Agent, installed on the honeypot VM, reads Cowrie’s log files and forwards them to the Wazuh Manager.
3. The Wazuh Manager parses the logs using our custom rules to generate alerts.
4. Alerts and enriched log data are sent to Elasticsearch for indexing.
5. Dashboards (Grafana or Wazuh’s own dashboard) query Elasticsearch to visualize the data.

![Diagram](Architecture-Diagram.png)


### **Visualization in Grafana**
Instead of Kibana, this project uses **Grafana** with the **Elasticsearch plugin** to create real-time dashboards. Although Kibana is commonly used with Elasticsearch, I chose Grafana for this project because my team at work is planning to adopt it soon. I wanted to get ahead by becoming familiar with the tool, and this project gave me a practical use case to start exploring its capabilities.

Visualizations include:
- Successful and failed login attempts
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
