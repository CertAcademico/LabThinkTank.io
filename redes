Scanning Tools and Enumeration Objectives


https://github.com/future-architect/vuls
https://github.com/evilsocket/opensnitch
https://github.com/nmap/nmap
https://github.com/slackhq/nebula
https://github.com/InterviewMap/CS-Interview-Knowledge-Map
https://github.com/cilium/cilium
https://github.com/projectdiscovery/nuclei
https://github.com/GyulyVGC/sniffnet
https://github.com/edoardottt/awesome-hacker-search-engines

------------------------------------------------------------------------------------------------------------------
Guia de Instalciones y Documentación de las herramientas 


    Primary Hacking Stage: Reconnaissance / Network Monitoring
    MITRE ATT&CK Phase: Discovery (TA0007)
    Target Environment: Local Area Networks (LAN)

⚙️ Product Information

    Developer/Owner: GyulyVGC
    GitHub Repository: https://github.com/GyulyVGC/sniffnet
    Popularity: 34,682 stars

🚀 Quick Start (Installation & Run)

# On macOS via Homebrew
brew install sniffnet
# On Linux (Cargo)
cargo install sniffnet

📖 Simple Usage Guide

    Launch the application and select the network interface you wish to monitor.
    Apply filters for specific protocols (TCP, UDP, ICMP) or traffic types to narrow your focus.
    Observe the real-time graphs and inspect individual connections for suspicious data flow.

🛡️ Security Note

Ensure you have explicit permission to monitor traffic on the selected network; unauthorized sniffing may violate privacy laws and corporate policies.
Nuclei
📋 Overview

Nuclei is a powerful, template-based vulnerability scanner that allows for fast, customizable scanning of modern applications. It utilizes a simple YAML-based DSL to enable the community to rapidly share and deploy checks for trending vulnerabilities.
🎯 Tactical Applicability

    Primary Hacking Stage: Vulnerability Research / Enumeration
    MITRE ATT&CK Phase: Reconnaissance (TA0043)
    Target Environment: Web Applications, APIs, Cloud, Networks

⚙️ Product Information

    Developer/Owner: projectdiscovery
    GitHub Repository: https://github.com/projectdiscovery/nuclei
    Popularity: 28,010 stars

🚀 Quick Start (Installation & Run)

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -u https://example.com

📖 Simple Usage Guide

    Update the local template library using the nuclei -ut command.
    Run a standard scan against a target URL to identify common misconfigurations.
    Review the output for severity-graded vulnerabilities and use the provided links for remediation steps.

🛡️ Security Note

Scanning targets without authorization is illegal; always use Nuclei within the scope of a bug bounty program or professional penetration test.
Cilium
📋 Overview

Cilium is an open-source project that provides eBPF-based networking, security, and observability for container workloads. It enables high-performance connectivity and rigorous security policies for Kubernetes clusters and other container orchestration platforms.
🎯 Tactical Applicability

    Primary Hacking Stage: Infrastructure Hardening / Defense
    MITRE ATT&CK Phase: Network Denial of Service (TA0040) / Defensive Evasion
    Target Environment: Kubernetes / Cloud Native

⚙️ Product Information

    Developer/Owner: cilium
    GitHub Repository: https://github.com/cilium/cilium
    Popularity: 24,177 stars

🚀 Quick Start (Installation & Run)

cilium install
cilium status

📖 Simple Usage Guide

    Install the Cilium CLI and deploy it to your Kubernetes cluster.
    Define "CiliumNetworkPolicy" resources to restrict traffic between specific microservices.
    Use the Hubble component to visualize flow logs and verify security policy enforcement.

🛡️ Security Note

Misconfiguration of eBPF policies can lead to service outages; test network policies in a staging environment before production deployment.
RustScan
📋 Overview

RustScan is a high-speed modern port scanner designed to find open ports in seconds. It is built to integrate seamlessly with Nmap, automatically piping discovered ports into Nmap for deeper script scanning.
🎯 Tactical Applicability

    Primary Hacking Stage: Enumeration
    MITRE ATT&CK Phase: Discovery (TA0007)
    Target Environment: Network Infrastructure

⚙️ Product Information

    Developer/Owner: bee-san
    GitHub Repository: https://github.com/bee-san/RustScan
    Popularity: 19,637 stars

🚀 Quick Start (Installation & Run)

docker run -it --rm --name rustscan rustscan/rustscan:latest -a 192.168.1.1 -- -sV

📖 Simple Usage Guide

    Run RustScan against a target IP or range to quickly identify all open ports.
    Allow the tool to automatically pass those open ports to Nmap for service version detection.
    Analyze the combined output to find entry points or exposed services.

🛡️ Security Note

The extreme speed of RustScan can easily trigger Intrusion Detection Systems (IDS) and firewalls; adjust batch sizes to avoid detection.
Bettercap
📋 Overview

Bettercap is the "Swiss Army knife" for network reconnaissance and Man-In-The-Middle (MITM) attacks. It supports auditing of WiFi, Bluetooth Low Energy (BLE), wireless HID, and traditional IPv4/IPv6 networks.
🎯 Tactical Applicability

    Primary Hacking Stage: Exploitation / MITM
    MITRE ATT&CK Phase: Adversary-in-the-Middle (T1557)
    Target Environment: Local Networks, WiFi, BLE

⚙️ Product Information

    Developer/Owner: bettercap
    GitHub Repository: https://github.com/bettercap/bettercap
    Popularity: 19,091 stars

🚀 Quick Start (Installation & Run)

sudo apt install bettercap
sudo bettercap -iface eth0

📖 Simple Usage Guide

    Start the interactive session and use net.probe on to discover hosts on the network.
    Use the arp.spoof module to position yourself between a target and the gateway.
    Enable net.sniff to capture credentials and sensitive data passing through the network.

🛡️ Security Note

MITM attacks can disrupt network stability and involve intercepting private data; use only in controlled, legal testing environments.
CS-Interview-Knowledge-Map
📋 Overview

This repository is a comprehensive educational resource covering core Computer Science concepts required for interviews. It includes detailed sections on security, networking, performance optimization, and algorithms.
🎯 Tactical Applicability

    Primary Hacking Stage: Skill Development / Knowledge Acquisition
    MITRE ATT&CK Phase: Preparation (TA0042)
    Target Environment: Educational / Career Development

⚙️ Product Information

    Developer/Owner: InterviewMap
    GitHub Repository: https://github.com/InterviewMap/CS-Interview-Knowledge-Map
    Popularity: 18,287 stars

🚀 Quick Start (Installation & Run)

# No installation required; read online or clone locally
git clone https://github.com/InterviewMap/CS-Interview-Knowledge-Map.git

📖 Simple Usage Guide

    Navigate to the "Security" or "Network" folders within the repository.
    Study the curated notes on XSS, CSRF, and HTTP protocols.
    Use the provided maps to visualize how different CS concepts interconnect during system design.

🛡️ Security Note

This is a documentation-only repository; ensure you apply the security knowledge learned here to build safer applications.
Nebula
📋 Overview

Nebula is a scalable overlay networking tool developed by Slack that focuses on performance and security. It allows users to create a seamless mesh network between any number of hosts, regardless of their physical location or network configuration.
🎯 Tactical Applicability

    Primary Hacking Stage: Post-Exploitation / Secure Communication
    MITRE ATT&CK Phase: Command and Control (TA0011)
    Target Environment: Distributed Infrastructure / Multi-Cloud

⚙️ Product Information

    Developer/Owner: slackhq
    GitHub Repository: https://github.com/slackhq/nebula
    Popularity: 17,244 stars

🚀 Quick Start (Installation & Run)

# Download binary and generate keys
./nebula-cert ca -name "MyNetwork"
./nebula -config config.yml

📖 Simple Usage Guide

    Define a "Lighthouse" node to serve as a central discovery point for all other nodes.
    Generate certificates for each host to ensure mutually authenticated encrypted traffic.
    Run the Nebula binary on each host to establish a secure, private overlay network.

🛡️ Security Note

The security of a Nebula network relies entirely on the secrecy of the CA private key; protect it with extreme care.
Hydra (Ory)
📋 Overview

Ory Hydra is a hardened, OpenID Certified™ OAuth 2.1 and OpenID Connect provider. It is designed to integrate with existing user management systems to provide secure authentication and authorization at scale.
🎯 Tactical Applicability

    Primary Hacking Stage: IAM / Security Architecture
    MITRE ATT&CK Phase: Valid Accounts (T1078)
    Target Environment: Web/Cloud Identity Systems

⚙️ Product Information

    Developer/Owner: ory
    GitHub Repository: https://github.com/ory/hydra
    Popularity: 17,076 stars

🚀 Quick Start (Installation & Run)

docker run -it --rm --name ory-hydra-example orycorp/hydra:v2.2 serve all --dev

📖 Simple Usage Guide

    Configure Hydra to connect to your existing user database via a simple login/consent flow provider.
    Register OAuth2 clients (applications) using the Hydra CLI.
    Use the generated tokens to authorize API requests across your microservices.

🛡️ Security Note

Improperly configured OAuth2 flows can lead to account takeovers; always follow the official Ory security best practices.
90DaysOfCyberSecurity
📋 Overview

This repository provides a structured 90-day study plan for individuals looking to master cybersecurity. It covers a vast range of topics including Linux, Python, Traffic Analysis, and Hacking techniques.
🎯 Tactical Applicability

    Primary Hacking Stage: Skill Development
    MITRE ATT&CK Phase: Preparation (TA0042)
    Target Environment: Personal Learning / Lab

⚙️ Product Information

    Developer/Owner: farhanashrafdev
    GitHub Repository: https://github.com/farhanashrafdev/90DaysOfCyberSecurity
    Popularity: 14,640 stars

🚀 Quick Start (Installation & Run)

git clone https://github.com/farhanashrafdev/90DaysOfCyberSecurity.git
cd 90DaysOfCyberSecurity && open LEARN.md

📖 Simple Usage Guide

    Follow the Day 1–90 roadmap sequentially to build a foundation in IT and security.
    Utilize the provided links and resources for hands-on practice in each domain.
    Track your progress by checking off daily tasks and completing the associated labs.

🛡️ Security Note

This repository contains links to offensive tools; ensure all practice is conducted within virtual machines or authorized labs.
OpenSnitch
📋 Overview

OpenSnitch is a GNU/Linux port of the famous Little Snitch application firewall. It monitors outgoing network connections and prompts the user to allow or deny them, providing deep visibility into application behavior.
🎯 Tactical Applicability

    Primary Hacking Stage: Defense / Egress Filtering
    MITRE ATT&CK Phase: Network Boundary Bridging (T1599)
    Target Environment: Linux Desktop/Server

⚙️ Product Information

    Developer/Owner: evilsocket
    GitHub Repository: https://github.com/evilsocket/opensnitch
    Popularity: 13,497 stars

🚀 Quick Start (Installation & Run)

# Install the daemon and GUI (Debian/Ubuntu example)
sudo apt install opensnitch

📖 Simple Usage Guide

    Start the OpenSnitch daemon and the GUI background process.
    Interact with the pop-up alerts whenever a new application attempts to connect to the internet.
    Review the "Rules" tab to permanently block or allow specific domains and IP ranges.

🛡️ Security Note

Blindly clicking "Allow" on every prompt defeats the purpose of a firewall; examine the process path and destination carefully.
Nmap
📋 Overview

Nmap ("Network Mapper") is the industry-standard tool for network discovery and security auditing. It uses raw IP packets in novel ways to determine what hosts are available, what services they offer, and what operating systems they are running.
🎯 Tactical Applicability

    Primary Hacking Stage: Recon / Enumeration
    MITRE ATT&CK Phase: Discovery (TA0007)
    Target Environment: Global Networks

⚙️ Product Information

    Developer/Owner: nmap
    GitHub Repository: https://github.com/nmap/nmap
    Popularity: 12,728 stars

🚀 Quick Start (Installation & Run)

sudo apt install nmap
nmap -A -T4 scanme.nmap.org

📖 Simple Usage Guide

    Perform a basic ping sweep to identify live hosts on a subnet.
    Run a service detection scan (-sV) to find the version numbers of running software.
    Use the Nmap Scripting Engine (NSE) to check for specific vulnerabilities like Heartbleed or SMB exploits.

🛡️ Security Note

Aggressive scans can crash legacy systems and are easily detected by modern blue teams; use timing templates (-T) wisely.
Vuls
📋 Overview

Vuls is an agentless vulnerability scanner for Linux and FreeBSD. It is designed for system administrators to automate vulnerability management across many servers, providing high-quality reports in multiple formats.
🎯 Tactical Applicability

    Primary Hacking Stage: Vulnerability Management
    MITRE ATT&CK Phase: Reconnaissance (TA0043)
    Target Environment: Linux Servers, Containers, WordPress

⚙️ Product Information

    Developer/Owner: future-architect
    GitHub Repository: https://github.com/future-architect/vuls
    Popularity: 12,113 stars

🚀 Quick Start (Installation & Run)

# Using the install script
curl -sL https://raw.githubusercontent.com/vulsio/vulsctl/master/install-host.sh | bash

📖 Simple Usage Guide

    Configure SSH access to the target servers you wish to scan.
    Run the vuls prepare command to check dependencies on target hosts.
    Execute vuls scan followed by vuls report to view a categorized list of CVEs affecting your systems.

🛡️ Security Note

Scanning requires SSH access; ensure the scanning user has the minimum necessary privileges to read package versions.
Netmaker
📋 Overview

Netmaker automates the creation of fast, secure, and distributed virtual networks using WireGuard. It acts as a central control plane to manage mesh VPNs across clouds, edge devices, and on-premise servers.
🎯 Tactical Applicability

    Primary Hacking Stage: Post-Exploitation / Tunneling
    MITRE ATT&CK Phase: Command and Control (TA0011)
    Target Environment: Multi-Cloud / Edge Computing

⚙️ Product Information

    Developer/Owner: gravitl
    GitHub Repository: https://github.com/gravitl/netmaker
    Popularity: 11,540 stars

🚀 Quick Start (Installation & Run)

# Deploying via Docker Compose (Simplified)
wget -qO - https://raw.githubusercontent.com/gravitl/netmaker/master/scripts/nm-quick.sh | bash

📖 Simple Usage Guide

    Log into the Netmaker UI and create a new network.
    Install the netclient agent on any host you want to add to the mesh.
    Use the Netmaker dashboard to manage access control lists (ACLs) between the connected nodes.

🛡️ Security Note

Exposing the Netmaker API to the public internet without strong authentication can compromise your entire virtual network.
SimpleX Chat
📋 Overview

SimpleX is a private messaging protocol and app that operates without user identifiers (no phone numbers, no emails). It is built for 100% privacy and metadata protection by utilizing a unique routing architecture.
🎯 Tactical Applicability

    Primary Hacking Stage: Secure Communication
    MITRE ATT&CK Phase: Command and Control (TA0011)
    Target Environment: Mobile / Desktop

⚙️ Product Information

    Developer/Owner: simplex-chat
    GitHub Repository: https://github.com/simplex-chat/simplex-chat
    Popularity: 10,935 stars

🚀 Quick Start (Installation & Run)

# Desktop version (example for Linux)
flatpak install flathub chat.simplex.SimpleX

📖 Simple Usage Guide

    Open the app and create a local profile (stored only on your device).
    Share a one-time invitation link with a contact via an external secure channel.
    Start messaging; the server only sees ephemeral queues, not your identity or social graph.

🛡️ Security Note

While highly private, the security of your conversations still depends on the physical security of your endpoint device.
Firezone
📋 Overview

Firezone is an open-source Zero Trust Access platform built on WireGuard. It provides a secure alternative to traditional VPNs, allowing for granular access control and identity-based routing for remote teams.
🎯 Tactical Applicability

    Primary Hacking Stage: Defense / Access Control
    MITRE ATT&CK Phase: Resource Hijacking (TA0040) / Defense Evasion
    Target Environment: Enterprise Cloud / Corporate Networks

⚙️ Product Information

    Developer/Owner: firezone
    GitHub Repository: https://github.com/firezone/firezone
    Popularity: 8,579 stars

🚀 Quick Start (Installation & Run)

bash <(curl -s https://raw.githubusercontent.com/firezone/firezone/master/scripts/install.sh)

📖 Simple Usage Guide

    Deploy Firezone on a central Linux server with a public IP.
    Integrate your OIDC or SAML provider (e.g., Google, Okta) for user authentication.
    Create specific policies to grant users access only to the internal applications they need.

🛡️ Security Note

Zero Trust requires strict policy maintenance; regularly audit user permissions to prevent over-privileged access.
Tsunami Security Scanner
📋 Overview

Tsunami is a general-purpose network security scanner from Google designed to detect high-severity vulnerabilities with high confidence. It features an extensible plugin system to identify exposed sensitive interfaces and RCE-level bugs.
🎯 Tactical Applicability

    Primary Hacking Stage: Vulnerability Assessment
    MITRE ATT&CK Phase: Reconnaissance (TA0043)
    Target Environment: Large-scale Enterprise Networks

⚙️ Product Information

    Developer/Owner: google
    GitHub Repository: https://github.com/google/tsunami-security-scanner
    Popularity: 8,565 stars

🚀 Quick Start (Installation & Run)

# Requires Java and Nmap
./tsunami.sh --target-address=127.0.0.1

📖 Simple Usage Guide

    Launch Tsunami against a target IP or hostname.
    The scanner will first perform reconnaissance to identify open ports and services.
    Vulnerability verification plugins will then execute to confirm the presence of high-impact flaws.

🛡️ Security Note

Tsunami is designed to minimize false positives by actually "verifying" the bug; ensure you have authorization as this may involve intrusive checks.
School of SRE
📋 Overview

Created by LinkedIn, this repository contains the curriculum used for onboarding entry-level Site Reliability Engineers. It covers Linux, Networking, Scripting, and System Design fundamentals.
🎯 Tactical Applicability

    Primary Hacking Stage: Defensive Foundations
    MITRE ATT&CK Phase: Preparation (TA0042)
    Target Environment: Infrastructure / DevOps

⚙️ Product Information

    Developer/Owner: linkedin
    GitHub Repository: https://github.com/linkedin/school-of-sre
    Popularity: 8,112 stars

🚀 Quick Start (Installation & Run)

git clone https://github.com/linkedin/school-of-sre.git
# Browse the /curriculum directory

📖 Simple Usage Guide

    Start with the "Level 101" modules to build a baseline in Linux internals.
    Progress to the "Networking" section to understand the stack from a reliability perspective.
    Complete the practical exercises to reinforce your understanding of how large-scale systems stay secure and operational.

🛡️ Security Note

SRE knowledge is critical for understanding system weaknesses; use these insights to build resilience rather than exploit it.
ntopng
📋 Overview

ntopng is a web-based network traffic monitoring application that provides deep packet inspection and security analysis. It visualizes network usage and detects anomalies such as DDoS attacks or data exfiltration.
🎯 Tactical Applicability

    Primary Hacking Stage: Blue Teaming / Traffic Analysis
    MITRE ATT&CK Phase: Network Effects (TA0040)
    Target Environment: Corporate/Campus Networks

⚙️ Product Information

    Developer/Owner: ntop
    GitHub Repository: https://github.com/ntop/ntopng
    Popularity: 7,735 stars

🚀 Quick Start (Installation & Run)

sudo apt install ntopng
sudo systemctl start ntopng

📖 Simple Usage Guide

    Access the web interface (usually port 3000) and identify the top talkers on your network.
    Set alerts for unusual traffic patterns or connections to known malicious blacklists.
    Drill down into specific host flows to investigate potential security breaches or bandwidth hogs.

🛡️ Security Note

ntopng processes sensitive metadata; secure the web interface with strong passwords and HTTPS.
Airgeddon
📋 Overview

Airgeddon is a multi-use bash script for Linux systems to audit wireless networks. It streamlines complex WiFi attacks, including deauthentication, WPA/WPA2 cracking, and "Evil Twin" captive portal attacks.
🎯 Tactical Applicability

    Primary Hacking Stage: Exploitation / WiFi Auditing
    MITRE ATT&CK Phase: Exploitation of Remote Services (T1210)
    Target Environment: 802.11 Wireless Networks

⚙️ Product Information

    Developer/Owner: v1s1t0r1sh3r3
    GitHub Repository: https://github.com/v1s1t0r1sh3r3/airgeddon
    Popularity: 7,660 stars

🚀 Quick Start (Installation & Run)

git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git
sudo ./airgeddon.sh

📖 Simple Usage Guide

    Launch the script and select your wireless interface (put it into Monitor Mode).
    Choose a module, such as "Evil Twin Attacks," to set up a rogue access point.
    Capture handshakes or credentials from connected clients for offline analysis.

🛡️ Security Note

Attacking wireless networks you do not own is highly illegal and easily traceable in many environments.
Zeek
📋 Overview

Zeek (formerly Bro) is a powerful network analysis framework that differs from a traditional signature-based IDS. It provides rich, structured logs of all network activity, enabling deep forensic analysis and threat hunting.
🎯 Tactical Applicability

    Primary Hacking Stage: Threat Hunting / Forensics
    MITRE ATT&CK Phase: Discovery (TA0007) / Exfiltration
    Target Environment: High-Throughput Enterprise Networks

⚙️ Product Information

    Developer/Owner: zeek
    GitHub Repository: https://github.com/zeek/zeek
    Popularity: 7,586 stars

🚀 Quick Start (Installation & Run)

# On Debian/Ubuntu
sudo apt install zeek
zeek -i eth0

📖 Simple Usage Guide

    Run Zeek on a mirror port (SPAN) to capture live network traffic.
    Inspect the generated .log files (e.g., conn.log, http.log, dns.log) to understand network events.
    Write custom Zeek scripts to detect specific behavioral patterns indicative of a breach.

🛡️ Security Note

Zeek generates large amounts of data; ensure you have adequate storage and a SIEM (like ELK) to process the logs.
Calico
📋 Overview

Calico is a cloud-native networking and network security solution that provides high-performance connectivity and policy enforcement for containers and VMs. It is widely used for implementing micro-segmentation in Kubernetes.
🎯 Tactical Applicability

    Primary Hacking Stage: Defensive Segmentation
    MITRE ATT&CK Phase: Lateral Movement (TA0008)
    Target Environment: Kubernetes, AWS, Azure, GCP

⚙️ Product Information

    Developer/Owner: projectcalico
    GitHub Repository: https://github.com/projectcalico/calico
    Popularity: 7,163 stars

🚀 Quick Start (Installation & Run)

kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

📖 Simple Usage Guide

    Deploy Calico into your Kubernetes cluster to manage pod-to-pod networking.
    Use the GlobalNetworkPolicy to define rules that apply across the entire cluster.
    Implement a "Zero Trust" model by defaulting to a deny-all policy and specifically allowing required traffic.

🛡️ Security Note

Incorrectly applied network policies can block critical cluster communication; test policies using "Audit" mode if available.
OnionShare
📋 Overview

OnionShare is an open-source tool that lets you securely and anonymously share files, host websites, and chat using the Tor network. It protects your identity by removing the need for a third-party server.
🎯 Tactical Applicability

    Primary Hacking Stage: Secure Data Transfer
    MITRE ATT&CK Phase: Exfiltration (TA0010)
    Target Environment: Cross-platform (Tor Network)

⚙️ Product Information

    Developer/Owner: onionshare
    GitHub Repository: https://github.com/onionshare/onionshare
    Popularity: 6,936 stars

🚀 Quick Start (Installation & Run)

# On Linux via Flatpak
flatpak install flathub org.onionshare.OnionShare

📖 Simple Usage Guide

    Open OnionShare and select "Share Files."
    Drag and drop the files you wish to send; the tool will generate a .onion address.
    Send the address to the recipient; they download the files directly from your computer via the Tor Browser.

🛡️ Security Note

Sharing files via Tor can be slow, and the link is only active as long as your OnionShare application is running.
NetAlertX
📋 Overview

NetAlertX (formerly Pi.Alert) is a centralized network visibility tool that continuously scans for new devices. It alerts the administrator of changes in the network, helping to detect unauthorized "intruder" devices.
🎯 Tactical Applicability

    Primary Hacking Stage: Blue Teaming / Asset Discovery
    MITRE ATT&CK Phase: Discovery (TA0007)
    Target Environment: Home/Small Office Networks

⚙️ Product Information

    Developer/Owner: netalertx
    GitHub Repository: https://github.com/netalertx/NetAlertX
    Popularity: 6,204 stars

🚀 Quick Start (Installation & Run)

docker run -d --name netalertx -v /path/to/config:/app/config -p 20211:80 jvfricke/netalertx

📖 Simple Usage Guide

    Set up the Docker container and configure your local subnet range.
    Allow the initial scan to build a "known" inventory of your devices.
    Configure mobile or email notifications to alert you when an unrecognized MAC address joins the network.

🛡️ Security Note

This tool relies on ARP/ICMP; sophisticated attackers can spoof MAC addresses or hide from simple pings.
Suricata
📋 Overview

Suricata is a high-performance Network IDS, IPS, and Network Security Monitoring engine. It is capable of real-time intrusion detection, inline intrusion prevention, and network security monitoring.
🎯 Tactical Applicability

    Primary Hacking Stage: Intrusion Prevention / Defense
    MITRE ATT&CK Phase: Detection (TA0007)
    Target Environment: Network Gateway / Perimeter

⚙️ Product Information

    Developer/Owner: OISF
    GitHub Repository: https://github.com/OISF/suricata
    Popularity: 6,167 stars

🚀 Quick Start (Installation & Run)

sudo apt install suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

📖 Simple Usage Guide

    Update your rule set using suricata-update to ensure detection of the latest threats.
    Configure Suricata in "Passive" mode to monitor traffic without affecting flow.
    Switch to "Inline" mode (IPS) to actively drop packets that match malicious signatures.

🛡️ Security Note

Running an IPS can lead to false positives that block legitimate business traffic; tune your rules carefully.
Kubernetes-Network-Policy-Recipes
📋 Overview

This repository is a curated collection of common Kubernetes Network Policy templates. It provides "copy-paste" solutions for securing pod communication in various scenarios.
🎯 Tactical Applicability

    Primary Hacking Stage: Infrastructure Hardening
    MITRE ATT&CK Phase: Lateral Movement (TA0008)
    Target Environment: Kubernetes Clusters

⚙️ Product Information

    Developer/Owner: ahmetb
    GitHub Repository: https://github.com/ahmetb/kubernetes-network-policy-recipes
    Popularity: 6,126 stars

🚀 Quick Start (Installation & Run)

git clone https://github.com/ahmetb/kubernetes-network-policy-recipes.git
# Browse the /recipes folder for YAML files

📖 Simple Usage Guide

    Identify your use case (e.g., "Deny all traffic to a namespace").
    Copy the relevant YAML recipe and modify the labels to match your pods.
    Apply the policy using kubectl apply -f policy.yaml.

🛡️ Security Note

Always verify your pod labels; if labels don't match, the policy may fail to apply, leaving pods exposed.
Bjorn
📋 Overview

Bjorn is an offensive security tool designed for the Raspberry Pi with an e-Paper display. It automates network scanning, vulnerability identification, and even "zombification" of hosts while being a portable handheld device.
🎯 Tactical Applicability

    Primary Hacking Stage: Physical Pentesting / Recon
    MITRE ATT&CK Phase: Discovery (TA0007) / Lateral Movement
    Target Environment: Local Physical Networks

⚙️ Product Information

    Developer/Owner: infinition
    GitHub Repository: https://github.com/infinition/Bjorn
    Popularity: 5,870 stars

🚀 Quick Start (Installation & Run)

# Usually installed on a Raspberry Pi Zero/4 with e-Paper HAT
git clone https://github.com/infinition/Bjorn.git
sudo ./install.sh

📖 Simple Usage Guide

    Plug Bjorn into a target network via Ethernet or connect via WiFi.
    Use the physical buttons on the HAT to start an automated "Scan & Attack" routine.
    Review the discovered vulnerabilities and stolen files via the local display or web interface.

🛡️ Security Note

This tool is highly intrusive and designed for physical red-teaming; use strictly on authorized networks only.
NetExec (nxc)
📋 Overview

NetExec is the successor to CrackMapExec, acting as a multi-protocol exploitation tool for large networks. It automates the assessment of Active Directory environments and other network services.
🎯 Tactical Applicability

    Primary Hacking Stage: Lateral Movement / Credential Stuffing
    MITRE ATT&CK Phase: Lateral Movement (TA0008)
    Target Environment: Windows/Active Directory, SMB, SSH

⚙️ Product Information

    Developer/Owner: Pennyw0rth
    GitHub Repository: https://github.com/Pennyw0rth/NetExec
    Popularity: 5,446 stars

🚀 Quick Start (Installation & Run)

pipx install netexec
nxc smb 192.168.1.0/24 -u user -p pass

📖 Simple Usage Guide

    Run a scan against an IP range to identify SMB signing and OS versions.
    Use valid credentials to test for local admin privileges across the subnet.
    Execute post-exploitation modules like dumping secrets or listing shares.

🛡️ Security Note

NetExec is loud and generates many failed login attempts if credentials are wrong; it will likely trigger an SOC alert.
Wireguard-Docs
📋 Overview

This is an unofficial but highly detailed documentation repository for WireGuard. It provides setup guides, configuration examples, and best practices for deploying WireGuard VPNs in various environments.
🎯 Tactical Applicability

    Primary Hacking Stage: Defensive Engineering / Secure Tunneling
    MITRE ATT&CK Phase: Command and Control (TA0011)
    Target Environment: Multi-platform VPN

⚙️ Product Information

    Developer/Owner: pirate
    GitHub Repository: https://github.com/pirate/wireguard-docs
    Popularity: 5,015 stars

🚀 Quick Start (Installation & Run)

# No installation; read the docs online
https://github.com/pirate/wireguard-docs

📖 Simple Usage Guide

    Refer to the "Quickstart" section to install WireGuard on your specific OS.
    Follow the "Site-to-Site" guide to connect two remote networks securely.
    Use the performance tuning tips to optimize your VPN throughput.

🛡️ Security Note

Documentation itself is safe; however, misconfiguring WireGuard (e.g., using weak keys) can compromise your privacy.
Hubble
📋 Overview

Hubble is a fully distributed networking and security observability platform for Kubernetes. Built on top of Cilium and eBPF, it provides deep visibility into how services communicate.
🎯 Tactical Applicability

    Primary Hacking Stage: Defensive Monitoring
    MITRE ATT&CK Phase: Network Effects (TA0040)
    Target Environment: Kubernetes

⚙️ Product Information

    Developer/Owner: cilium
    GitHub Repository: https://github.com/cilium/hubble
    Popularity: 4,164 stars

🚀 Quick Start (Installation & Run)

cilium hubble enable
hubble observe

📖 Simple Usage Guide

    Enable Hubble within an existing Cilium installation.
    Use the hubble observe command to see real-time flow data between pods.
    Utilize the Hubble UI to visualize the service map and identify blocked connections.

🛡️ Security Note

Hubble provides high-resolution data; ensure access to the Hubble API is restricted to authorized personnel.
IVRE
📋 Overview

IVRE is a powerful network reconnaissance framework that allows users to build their own "private Shodan." It integrates tools like Nmap, Masscan, and Zeek to collect and analyze network intelligence.
🎯 Tactical Applicability

    Primary Hacking Stage: Large-scale Recon / EASM
    MITRE ATT&CK Phase: Reconnaissance (TA0043)
    Target Environment: Internet-wide or Enterprise Networks

⚙️ Product Information

    Developer/Owner: ivre
    GitHub Repository: https://github.com/ivre/ivre
    Popularity: 4,004 stars

🚀 Quick Start (Installation & Run)

# Using Docker Compose for a quick setup
docker-compose up -d

📖 Simple Usage Guide

    Import your Nmap or Masscan results into the IVRE database.
    Use the web interface to search and filter discovered services across your infrastructure.
    Perform "Passive DNS" analysis to track changes in your network footprint over time.

🛡️ Security Note

Hosting a private Shodan-like database requires significant compute and storage resources; monitor your scanning activities to avoid ISP blacklisting.
