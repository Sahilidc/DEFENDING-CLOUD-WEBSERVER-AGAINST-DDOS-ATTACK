# DEFENDING CLOUD WEBSERVER AGAINST DDOS ATTACK: DETECTION, PROTECTION, AND MITIGATION
#### Executive Summary
This project presents a comprehensive defense system for cloud-hosted web servers against Distributed Denial of Service (DDoS) attacks. At its core is a lightweight ML-based detection module using Tsetlin Machine classifiers, combined with AWS cloud-native protection services and auto-scaling mitigation. The solution achieves 98.7% detection accuracy with minimal latency and provides interpretable rule-based explanations of threat detection.

#### 1.1 DDoS Attacks Overview
DDoS attacks aim to disrupt online services by overwhelming target servers with malicious traffic from multiple sources. These attacks can be categorized into three main types:
- Bandwidth Depletion DDoS
![image](https://github.com/user-attachments/assets/4ddca5c9-7995-4aa3-ada2-3ef48a372126)

- Resource Depletion DDoS
![image](https://github.com/user-attachments/assets/3633bf44-9326-45c8-8334-77d84a314eb6)
These attacks can cause significant financial losses and reputational damage by disrupting the link between organizations and customers.

#### 2.1 Objectives

- Achieve ≥95% accuracy in DDoS attack detection
- Reduce false positive rate to <5%
- Maintain <1% downtime during attacks
- Enable auto-scaling responses within 5 minutes
- Ensure efficient resource usage (<20% CPU/memory)
- Provide interpretable detection decisions

#### 2.2 System Architecture
![image](https://github.com/user-attachments/assets/660399b3-e15f-449e-8575-450de9e47adc)

The system implements a multi-layered defense:

- ML-based Detection Module: Analyzes incoming traffic to identify potential DDoS threats
- DDoS ML-based Segregation Module: Classifies specific attack types
- Defense Mechanism: Applies rules like geo-blocking and rate-limiting
- Honeypot: Traps severe attack traffic for analysis
- Mitigation Strategy: Employs AWS services for traffic management

#### 2.3 Data Flow
![image](https://github.com/user-attachments/assets/8d197e82-3c09-470a-920b-5692ad56927b)

The data flow begins with incoming requests, proceeds through packet capture, feature extraction, and classification, with appropriate actions taken based on traffic legitimacy.

#### 3. Implementation Details

##### 3.1 Packet Capture and Buffering

- Tools: Wireshark with tshark , NFstream for real-time packet capture
- Buffering: Using iptables with NFQUEUE (1000 packets or 5-second timeout)
- Processing: Conversion to JSON format with 5-tuple extraction

##### 3.2 Flow Grouping and Feature Extraction

- Tool: NFStream for real-time flow distribution
- Features: Flow_IAT_Mean, Fwd_Packets_per_s, Init_Fwd_Win_Bytes
- Preprocessing: Normalization and booleanization for Tsetlin Machine compatibility

##### 3.3 ML-based Detection with Tsetlin Machine

- Backend: FastAPI application for real-time inference
- Efficiency: Lazy loading to reduce memory overhead
- Performance: Batch processing with asyncio and ThreadPoolExecutor
![image](https://github.com/user-attachments/assets/8742dac6-a2d3-4ac0-be0d-a99784fd7d48)

- Deployment: AWS EC2 instance within a VPC

##### 3.4 Defense Mechanism (AWS-based Rules)

- AWS WAF Configuration: Five key rules implemented
![image](https://github.com/user-attachments/assets/1fdf905a-3c3a-4d5a-bf22-df2a4f9744ff)
![image](https://github.com/user-attachments/assets/8939e269-5649-49ab-b2bd-b42b100393fc)
![Screenshot (65)](https://github.com/user-attachments/assets/db9f8170-b649-49b2-b60f-73be0a276833)
![Screenshot (66)](https://github.com/user-attachments/assets/71fc0785-85c1-48e7-86f7-fb3b6a2c7dac)
![Screenshot (67)](https://github.com/user-attachments/assets/d518173a-09ab-4353-89eb-4e0192ccaff3)
![Screenshot (68)](https://github.com/user-attachments/assets/216bcfb6-fd01-4f79-bb8f-5696c4ef8db7)
![Screenshot (69)](https://github.com/user-attachments/assets/4a5bebf3-792c-492a-82d3-08fd8cd3b141)

- Lambda Function: For automated IP blocking and traffic management
![image](https://github.com/user-attachments/assets/b13ac7cf-85fc-4718-9426-ff5a6d764c1a)

![image](https://github.com/user-attachments/assets/2f62eae3-e638-4c81-b257-2718dff677e9)

##### 3.5 Mitigation Strategies

- DNS Rerouting: Using Route 53 for traffic redirection
- Load Balancing: ALB and NLB for traffic distribution
- Logging: CloudWatch for comprehensive activity monitoring
- EC2 Setup: Instances configured for various system components

#### 4 AWS Configuration Results

- WAF Effectiveness: Successful filtering of malicious traffic
- Lambda Integration: Automated blocking of flagged IPs
- Load Balancing: Even traffic distribution during attack scenarios
- Routing: Successful traffic rerouting during attacks

##### 4.5 System Scalability and Stability

- Scalability: Demonstrated potential for horizontal scaling
- Stability: Robust error handling with no crashes during operation

#### 5. Conclusion and Future Work

##### 5.1 Achievements
- Developed a comprehensive, modular DDoS defense system
- Implemented real-time detection using a Tsetlin Machine
- Integrated AWS-based protection and mitigation strategies
- Achieved high accuracy with interpretable results

##### 5.2 Future Enhancements
- Auto-scaling implementation for dynamic traffic handling
- Zero trust policies for stricter access control
- Real-time alert analysis for faster response
- Integration with Kubernetes for improved scalability
- Model updates with newer datasets
- Advanced anomaly detection techniques using segregation 

#### 6. [Flow Tracking script](http://https://github.com/Sahilidc/DEFENDING-CLOUD-WEBSERVER-AGAINST-DDOS-ATTACK/blob/main/Flow%20Tracking%20Script%20with%20NFStream.py "Flow Tracking script")

#####  This script is a network flow tracking tool that uses NFStream to extract and record detailed information about network traffic in real-time. Here's an explanation of what it does:

The script monitors network traffic on a specified interface (in this case, "enp0s3") and captures flow information - a flow is a series of related packets between two endpoints.
For each network flow, it:

Generates a unique Flow ID using the 5-tuple (source IP, destination IP, source port, destination port, protocol)
Extracts various statistical features about the flow, such as:

- Packet timing information (intervals between packets)
- Packet size statistics
- TCP flag counts (ACK, RST, URG, etc.)
- Flow duration metrics
- Packet rates and counts


The extracted features are compiled into JSON format and:
Written to a timestamped output file in the "flow_data" directory
Logged for monitoring purposes
Printed to the console for real-time visibility


This tool is useful for:
- Network traffic analysis
- Security monitoring (identifying unusual patterns)
- Performance tracking
- Creating datasets for machine learning models that analyze network behavior

###### The script focuses on extracting statistical features that are commonly used in network traffic classification and anomaly detection, particularly useful for identifying various types of network behavior including potential attacks.

#### 7. [Attack Script](http://https://github.com/Sahilidc/DEFENDING-CLOUD-WEBSERVER-AGAINST-DDOS-ATTACK/blob/main/hulk2.py "Attack Script") 
**This is a Python implementation of HULK (HTTP Unbearable Load King), which is a DoS (Denial of Service) attack tool. Here's what it does:**

- The script creates multiple threads (500 by default) that simultaneously send HTTP requests to a target website.
- Each request:
- Uses a randomly selected User-Agent to appear as different browsers
- Adds random parameters to URLs to bypass caching
- Includes various HTTP headers to make requests look legitimate

#### 8. [Lambda Redirection Script](https://github.com/Sahilidc/DEFENDING-CLOUD-WEBSERVER-AGAINST-DDOS-ATTACK/blob/main/lambda_function.py "Lambda Redirection Script")
**This AWS Lambda function automates real-time detection and mitigation of DDoS attacks based on traffic predictions from a JSON data source hosted on an EC2 instance. Here's a detailed breakdown of what the script does:**
- Automates real-time DDoS detection and response using AWS services.
- Input: Fetches JSON traffic flow data from a public EC2-hosted URL.
- Prediction Handling:
  - If Prediction == "DDOS": Extracts the source_ip. Adds the IP to an AWS WAF IP Set (blocks it). Logs the IP and TTL in a DynamoDB table (BlockedIPs) for time-based 
  unblocking.
  - ![image](https://github.com/user-attachments/assets/500f8736-cace-4562-9117-9413fe1a613b)
  - If Prediction == "BENIGN": Redirects traffic to a specific EC2 instance by updating the ALB listener to point to the target group.
- AWS Services Used:
  AWS Lambda: Executes the automation logic.
  Amazon WAFv2: Blocks IPs dynamically using IP sets.
  Amazon DynamoDB: Stores blocked IPs with TTL for automatic expiration.
  Elastic Load Balancer (ALB): Forwards/redirects traffic to EC2 instances.
- Error Handling: Logs all exceptions and handles empty or invalid JSON gracefully.
- Customizable Parameters: WAF ACL name/ID, IP set name/ID, ALB ARN, target group ARN, EC2 JSON URL, and block duration.
- Logging: Uses Python’s logging module to log key actions and issues.

*The goal is to exhaust the target server's resources by overwhelming it with a large number of connections, potentially making the website unavailable to legitimate users.
The script includes a monitoring thread that reports how many requests have been sent during the attack.
There's an optional "safe" mode that automatically stops the attack if the target server starts returning 500 error codes (indicating server errors).*

###### Important note: This script is labeled for research purposes only. Using such tools against websites without explicit permission is illegal in most jurisdictions and could result in serious legal consequences. DoS attacks disrupt services and can cause significant financial and operational damage to organizations.Important note: This script is labeled for research purposes only. Using such tools against websites without explicit permission is illegal in most jurisdictions and could result in serious legal consequences. DoS attacks disrupt services and can cause significant financial and operational damage to organizations.

