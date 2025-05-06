# DEFENDING CLOUD WEBSERVER AGAINST DDOS ATTACK: DETECTION, PROTECTION, AND MITIGATION
#### Executive Summary
This project presents a comprehensive defense system for cloud-hosted web servers against Distributed Denial of Service (DDoS) attacks. At its core is a lightweight ML-based detection module using Tsetlin Machine classifiers, combined with AWS cloud-native protection services and auto-scaling mitigation. The solution achieves 98.7% detection accuracy with minimal latency and provides interpretable rule-based explanations of threat detection.
#### 1.1 DDoS Attacks Overview
DDoS attacks aim to disrupt online services by overwhelming target servers with malicious traffic from multiple sources. These attacks can be categorized into three main types:

- Volumetric Attacks: Consume available bandwidth through amplification or flooding.
![image](https://github.com/user-attachments/assets/67c09136-5d22-48a4-b0c3-ae87dff47eb5)

- Application Layer Attacks: Target web page generation processes through expensive HTTP requests.
![image](https://github.com/user-attachments/assets/25d896eb-f4ea-463d-b453-ccdb7f886ada)

- Protocol Attacks: Exploit weaknesses in layer 3 and 4 of the protocol stack.
  ![image](https://github.com/user-attachments/assets/db48965b-6c72-47bf-a296-e8eb25020bde)


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
- Advanced anomaly detection techniques
