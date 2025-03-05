# Identifying Vulnerabilities and Remediation Techniques

## 📌 Overview  
This project demonstrates how to identify and remediate security vulnerabilities in a web application hosted on Google Cloud Platform (GCP). The lab focuses on detecting and fixing a Cross-Site Scripting (XSS) vulnerability using **Google Cloud Web Security Scanner** and implementing security best practices.  

---

## 🛠️ Steps Performed  

### **1. Launching a Virtual Machine**  
- Created a **static IP address** using `gcloud compute addresses create`.  
- Launched a **VM instance** with `gcloud compute instances create`.  
- Installed **Flask**, a Python web framework, to run the vulnerable web application.  

### **2. Setting Up and Running the Vulnerable Application**  
- Created a **firewall rule** to allow access on port `8080` for vulnerability scanning.  
- Established an **SSH connection** to the VM.  
- Downloaded and extracted the vulnerable web application.  
- Started the Flask application (`python3 app.py`).  

### **3. Testing for Cross-Site Scripting (XSS) Vulnerability**  
- Accessed the application via the browser using `<STATIC_IP>:8080`.  
- Injected **malicious JavaScript** into the web form:  
  ```html
  <script>alert('This is an XSS Injection to demonstrate one of OWASP vulnerabilities')</script>
Observed the alert pop-up, confirming an XSS vulnerability.

4. Scanning for Vulnerabilities
Enabled Google Web Security Scanner API.
Configured a new security scan targeting the application.
Detected the XSS vulnerability via automated scanning.

5. Remediating the XSS Vulnerability
Edited the app.py file to sanitize user input by escaping HTML characters:
python

output_string = "".join([html_escape_table.get(c, c) for c in input_string])
Restarted the web application with the security fix.

6. Re-scanning to Verify Fixes
Re-ran the Web Security Scanner to check for vulnerabilities.
Verified that the XSS vulnerability was successfully remediated.

🔍 Key Findings & Fixes
Vulnerability	Description	Remediation
Cross-Site Scripting (XSS)	Web app accepts unescaped user input.	Implement input validation & HTML escaping.

Open Firewall Rule	Allowed access from all IPs.	Restrict firewall rules to trusted IPs.

🚀 Lessons Learned
✅ Proactive vulnerability scanning helps identify security risks before exploitation.
✅ Web applications must sanitize user input to prevent XSS and other injection attacks.
✅ Cloud security tools like Web Security Scanner automate the detection of web vulnerabilities.
✅ Firewall rules should be restrictive to limit exposure.

