Authorization & Responsible Testing Statement

Project: PentraAI — AI-Driven Autonomous Web Penetration Testing Agent (v1.1.0)

Team members:

Muhammad saad Abdullah
Pooja Sri Kuppuswamy Niranjana
Prabanjan Velayutham

Institution: EPITA 
Specialization: Computer Security 
Supervisor: Mohammad-salman Nadeem
Date: 06/07/26

Declaration
We, the undersigned team members, confirm that all security testing carried out during the development, evaluation, and benchmarking of PentraAI was performedonly against systems that we own or that we were explicitly authorized to test.
Specifically, we confirm the following:
Authorized targets only. All scans, exploit attempts, and vulnerability verification were conducted exclusively against intentionally vulnerable applications deployed locally on our own machines for research and educational purposes. No testing was directed at any third-party, production, or internet-facing system that we did not own or have written permission to test.
Test environment. The benchmark and demonstration targets used were:

Target	                                   Purpose	                               Deployment	                  Access
OWASP Juice Shop	                Modern IDOR / JWT / logic benchmark	   Local Docker (localhost:3001)	Self-hosted, private
crAPI (Completely Ridiculous API)	BOLA / JWT / SSRF verification	       Local deployment	                Self-hosted, private
 
Each of these applications is published by its maintainers specifically for security training and was run in an isolated local environment, never exposed to the public internet.
No unauthorized access. At no point did any team member attempt to access, scan, or exploit any system belonging to another individual or organisation without authorization. No real user data was accessed, collected, or exfiltrated.
Responsible handling. Any credentials, tokens, or findings generated during testing relate solely to the disposable local test instances above and carry no real-world sensitivity. Secrets used for local configuration are kept out of version control.
Intended use. PentraAI is intended as a defensive, educational security research tool for use by authorized testers against systems they are permitted to assess. We acknowledge that using this tool against systems without explicit authorization would be unlawful and unethical, and the project must not be used for that purpose.
Signatures
Each team member confirms the declaration above by signing below.
 
#	Name	                                    Signature	                                 Date
1	Muhammad saad Abdullah                    M Saad Abdullah                              06/07/26
2	Pooja Sri Kuppuswamy Niranjana            Pooja Sri K N                                06/07/26
3   Prabanjan Velayutham                      V prabanjan                                  06/07/26