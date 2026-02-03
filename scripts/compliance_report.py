import csv
import os
from policy_parser import analyze_folder

#Map findings to compliance frameworks
COMPLIANCE_MAPPING = {
    "Wildcard Action": {
        "NIST": "AC-3 (Access Enforcement)",
        "CIS": "CIS 1.4 - Least Privilege",
        "HIPPA":" 164.308(a)(4)(i) - Information Access Management",
        "HITRUST": "01.b - Access Control Procedures"
   
    },
    "Wildcard Resource": {
         "NIST": "AC-6 (Least Privilege)",
         "CIS": "CIS 1.3 - Resource Access Control",
         "HIPAA": "164.312(a)(1) - Access Control",
         "HITRUST": "01.c - Least Privilege"
    
    },
    "Full Service Access": {
        "NIST": "AC-6 (Least Privilege)",
        "CIS": "CIS 1.4 - Privilege Restriction",
        "HIPAA": "164.308(a)(3)(ii)(B) - Workforce Access Authorization",
        "HITRUST": "01.d - Privileged Access Manageent"
    }
}

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    policies_folder = os.path.join(base_dir, "..", "sample_policies")
    reports_folder = os.path.join(base_dir, "..", "reports")
    output_file = os.path.join(reports_folder, "compliance_report.csv")

    print(f"Generating compliance report from: {policies_folder}")

    result = analyze_folder(policies_folder)

    with open(output_file, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "policy_file",
            "issue",
            "severity",
            "details",
            "nist_control",
            "cis_control",
            "hipaa_control",
            "hitrust_control"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()  

        for policy in result:
            if not policy["findings"]:
                writer.writerow({
                    "policy_file": policy["policy_file"],
                    "issue": "No findings",
                    "severity": "None",
                    "details": "Policy follows least privilege",
                    "nist_control": "N/A",
                    "cis_control": "N/A",
                    "hipaa_control": "N/A",
                    "hitrust_control": "N\A"
                })
            else:
                   for finding in policy["findings"]:
                        mapping = COMPLIANCE_MAPPING.get(finding["issue"], {})
                        writer.writerow({
                             "policy_file": policy["policy_file"],
                             "issue": finding["issue"],
                             "severity": finding["severity"],
                             "details": finding["details"],
                             "nist_control": mapping.get("NIST", "Unmapped"),
                             "cis_control": mapping.get("CIS", "Unmapped"),
                             "hipaa_control": mapping.get("HIPAA", "Unmapped"),
                             "hitrust_control": mapping.get("HITRUST", "Unmapped")

                        })

print(f"Compliance report generated: {output_file}")
                   