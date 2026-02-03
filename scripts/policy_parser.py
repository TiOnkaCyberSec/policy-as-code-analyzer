import json
import os

def load_policy(file_path):
    """"
    Load an IAM policy JSON file
    """
    with open(file_path, 'r') as f:
        return json.load(f)
    
def analyze_permissions(policy):
    """
    Analyze IAM policy statements for risky permissions
    """
    findings = []

    statements = policy.get("Statement", [])
    if isinstance(statements,dict):
        statements = [statements]
        
    for statement in statements:
        effect = statement.get("Effect", "Unknown")
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])

        if isinstance(actions,str):
            actions = [actions]
        if isinstance(resources,str):
            resources = [resources]

        if '*' in actions:
            findings.append({
                "issue": "Wildcard Action",
                "severity": "High",
                "details": f"Effect={effect}, Actions={actions}, Resources={resources}"
                })

        if '*' in resources:
            findings.append({
                 "issue": "Wildcard Resource",
                 "severity": "High",
                 "details": f"Effect={effect}, Actions={actions}, Resources={resources}"
                })

    for action in actions:
         if action.endswith(":*") and action != '*':
             findings.append({
                "issue": "Full Service Access",
                "severity": "Medium",
                "details": f"Effect={effect}, Action={action}, Resources={resources}"
                })

    return findings


def analyze_folder(folder_path):
    """
    Analyze all JSON policy files in a folder 
    """

    report = []

    print(f"DEBUG: Scanning folder: {folder_path}")

    for filename in os.listdir(folder_path):
        print(f"DEBUG: Found file: {filename}")
        if filename.endswith(".json"):
            full_path = os.path.join(folder_path, filename)
            policy = load_policy(full_path)
            print(f"DEBUG: Loaded policy: {policy} ")
            findings = analyze_permissions(policy)

            report.append({
                "policy_file":filename,
                "findings": findings

                })

    return report
        
if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    policies_folder = os.path.join(base_dir, "..", "sample_policies")

    print(f"DEBUG: Looking for policies in {policies_folder}")
    results = analyze_folder(policies_folder)
   
    for result in results:
        print(f"\nPolicy: {result['policy_file']}")
    if result["findings"]:
            for finding in result["findings"]:
             print(f" - {finding['issue']}({finding['severity']}): {finding['details']}")
    else:
            print(" - No issues found")