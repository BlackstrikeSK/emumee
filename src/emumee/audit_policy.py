"""Guest audit-policy names and GUIDs from the Windows SDK NTSecAPI.h.

English labels describe the modeled system policy; host policy is never queried.
"""

import csv
import io


CATEGORIES = ("System", "Logon/Logoff", "Object Access", "Privilege Use",
              "Detailed Tracking", "Policy Change", "Account Management",
              "DS Access", "Account Logon")

# Subcategory GUID Data1 values are contiguous in the Windows 11 SDK.
# Each entry is (category index, English auditpol name), beginning at 0x0cce9210.
_SUBCATEGORIES = (
    (0, "Security State Change"), (0, "Security System Extension"),
    (0, "System Integrity"), (0, "IPsec Driver"), (0, "Other System Events"),
    (1, "Logon"), (1, "Logoff"), (1, "Account Lockout"), (1, "IPsec Main Mode"),
    (1, "IPsec Quick Mode"), (1, "IPsec Extended Mode"), (1, "Special Logon"),
    (1, "Other Logon/Logoff Events"),
    (2, "File System"), (2, "Registry"), (2, "Kernel Object"), (2, "SAM"),
    (2, "Certification Services"), (2, "Application Generated"),
    (2, "Handle Manipulation"), (2, "File Share"),
    (2, "Filtering Platform Packet Drop"), (2, "Filtering Platform Connection"),
    (2, "Other Object Access Events"),
    (3, "Sensitive Privilege Use"), (3, "Non Sensitive Privilege Use"),
    (3, "Other Privilege Use Events"),
    (4, "Process Creation"), (4, "Process Termination"), (4, "DPAPI Activity"),
    (4, "RPC Events"),
    (5, "Audit Policy Change"), (5, "Authentication Policy Change"),
    (5, "Authorization Policy Change"), (5, "MPSSVC Rule-Level Policy Change"),
    (5, "Filtering Platform Policy Change"), (5, "Other Policy Change Events"),
    (6, "User Account Management"), (6, "Computer Account Management"),
    (6, "Security Group Management"), (6, "Distribution Group Management"),
    (6, "Application Group Management"), (6, "Other Account Management Events"),
    (7, "Directory Service Access"), (7, "Directory Service Changes"),
    (7, "Directory Service Replication"), (7, "Detailed Directory Service Replication"),
    (8, "Credential Validation"), (8, "Kerberos Service Ticket Operations"),
    (8, "Other Account Logon Events"), (8, "Kerberos Authentication Service"),
    (1, "Network Policy Server"), (2, "Detailed File Share"),
    (2, "Removable Storage"), (2, "Central Policy Staging"), (1, "User / Device Claims"),
    (4, "Plug and Play Events"), (1, "Group Membership"), (4, "Token Right Adjusted Events"),
)
SUBCATEGORIES = tuple((CATEGORIES[category], name,
                      f"{{{0x0cce9210 + i:08x}-69ae-11d9-bed3-505054503030}}")
                     for i, (category, name) in enumerate(_SUBCATEGORIES))
SETTINGS = ("No Auditing", "Success", "Failure", "Success and Failure")


def validate_policy(policy):
    """Keep policy overrides bounded to known names and explicit settings."""
    if (not isinstance(policy, dict) or set(policy) != {"read_allowed", "subcategories"} or
            not isinstance(policy["read_allowed"], bool) or
            not isinstance(policy["subcategories"], dict)):
        raise ValueError("Persona audit_policy fields are invalid")
    known = {name for _, name, _ in SUBCATEGORIES}
    for name, setting in policy["subcategories"].items():
        if name not in known or not isinstance(setting, str) or setting not in SETTINGS:
            raise ValueError("Persona audit_policy subcategory or setting is invalid")


def policy_text(persona, arguments):
    """Render supported auditpol views from a single guest policy snapshot."""
    argument = arguments.casefold()
    if not argument:
        return "Usage: auditpol /get /category:* [/r] | /list /category | /list /subcategory:* [/v]\r\n"
    if argument == "/list /category":
        return "Category\r\n" + "\r\n".join(CATEGORIES) + "\r\n"
    if argument in ("/list /subcategory:*", "/list /subcategory:* /v"):
        rows = ["Category/Subcategory" + ("\tGUID" if argument.endswith(" /v") else "")]
        for category in CATEGORIES:
            rows.append(category)
            for group, name, guid in SUBCATEGORIES:
                if group == category:
                    rows.append("  " + name + ("\t" + guid if argument.endswith(" /v") else ""))
        return "\r\n".join(rows) + "\r\n"
    if argument not in ("/get /category:*", "/get /category:* /r"):
        raise ValueError("unsupported auditpol arguments")
    if not (persona["user_is_admin"] or persona["audit_policy"]["read_allowed"]):
        return "Error 0x00000005 occurred:\r\nAccess is denied.\r\n"
    settings = persona["audit_policy"]["subcategories"]
    if argument.endswith(" /r"):
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\r\n")
        writer.writerow(("Machine Name", "Policy Target", "Subcategory", "Subcategory GUID",
                         "Inclusion Setting", "Exclusion Setting"))
        for category in CATEGORIES:
            for group, name, guid in SUBCATEGORIES:
                if group == category:
                    writer.writerow((persona["hostname"], "System", name, guid,
                                     settings.get(name, "No Auditing"), ""))
        return output.getvalue()
    rows = ["System audit policy", "Category/Subcategory                      Setting"]
    for category in CATEGORIES:
        rows.append(category)
        for group, name, _ in SUBCATEGORIES:
            if group == category:
                rows.append(f"  {name:<42} {settings.get(name, 'No Auditing')}")
    return "\r\n".join(rows) + "\r\n"
