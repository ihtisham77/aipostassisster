"""
Module Registry
Defines available security assessment modules with OS compatibility
"""

# Module registry with OS compatibility
MODULES = {
    "reconnaissance": {
        "name": "Reconnaissance",
        "description": "Gather system and network information",
        "os": ["Linux", "Windows"],
        "priority": 1
    },
    "credential_access": {
        "name": "Credential Access",
        "description": "Check for exposed credentials and insecure credential storage",
        "os": ["Linux", "Windows"],
        "priority": 2
    },
    "privilege_escalation": {
        "name": "Privilege Escalation",
        "description": "Check for privilege escalation vulnerabilities",
        "os": ["Linux", "Windows"],
        "priority": 3
    },
    "persistence": {
        "name": "Persistence",
        "description": "Check for persistence mechanisms",
        "os": ["Linux", "Windows"],
        "priority": 4
    },
    "lateral_movement": {
        "name": "Lateral Movement",
        "description": "Check for lateral movement opportunities",
        "os": ["Linux", "Windows"],
        "priority": 5
    },
    "active_directory": {
        "name": "Active Directory",
        "description": "Comprehensive AD security assessment: Kerberos attacks, delegation abuse, trust exploitation, certificate services",
        "os": ["Windows", "Linux"],
        "priority": 6
    },
    "exfiltration": {
        "name": "Exfiltration",
        "description": "Check for data exfiltration opportunities including accessible sensitive data, network channels, external storage, and cloud tools",
        "os": ["Linux", "Windows"],
        "priority": 7
    },
    "cleanup": {
        "name": "Cleanup",
        "description": "Check logging and forensic capabilities for anti-forensic opportunities",
        "os": ["Linux", "Windows"],
        "priority": 8
    }
}


def get_all_modules():
    """Get list of all module names"""
    return list(MODULES.keys())


def get_compatible_modules(os_type):
    """
    Get modules compatible with specified OS

    Args:
        os_type: OS type string (Linux, Windows, Darwin, etc.)

    Returns:
        List of compatible module names
    """
    compatible = []

    # Normalize OS type
    os_normalized = os_type.lower()

    for module_id, module_info in MODULES.items():
        # Check if module supports this OS
        for supported_os in module_info["os"]:
            if supported_os.lower() in os_normalized or os_normalized in supported_os.lower():
                compatible.append(module_id)
                break

    return compatible


def get_modules_by_priority(os_type=None):
    """
    Get modules sorted by priority

    Args:
        os_type: Optional OS type to filter by

    Returns:
        List of module names sorted by priority (high to low)
    """
    if os_type:
        compatible = get_compatible_modules(os_type)
        modules_to_sort = {k: v for k, v in MODULES.items() if k in compatible}
    else:
        modules_to_sort = MODULES

    sorted_modules = sorted(
        modules_to_sort.items(),
        key=lambda x: x[1]["priority"]
    )

    return [m[0] for m in sorted_modules]


def get_module_info(module_name):
    """
    Get information about a specific module

    Args:
        module_name: Name of the module

    Returns:
        Dict with module information or None if not found
    """
    return MODULES.get(module_name)


def is_module_compatible(module_name, os_type):
    """
    Check if a module is compatible with given OS

    Args:
        module_name: Name of the module
        os_type: OS type string

    Returns:
        Boolean indicating compatibility
    """
    module_info = get_module_info(module_name)
    if not module_info:
        return False

    os_normalized = os_type.lower()

    for supported_os in module_info["os"]:
        if supported_os.lower() in os_normalized or os_normalized in supported_os.lower():
            return True

    return False


def get_module_list_formatted(os_type=None):
    """
    Get formatted module list for display

    Args:
        os_type: Optional OS type to filter by

    Returns:
        List of tuples (module_id, name, description, os_list)
    """
    if os_type:
        module_ids = get_compatible_modules(os_type)
    else:
        module_ids = get_all_modules()

    formatted = []
    for module_id in module_ids:
        info = MODULES[module_id]
        formatted.append((
            module_id,
            info["name"],
            info["description"],
            ", ".join(info["os"])
        ))

    return formatted


if __name__ == "__main__":
    # Test the registry
    print("All modules:", get_all_modules())
    print("\nLinux modules:", get_compatible_modules("Linux"))
    print("\nWindows modules:", get_compatible_modules("Windows"))
    print("\nModules by priority (Linux):", get_modules_by_priority("Linux"))
