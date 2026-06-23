"""
Vulnerability Database
Contains known vulnerabilities for common services and versions
"""

VULNERABILITY_DB = {
    'ssh': {
        'OpenSSH 7.2': {
            'cve': 'CVE-2016-6210',
            'description': 'User enumeration vulnerability',
            'severity': 'MEDIUM',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6210'
        },
        'OpenSSH 7.4': {
            'cve': 'CVE-2017-15906',
            'description': 'Denial of service vulnerability',
            'severity': 'MEDIUM',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-15906'
        },
        'OpenSSH 8.5': {
            'cve': 'CVE-2021-41617',
            'description': 'Privilege escalation vulnerability',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41617'
        },
        'OpenSSH 9.0': {
            'cve': 'CVE-2022-3303',
            'description': 'Memory corruption vulnerability',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2022-3303'
        }
    },
    'apache': {
        'Apache 2.4.49': {
            'cve': 'CVE-2021-41773',
            'description': 'Path traversal vulnerability',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
        },
        'Apache 2.4.50': {
            'cve': 'CVE-2021-42013',
            'description': 'Path traversal and RCE vulnerability',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'
        }
    },
    'nginx': {
        'nginx 1.18.0': {
            'cve': 'CVE-2021-23017',
            'description': 'DNS resolver vulnerability',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
        },
        'nginx 1.20.0': {
            'cve': 'CVE-2021-23017',
            'description': 'DNS resolver vulnerability',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
        }
    },
    'mysql': {
        'MySQL 5.7.0': {
            'cve': 'CVE-2016-6662',
            'description': 'Remote code execution vulnerability',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6662'
        },
        'MySQL 8.0.0': {
            'cve': 'CVE-2021-2071',
            'description': 'Privilege escalation vulnerability',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-2071'
        }
    },
    'rdp': {
        'Microsoft RDP 2016': {
            'cve': 'CVE-2019-0708',
            'description': 'BlueKeep - Remote code execution',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'
        }
    }
}

def check_vulnerabilities(service_name, version):
    """
    Check if a service version has known vulnerabilities.
    
    Args:
        service_name (str): Service name (e.g., 'ssh', 'apache')
        version (str): Service version (e.g., 'OpenSSH 7.2')
    
    Returns:
        dict: Vulnerability information or None
    """
    service_name = service_name.lower()
    
    if service_name in VULNERABILITY_DB:
        for key, vuln in VULNERABILITY_DB[service_name].items():
            if key in version or key.lower() in version.lower():
                return {
                    'service': service_name,
                    'version': key,
                    'cve': vuln['cve'],
                    'description': vuln['description'],
                    'severity': vuln['severity'],
                    'link': vuln['link']
                }
    
    return None

def parse_banner_for_vulnerabilities(banner, port):
    """
    Parse a banner and check for vulnerabilities.
    
    Args:
        banner (str): Service banner
        port (int): Port number
    
    Returns:
        list: List of vulnerability findings
    """
    findings = []
    
    # Map ports to service names
    service_map = {
        22: 'ssh',
        80: 'apache',
        443: 'apache',
        8080: 'apache',
        8443: 'apache',
        3306: 'mysql',
        3389: 'rdp'
    }
    
    service_name = service_map.get(port)
    if not service_name:
        return findings
    
    # Check for known versions in banner
    for version_key in VULNERABILITY_DB.get(service_name, {}):
        if version_key.lower() in banner.lower():
            vuln = check_vulnerabilities(service_name, version_key)
            if vuln:
                findings.append(vuln)
    
    return findings

# Test the vulnerability database
if __name__ == "__main__":
    test_banners = [
        ("SSH-2.0-OpenSSH_7.2 Ubuntu-4ubuntu6", 22),
        ("Apache/2.4.49 (Ubuntu)", 80),
        ("MySQL 5.7.0", 3306)
    ]
    
    for banner, port in test_banners:
        print(f"\nTesting: {banner}")
        findings = parse_banner_for_vulnerabilities(banner, port)
        if findings:
            for finding in findings:
                print(f"  ⚠️  {finding['cve']}: {finding['description']} ({finding['severity']})")
        else:
            print("  ✅ No known vulnerabilities found")