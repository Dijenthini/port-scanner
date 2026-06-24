VULNERABILITY_DB = {
    'ssh': {
        'OpenSSH_6.6.1p1': {
            'cve': 'CVE-2015-5600',
            'description': 'MaxAuthTries bypass / brute-force amplification',
            'severity': 'MEDIUM',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2015-5600'
        },
        'OpenSSH 7.2': {
            'cve': 'CVE-2016-6210',
            'description': 'Username enumeration via timing side-channel',
            'severity': 'MEDIUM',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6210'
        },
        'OpenSSH 7.4': {
            'cve': 'CVE-2017-15906',
            'description': 'Denial of service via crafted packets in read-only mode',
            'severity': 'MEDIUM',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2017-15906'
        },
        'OpenSSH 8.5': {
            'cve': 'CVE-2021-41617',
            'description': 'Privilege escalation when AuthorizedKeysCommand is set',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41617'
        },
        
        'OpenSSH_9.3': {
            'cve': 'CVE-2023-38408',
            'description': 'Remote code execution via ssh-agent forwarding',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2023-38408'
        }
    },
    'apache': {
        'Apache/2.4.49': {
            'cve': 'CVE-2021-41773',
            'description': 'Path traversal and remote code execution',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773'
        },
        'Apache/2.4.50': {
            'cve': 'CVE-2021-42013',
            'description': 'Path traversal bypass and RCE (incomplete fix for 41773)',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'
        }
    },
    'nginx': {
        
        'nginx/1.18': {
            'cve': 'CVE-2021-23017',
            'description': 'Off-by-one heap write in DNS resolver (1-byte overwrite)',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
        },
        'nginx/1.20.0': {
            'cve': 'CVE-2021-23017',
            'description': 'Off-by-one heap write in DNS resolver (1-byte overwrite)',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017'
        }
    },
    'mysql': {
        '5.7.': {
            'cve': 'CVE-2016-6662',
            'description': 'Remote code execution via malicious my.cnf injection',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2016-6662'
        },
        '8.0.': {
            'cve': 'CVE-2020-14812',
            'description': 'Privilege escalation via Server: Locking component',
            'severity': 'HIGH',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2020-14812'
        }
    },
    'rdp': {
        
        'Microsoft Terminal': {
            'cve': 'CVE-2019-0708',
            'description': 'BlueKeep: unauthenticated remote code execution via RDP',
            'severity': 'CRITICAL',
            'link': 'https://nvd.nist.gov/vuln/detail/CVE-2019-0708'
        }
    }
}


PORT_TO_SERVICE = {
    22:   'ssh',
    80:   'apache',
    443:  'apache',
    8080: 'apache',
    8443: 'nginx',
    3306: 'mysql',
    3389: 'rdp'
}


def check_vulnerabilities(service_name, banner):

    service_db = VULNERABILITY_DB.get(service_name.lower(), {})
    for version_key, vuln in service_db.items():
        if version_key.lower() in banner.lower():
            return {
                'service':     service_name,
                'matched_key': version_key,
                'cve':         vuln['cve'],
                'description': vuln['description'],
                'severity':    vuln['severity'],
                'link':        vuln['link']
            }
    return None


def parse_banner_for_vulnerabilities(banner, port):

    findings = []

    service_name = PORT_TO_SERVICE.get(port)
    if not service_name:
        return findings

    vuln = check_vulnerabilities(service_name, banner)
    if vuln:
        findings.append(vuln)

    return findings



if __name__ == "__main__":
    test_cases = [
        ("SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13", 22),
        ("SSH-2.0-OpenSSH_9.3p1 Debian-1",             22),
        ("Apache/2.4.49 (Ubuntu)",                      80),
        ("Apache/2.4.50 (Debian)",                      443),
        ("nginx/1.18.0 (Ubuntu)",                       80),
        ("5.7.33-0ubuntu0.18.04.1",                     3306),
        ("Microsoft Terminal Services",                  3389),
        ("Apache/2.4.62 (Latest)",                       80),   
    ]

    print("Vulnerability Scanner — Banner Test\n" + "=" * 50)
    for banner, port in test_cases:
        findings = parse_banner_for_vulnerabilities(banner, port)
        status = f"⚠️  {findings[0]['cve']} [{findings[0]['severity']}]" if findings else "✅ No known CVE"
        print(f"Port {port:5d} | {status}")
        print(f"         Banner: {banner}")
        print()