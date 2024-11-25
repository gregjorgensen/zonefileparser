from flask import Flask, request, jsonify, render_template
import dns.resolver
import re
import whois
import socket
import ssl
import requests
from datetime import datetime
import spf  # For SPF parsing
import dkim  # For DKIM parsing

app = Flask(__name__)

# Custom DNS resolver instances
resolver_cloudflare = dns.resolver.Resolver()
resolver_google = dns.resolver.Resolver()
resolver_cloudflare.nameservers = ['1.1.1.1']  # Cloudflare DNS
resolver_google.nameservers = ['8.8.8.8']  # Google DNS

# Function to provide explanations for DNS records
def get_record_explanation(record_type, records, discrepancies=None):
    explanations = []
    highlighted_info = []
    if record_type == "A":
        explanations.append("An A record maps a domain to an IPv4 address, directing traffic to the correct server.")
    elif record_type == "AAAA":
        explanations.append("An AAAA record maps a domain to an IPv6 address, which is the newer version of IP addressing.")
    elif record_type == "MX":
        explanations.append("An MX record specifies the mail server responsible for receiving emails for the domain.")
    elif record_type == "NS":
        explanations.append("NS records specify the authoritative servers for the domain, used to resolve domain names to IP addresses.")
    elif record_type == "TXT":
        for record in records:
            # Break down each TXT record and provide detailed explanations
            record_explanation = ""
            # DMARC Detection
            if re.search(r'v=DMARC1', record, re.IGNORECASE):
                record_explanation += f"DMARC Record: \"{record}\". DMARC helps prevent email spoofing.\n"
                # Parse DMARC record
                parsed_dmarc = parse_dmarc_record(record)
                if parsed_dmarc:
                    policy = parsed_dmarc.get('p', '').upper()
                    highlighted_info.append(f"DMARC Policy: {policy}")
                    record_explanation += f"DMARC Policy is set to {policy}, which defines how receiving mail servers should handle emails that fail authentication.\n"
                else:
                    record_explanation += "Unable to parse DMARC record.\n"
            # SPF Detection
            elif re.search(r'v=spf1', record, re.IGNORECASE):
                record_explanation += f"SPF Record: \"{record}\". SPF specifies authorized mail servers.\n"
                highlighted_info.append("SPF Record Found")
                # Analyze SPF record for included domains
                includes = re.findall(r'include:([^\s]+)', record)
                if includes:
                    record_explanation += "Includes the following domains in SPF:\n"
                    for include_domain in includes:
                        record_explanation += f"- {include_domain}\n"
                        # Example inference: Check if the included domain is a known provider
                        known_providers = {
                            "mailchimp.com": "Mailchimp",
                            "sendgrid.net": "SendGrid",
                            "spf.protection.outlook.com": "Microsoft Office 365",
                            "servers.mcsv.net": "Mailchimp",
                            "spf.mandrillapp.com": "Mandrill",
                            "servers.outbound.mailhop.org": "Dyn Email",
                            "smtp.sendgrid.net": "SendGrid",
                            "spf.constantcontact.com": "Constant Contact",
                            "spf.em.secureserver.net": "GoDaddy Email",
                            # ... add more as needed
                        }
                        for keyword, provider_name in known_providers.items():
                            if keyword in include_domain.lower():
                                record_explanation += f"This suggests the use of {provider_name} for sending emails.\n"
                else:
                    record_explanation += "No included domains found in SPF record.\n"
            # DKIM Detection
            elif re.search(r'v=DKIM1', record, re.IGNORECASE):
                record_explanation += f"DKIM Record: \"{record}\". DKIM verifies the authenticity of your emails.\n"
                highlighted_info.append("DKIM Record Found")
                # Parse DKIM record
                try:
                    parsed_dkim = dkim.parse_tag_value(record.encode())
                    if 'p' in parsed_dkim:
                        record_explanation += "DKIM public key found.\n"
                    else:
                        record_explanation += "DKIM record is missing the public key ('p' tag).\n"
                except Exception as e:
                    record_explanation += f"Error parsing DKIM record: {str(e)}\n"
            # Other TXT Records
            else:
                record_explanation += f"General TXT Record: \"{record}\".\n"
            explanations.append(record_explanation.strip())
    return "\n".join(explanations), highlighted_info

# Function to parse DMARC record using regex
def parse_dmarc_record(record):
    record = record.strip()
    if not record.startswith('v=DMARC1'):
        return None
    tags = {}
    tag_pairs = record.split(';')
    for pair in tag_pairs:
        if '=' in pair:
            key, value = pair.strip().split('=', 1)
            tags[key.strip()] = value.strip()
    return tags

# Function to detect email security tools based on MX records
def detect_email_security_tools(mx_records):
    known_providers = {
        "mimecast": "Mimecast",
        "proofpoint": "Proofpoint",
        "barracuda": "Barracuda Networks",
        "messagelabs": "Symantec Email Security.cloud",
        "pphosted": "Proofpoint",
        "google": "Google Workspace",
        "googlemail": "Google Workspace",
        "outlook": "Microsoft Office 365",
        "office365": "Microsoft Office 365",
        "emailsrvr": "Rackspace Email",
        "zoho": "Zoho Mail",
        "mailgun": "Mailgun",
        "sendgrid": "SendGrid",
        "sparkpost": "SparkPost",
        "mailprotector": "Mailprotector",
        "fusemail": "FuseMail",
        "spamexperts": "SpamExperts",
        "sophos": "Sophos Email",
        "fortinet": "Fortinet FortiMail",
        "cisco": "Cisco Email Security",
        "trendmicro": "Trend Micro Email Security",
        "titanhq": "TitanHQ",
        "forcepoint": "Forcepoint Email Security",
        "libraesva": "Libraesva",
        "protonmail": "ProtonMail",
        "fastmail": "FastMail",
        "naver": "Naver Mail",
        "secureserver": "GoDaddy Email",
        "yahoodns": "Yahoo Mail",
        "messagingengine": "FastMail",
        "qq.com": "Tencent QQ Mail",
        "opentext": "OpenText (formerly Carbonite/Webroot)",
        "barracudanetworks": "Barracuda Networks",
        "mcafeesaas": "McAfee SaaS",
        "messagelabs": "Symantec.cloud",
        # ... add more providers as needed
    }
    detected_tools = []
    unknown_providers = []
    for record in mx_records:
        mx_host = record.split()[-1].rstrip('.')
        provider_found = False
        for keyword, provider_name in known_providers.items():
            if keyword in mx_host.lower():
                detected_tools.append(provider_name)
                provider_found = True
                break
        if not provider_found:
            unknown_providers.append(mx_host)
    return list(set(detected_tools)), unknown_providers  # Return both known and unknown providers

# Function to detect DMARC service providers
def detect_dmarc_providers(txt_records):
    # Known DMARC service providers
    service_providers = {
        "dmarcian": "dmarcian",
        "easydmarc": "EasyDMARC",
        "agari": "Agari",
        "valimail": "Valimail",
        "oneneutral": "OneNeutral",
        "trustifi": "Trustifi",
        "proofpoint": "Proofpoint",
        "mimecast": "Mimecast",
        "mailchimp": "Mailchimp",
        "sparkpost": "SparkPost",
        "postmarkapp": "Postmark",
        "onetrust": "OneTrust",
        "trustarc": "TrustArc",
        "redsift": "OnDMARC (Red Sift)",
        "digicert": "DigiCert",
        "elasticemail": "Elastic Email",
        # ... add more known DMARC service providers as needed
    }
    detected_providers = []
    for record in txt_records:
        if re.search(r'v=DMARC1', record, re.IGNORECASE):
            # Extract rua and ruf email addresses
            rua_ruf_matches = re.findall(r'(rua|ruf)=([^;]+)', record)
            for tag, addresses in rua_ruf_matches:
                emails = addresses.split(',')
                for email in emails:
                    domain_match = re.search(r'@([^,>]+)', email)
                    if domain_match:
                        domain_in_email = domain_match.group(1)
                        for keyword, provider_name in service_providers.items():
                            if keyword in domain_in_email.lower():
                                detected_providers.append(provider_name)
                                break  # Stop after finding a matching provider
    return list(set(detected_providers))

# Function to get domain expiration date and registrar information
def get_domain_info(domain):
    try:
        domain_info = whois.whois(domain)
        expiration_date = domain_info.expiration_date
        registrar = domain_info.registrar
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        return expiration_date, registrar
    except Exception as e:
        return None, None

# Function to check website accessibility and SSL certificate validation
def check_website_accessibility(domain):
    try:
        response = requests.get(f"https://{domain}", timeout=5)
        status_code = response.status_code
        ssl_valid = True  # If no SSL error is raised, the certificate is valid
        return {
            "accessible": True,
            "status_code": status_code,
            "ssl_valid": ssl_valid
        }
    except requests.exceptions.SSLError as e:
        return {
            "accessible": False,
            "error": f"SSL Error: {str(e)}",
            "ssl_valid": False
        }
    except requests.exceptions.ConnectionError as e:
        return {
            "accessible": False,
            "error": f"Connection Error: {str(e)}",
            "ssl_valid": False
        }
    except Exception as e:
        return {
            "accessible": False,
            "error": f"Error: {str(e)}",
            "ssl_valid": False
        }

# Helper function to perform DNS lookups
def perform_dns_lookup(domain, record_type):
    try:
        results_cf = []
        results_gg = []
        if record_type == "TXT":
            # Retrieve TXT records for root domain, _dmarc, and relevant subdomains
            subdomains = [domain, f"_dmarc.{domain}"]
            # Add common DKIM selectors
            common_selectors = ['default', 'selector1', 'selector2', 'google', 'smtp', 'mail']
            for selector in common_selectors:
                subdomains.append(f"{selector}._domainkey.{domain}")

            for subdomain in subdomains:
                # Query with Cloudflare resolver
                try:
                    answers_cf = resolver_cloudflare.resolve(subdomain, 'TXT')
                    results_cf.extend([r.to_text().strip('"') for r in answers_cf])
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
                # Query with Google resolver
                try:
                    answers_gg = resolver_google.resolve(subdomain, 'TXT')
                    results_gg.extend([r.to_text().strip('"') for r in answers_gg])
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    pass
        else:
            # Other record types
            try:
                answers_cf = resolver_cloudflare.resolve(domain, record_type)
                results_cf = [str(r) for r in answers_cf]
            except Exception:
                pass  # Handle exceptions as needed

            try:
                answers_gg = resolver_google.resolve(domain, record_type)
                results_gg = [str(r) for r in answers_gg]
            except Exception:
                pass  # Handle exceptions as needed

        # Determine discrepancies
        discrepancies = list(set(results_cf) ^ set(results_gg))

        # Only include Google results if there are discrepancies
        if discrepancies:
            response = {
                "cloudflare": results_cf,
                "google": results_gg,
                "verification": "Warning: Different results returned by resolvers.",
                "discrepancies": discrepancies
            }
        else:
            response = {
                "cloudflare": results_cf,
                "verification": "Verified: Results match between resolvers."
            }

        return response

    except dns.resolver.NXDOMAIN:
        return {"error": f"Domain {domain} does not exist."}
    except dns.resolver.Timeout:
        return {"error": "The DNS request timed out."}
    except dns.resolver.NoAnswer:
        return {"error": f"No answer was returned for the DNS query for {domain}."}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

# Function to analyze SPF record and count DNS lookups
def analyze_spf_record(spf_record):
    try:
        # Parse the SPF record
        dns_lookups = 0
        mechanisms = spf_record.split()
        for mech in mechanisms:
            if mech.startswith(('include:', 'a', 'mx', 'ptr', 'exists', 'redirect=')):
                dns_lookups += 1
            elif mech.startswith('ip4:') or mech.startswith('ip6:') or mech == 'all':
                continue  # These do not cause DNS lookups
        return dns_lookups
    except Exception as e:
        return None

# Function to analyze DKIM records using dkimpy
def analyze_dkim_records(domain):
    selectors = ['default', 'selector1', 'selector2', 'google', 'smtp', 'mail']
    dkim_records = []
    valid_dkim_found = False
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        try:
            answers = resolver_cloudflare.resolve(dkim_domain, 'TXT')
            for rdata in answers:
                record = rdata.to_text().strip('"')
                # Parse the DKIM record
                parsed_record = dkim.parse_tag_value(record.encode())
                if 'p' in parsed_record:
                    valid_dkim_found = True
                    dkim_records.append((dkim_domain, parsed_record))
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            continue
    return valid_dkim_found, dkim_records

# Function to analyze DMARC record
def analyze_dmarc_record(domain):
    dmarc_domain = f"_dmarc.{domain}"
    try:
        answers = resolver_cloudflare.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            record = rdata.to_text().strip('"')
            # Parse the DMARC record
            parsed_record = parse_dmarc_record(record)
            if parsed_record:
                return parsed_record
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return None
    return None

# Function to calculate the security score
def calculate_security_score(results, domain):
    score = 0
    max_score = 4  # Updated maximum score
    dmarc_status = "Not Found"
    spf_status = "Not Found"
    dkim_status = "Not Found"

    # Check for DMARC record
    parsed_dmarc_record = analyze_dmarc_record(domain)
    if parsed_dmarc_record:
        policy = parsed_dmarc_record.get('p', '').lower()
        if policy == 'reject':
            score += 2  # Full points for p=reject
            dmarc_status = "Policy set to reject (Good)"
        elif policy in ['quarantine', 'none']:
            score += 1  # Partial points for other policies
            dmarc_status = f"Policy set to {policy} (Could be improved)"
        else:
            dmarc_status = "Policy not recognized"
    else:
        dmarc_status = "DMARC Record Not Found"

    # Check for SPF record
    spf_found = False
    dns_lookups = None
    spf_warning = None
    if "TXT" in results and "cloudflare" in results["TXT"]:
        txt_records = results["TXT"]["cloudflare"]
        for record in txt_records:
            if re.search(r'v=spf1', record, re.IGNORECASE):
                score += 1
                spf_status = "SPF Record Found"
                spf_found = True
                # Analyze SPF record for DNS lookups
                dns_lookups = analyze_spf_record(record)
                if dns_lookups is not None and dns_lookups > 10:
                    spf_warning = f"DNS lookup count in your SPF record ({dns_lookups}) exceeds the maximum limit of 10. This can cause SPF authentication failures."
                break
    if not spf_found:
        spf_status = "SPF Record Not Found"

    # Check for DKIM record
    dkim_valid, dkim_records = analyze_dkim_records(domain)
    if dkim_valid:
        score += 1
        dkim_status = "DKIM Record Found and Valid"
    else:
        dkim_status = "DKIM Record Not Found or Invalid"

    return score, max_score, dmarc_status, spf_status, dkim_status, dns_lookups, spf_warning

@app.route('/')
def index():
    return render_template('zonefile_tool.html')

@app.route('/lookup', methods=['POST'])
def lookup():
    domain = request.form.get('domain')
    if not domain:
        return jsonify({"error": "Domain not provided"}), 400

    # Perform DNS lookups
    results = {}
    record_types = ["A", "MX", "NS", "TXT"]
    # Only include AAAA if there are no A records
    a_records = perform_dns_lookup(domain, "A")
    if a_records.get("cloudflare") and a_records["cloudflare"]:
        results["A"] = a_records
    else:
        aaaa_records = perform_dns_lookup(domain, "AAAA")
        if aaaa_records.get("cloudflare") and aaaa_records["cloudflare"]:
            results["AAAA"] = aaaa_records

    # Fetch other record types
    for record_type in ["MX", "NS", "TXT"]:
        results[record_type] = perform_dns_lookup(domain, record_type)

    # Calculate security score
    score, max_score, dmarc_status, spf_status, dkim_status, dns_lookups, spf_warning = calculate_security_score(results, domain)

    # Get domain expiration date and registrar
    expiration_date, registrar = get_domain_info(domain)
    if expiration_date:
        # Calculate days until expiration
        days_until_expiration = (expiration_date - datetime.now()).days
        expiration_info = f"The domain expires on {expiration_date.strftime('%Y-%m-%d')} ({days_until_expiration} days remaining)."
    else:
        expiration_info = "Expiration date could not be retrieved."

    if registrar:
        registrar_info = f"Registrar: {registrar}"
    else:
        registrar_info = "Registrar information not available."

    # Check website accessibility and SSL validation
    website_status = check_website_accessibility(domain)

    # Detect email security tools
    email_security_tools = []
    unknown_mx_providers = []
    if "MX" in results and "cloudflare" in results["MX"]:
        mx_records = results["MX"]["cloudflare"]
        mx_tools, unknown_mx_providers = detect_email_security_tools(mx_records)
        email_security_tools.extend(mx_tools)

    # Detect DMARC service providers
    if "TXT" in results and "cloudflare" in results["TXT"]:
        txt_records = results["TXT"]["cloudflare"]
        dmarc_providers = detect_dmarc_providers(txt_records)
        if dmarc_providers:
            # Append with indication that they are DMARC tools
            for provider in dmarc_providers:
                email_security_tools.append(f"DMARC Service: {provider}")

    # Remove duplicates
    email_security_tools = list(set(email_security_tools))

    response = {
        "domain": domain,
        "results": results,
        "score": score,
        "max_score": max_score,
        "dmarc_status": dmarc_status,
        "spf_status": spf_status,
        "dkim_status": dkim_status,
        "expiration_info": expiration_info,
        "registrar_info": registrar_info,
        "website_status": website_status,
        "email_security_tools": email_security_tools,
        "unknown_mx_providers": unknown_mx_providers,
        "highlighted_info": [],
        "spf_dns_lookups": dns_lookups,
        "spf_warning": spf_warning
    }

    # Add explanations to the results
    for record_type, result in results.items():
        if isinstance(result, dict) and "cloudflare" in result:
            discrepancies = result.get("discrepancies", None)
            explanation, highlighted_info = get_record_explanation(record_type, result["cloudflare"], discrepancies)
            result["explanation"] = explanation
            result.setdefault("highlighted_info", []).extend(highlighted_info)
            response["highlighted_info"].extend(highlighted_info)

    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5001)
