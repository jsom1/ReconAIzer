from dotenv import load_dotenv
import os
load_dotenv()

import subprocess
import re
import openai
import os
import webbrowser
from datetime import datetime
import markdown
import json
import xml.etree.ElementTree as ET
from jinja2 import Environment, FileSystemLoader, select_autoescape

def print_rainbow(text):
    colors = ["\033[31m", "\033[33m", "\033[32m", "\033[36m", "\033[34m", "\033[35m"]
    reset = "\033[0m"
    colored_text = "".join(f"{colors[i % len(colors)]}{char}{reset}" for i, char in enumerate(text))
    print(colored_text)

def display_start_message():
    ascii_art = """
    ____                         _    ___                  
   |  _ \ ___  ___ ___  _ __    / \  |_ _|_______ _ __     
   | |_) / _ \/ __/ _ \| '_ \  / _ \  | ||_  / _ \ '__|    
   |  _ <  __/ (_| (_) | | | |/ ___ \ | | / /  __/ |       
   |_| \_\___|\___\___/|_| |_/_/   \_\___/___\___|_|  
    """
    print_rainbow(ascii_art)

    welcome_message = (
        "Welcome to ReconAIzer!\n"
        "ReconAIzer uses chatGPT to issue enumeration recommendations for services discovered by nmap.\n"
    )

    print(welcome_message)

def print_green(text):
    print(f"\033[32m{text}\033[0m")

def scan_nmap(ip_address):
    command = ["nmap", "-sV", "-sC", "-oX", "scan.xml", ip_address]
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print(f"Scan results on {ip_address}:\n{result.stdout}")
        services = parse_nmap_xml("scan.xml")
        return services, result.stdout
    except subprocess.CalledProcessError as e:
        print("Nmap scan failed:", e)
        return [], ""

def parse_nmap_xml(xml_file="scan.xml"):
    services = []
    try:
        tree = ET.parse(xml_file)
        root = tree.getroot()
        for host in root.findall('host'):
            ports = host.find('ports')
            if ports is None:
                continue
            for port in ports.findall('port'):
                port_id = port.get('portid')
                state = port.find('state').get('state')
                service_elem = port.find('service')
                service = service_elem.get('name') if service_elem is not None else "unknown"
                version = service_elem.get('version') if service_elem is not None and service_elem.get('version') is not None else "N/A"
                services.append((f"{port_id}/tcp", state, service, version))
        return services
    except Exception as e:
        print(f"Error parsing XML : {e}")
        return []

def clean_response(response_str):
    """
    Clean up the response string to remove Markdown delimiters and superfluous text to obtain pure JSON
    """
    if response_str.startswith("```") and response_str.endswith("```"):
        lines = response_str.splitlines()
        response_str = "\n".join(lines[1:-1])
    return response_str.strip()

def get_service_info(service_name, client):
    schema = {
        "type": "object",
        "properties": {
            "description": {
                "type": "string",
                "description": f"A detailed explanation of the {service_name} service, including potential vulnerabilities."
            },
            "vulnerability_score": {
                "type": "integer",
                "description": "A score from 1 to 10 estimating the likelihood of vulnerability.",
                "minimum": 1,
                "maximum": 10
            },
            "recommendations": {
                "type": "array",
                "description": (
                    "A list of command recommendations with explanations. Each command must use"
                    "placeholders {ip-address} and {port} for the port and ip address. "
                    "For each command, explain its purpose and options, and always enclose commands in apostrophes."
                    "A few examples: 'nmap -sV -sC {ip-address} {port}', 'dirb http://{ip-address} -r', 'nikto -h http://{ip-address}', and so on..."
                ),
                "items": {"type": "string"}
            }
        },
        "required": ["description", "vulnerability_score", "recommendations"]
    }

    prompt = (
        f"Provide ONLY a valid JSON response structured according to the following schema for the service '{service_name}':\n"
        f"{json.dumps(schema, indent=2)}\n"
        f"The response must contain only the JSON object, with no additional text or markdown formatting.\n"
        f"All commands must include the placeholders {{ip-address}} and {{port}} exactly, and use complete commands as shown in the examples.\n"
        f"For example, provide 'nmap -sV -p {{port}} {{ip-address}}' instead of just 'nmap -p'. "
        f"After the command, explain what it does and the different options. Always enclose commands in apostrophes."
    )

    response = client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        functions=[{"name": "get_service_info", "parameters": schema}],
        function_call="auto"
    )

    # print("Raw API response:", response) --> debug

    # The response is either in function_call or in content
    try:
        function_call = response.choices[0].message.function_call
        if function_call and function_call.arguments:
            service_info_json = function_call.arguments
        else:
            service_info_json = response.choices[0].message.content
            print(f"Using content fallback for service '{service_name}'.")

        service_info_json = clean_response(service_info_json)

        service_info = json.loads(service_info_json)
        return service_info
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for service '{service_name}': {e}")
        print(f"Raw service info response was:\n{service_info_json}")
        return {"description": "No description available.", "recommendations": [], "vulnerability_score": 0}
    except AttributeError:
        print(f"Error: No valid response format received for service '{service_name}'.")
        return {"description": "No description available.", "recommendations": [], "vulnerability_score": 0}

def generate_report_data(ip_address, services, client):
    """
    List of dictionaries to feed the HTML template
    """
    services_info = []
    for port, state, service, version in services:
        info = get_service_info(service, client)
        recommendations = info.get("recommendations", [])
        processed_recommendations = []
        for rec in recommendations:
            rec = rec.replace("{ip-address}", ip_address)
            rec = rec.replace("{port}", port)
            processed_recommendations.append(rec)
        
        service_entry = {
            "name": service.capitalize(),
            "port": port,
            "state": state,
            "version": version,
            "description": info.get("description", "No description available."),
            "vulnerability_score": info.get("vulnerability_score", 0),
            "recommendations": processed_recommendations
        }
        services_info.append(service_entry)
    return services_info

def save_scan_to_report(ip_address, scan_output):
    with open("report.md", "w") as report:
        report.write(f"## Nmap Scan Results\n<pre><code>\n{scan_output.strip()}\n</code></pre>\n")

        report.write("\n## Enumeration Recommendations\n")
        for port, state, service, version in services:
            anchor = f"{service}_{port}".replace("/", "_")
            service_info = selected_actions.get(service, {"description": "No description available.", "recommendations": []})
            report.write(f"\n<a name=\"{anchor}\"></a>\n### {service.capitalize()} on {port} (version: {version})\n\n")
            report.write(f"**Description:**\n{service_info['description']}\n\n")
            report.write(f"**Vulnerability Score:** {service_info.get('vulnerability_score', 'N/A')}/10\n\n")
            report.write("**Recommendations:**\n<ul>")
            for recommendation in service_info["recommendations"]:
                report.write(f"<li>{recommendation}</li>")
            report.write("</ul>\n")
            report.write("\n-----------------------------------------------------------------------------------------\n")

def generate_report_html(ip_address, services_info, nmap_scan_results):
    # Jinja2 environment to load the template from the "templates" folder
    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html", "xml"])
    )
    template = env.get_template("report_template.html")
    
    context = {
        "ip_address": ip_address,
        "scan_date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "nmap_scan_results": nmap_scan_results,
        "services": services_info
    }
    
    html_content = template.render(context)

    report_path = "scan_report.html"
    with open(report_path, "w") as file:
        file.write(html_content)
    
    print_green(f"\nThe report has been generated: {report_path}. Type 'open {report_path}' (Mac/Linux) or 'start {report_path}' (Windows) to open it.")
    webbrowser.open(report_path)

def main():
    display_start_message()
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OpenAI API key is undefined. Set the OPENAI_API_KEY environment variable.")
    
    openai.api_key = api_key
    ip_address = input(f"\033[32mTarget IP address: \033[0m")
    services, nmap_output = scan_nmap(ip_address)
    if services:
        print_green("Sending results to ChatGPT...")
        services_info = generate_report_data(ip_address, services, openai)
        generate_report_html(ip_address, services_info, nmap_output)
    else:
        print("No open services found or scan failed.")


if __name__ == "__main__":
    main()

