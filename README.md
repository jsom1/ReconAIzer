# ReconAIzer

**ReconAIzer** is a command-line tool that integrates Nmap scanning with ChatGPT-powered vulnerability assessments and command recommendations for network enumeration and penetration testing. It automatically scans a target using Nmap, parses the results via XML, sends service details to ChatGPT to fetch exploitation tips, and then generates an interactive HTML report with a clickable table of contents and actionable recommendations.

## Features

- **Automated Nmap Scanning:**  
  Runs Nmap with service version detection and default scripts to identify open services on a target.
  
- **XML Parsing:**  
  Uses XML output for reliable extraction of scan data.
  
- **ChatGPT Integration:**  
  Retrieves detailed vulnerability information and recommended commands for each detected service.
  
- **Interactive HTML Report:**  
  Generates a styled HTML report (using Jinja2) that includes:
  - A clickable Table of Contents for easy navigation.
  - Checkboxes to mark tested recommendations.
  - A remarks section for additional notes.

- **Secure Configuration:**  
  Manages sensitive credentials through a `.env` file and ignores generated files via `.gitignore`.

## Requirements

- Python 3.x  
- Nmap (installed and available in your system PATH)  
- An OpenAI API key for ChatGPT integration  

### Python Packages

Install the required packages with:

```bash
pip3 install python-dotenv jinja2 markdown openai
````

## Installation

1. Clone the repository:

```bash
git clone https://github.com/jsom/ReconAIzer.git
cd reconaizer
```

2. Create a *.env* file in the project root with your OpenAI API key:

```bash
OPENAI_API_KEY=your_openai_api_key
````

3. Verify your .gitignore: ensure that sensitive and generated files (.env, scan.xml, ...) are ignored.

## Usage

Run ReconAIzer with the following command:

```bash
sudo python3 reconaizer.py
````

When prompted, enter the target IP address or hostname. For example:

```css
Target IP address: scanme.nmap.org
````

The tool will:

- Perform an nmap scan of the target
- Fetch vulnerability information and recommendations for each detected service via ChatGPT
- Generate an interactive HTML report (*scan_report.html*) that automatically opens in your web browser
