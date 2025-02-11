import subprocess
import os

def run_command(command, description):
    """Run a shell command and handle errors."""
    print(f"[+] Running: {description}")
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] Error running {description}: {result.stderr.strip()}")
    else:
        print(f"[+] {description} completed successfully.")
    return result.stdout.strip()

def check_tool_installed(tool):
    """Check if a tool is installed and available in PATH."""
    result = subprocess.run(f"which {tool}", shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] {tool} is not installed or not in PATH.")
        return False
    return True

def install_tools():
    """Install necessary tools for the script."""
    tools = {
        "assetfinder": "go install github.com/tomnomnom/assetfinder@latest",
        "amass": "sudo apt update && sudo apt install -y amass",
        "httprobe": "go install github.com/tomnomnom/httprobe@latest",
        "subjack": (
            "go install github.com/haccer/subjack@latest && "
            "wget https://raw.githubusercontent.com/haccer/subjack/master/fingerprints.json "
            "-O ~/go/src/github.com/haccer/subjack/fingerprints.json"
        ),
        "waybackurls": "go install github.com/tomnomnom/waybackurls@latest",
        "nmap": "sudo apt install -y nmap",
    }
    for tool, command in tools.items():
        if not check_tool_installed(tool):
            print(f"[+] Installing {tool}...")
            run_command(command, f"Installing {tool}")

def create_directories(base_dir, sub_dirs):
    """Create directories if they don't exist."""
    for sub_dir in sub_dirs:
        os.makedirs(os.path.join(base_dir, sub_dir), exist_ok=True)

def validate_alive_file(alive_file):
    """Validate domains in the alive file to avoid scanning unresolvable domains."""
    valid_domains = []
    with open(alive_file, "r") as file:
        for line in file:
            domain = line.strip()
            if domain:
                result = subprocess.run(f"nslookup {domain}", shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    valid_domains.append(domain)
                else:
                    print(f"[-] Skipping unresolvable domain: {domain}")
    with open(alive_file, "w") as file:
        file.write("\n".join(valid_domains))

def main():
    # Install tools
    print("[+] Checking and installing necessary tools...")
    install_tools()

    # Input URL
    url = input("Enter the target URL (e.g., example.com): ").strip()
    if not url:
        print("[-] URL cannot be empty!")
        return

    base_dir = url
    recon_dirs = [
        "recon",
        "recon/scans",
        "recon/httprobe",
        "recon/potential_takeovers",
        "recon/wayback",
        "recon/wayback/params",
        "recon/wayback/extensions",
    ]
    create_directories(base_dir, recon_dirs)

    # File paths
    alive_file = os.path.join(base_dir, "recon/httprobe/alive.txt")
    final_file = os.path.join(base_dir, "recon/final.txt")
    takeover_file = os.path.join(base_dir, "recon/potential_takeovers/potential_takeovers.txt")
    wayback_output = os.path.join(base_dir, "recon/wayback/wayback_output.txt")

    # Create empty files if not exist
    open(alive_file, "a").close()
    open(final_file, "a").close()
    open(takeover_file, "a").close()

    # Harvesting subdomains with assetfinder
    run_command(f"assetfinder {url} > {base_dir}/recon/assets.txt", "Assetfinder for subdomains")
    run_command(f"cat {base_dir}/recon/assets.txt | grep {url} >> {final_file}", "Filtering subdomains")
    os.remove(f"{base_dir}/recon/assets.txt")

    # Double-checking with amass
    run_command(f"amass enum -d {url} >> {base_dir}/recon/f.txt", "Amass enumeration")
    run_command(f"sort -u {base_dir}/recon/f.txt >> {final_file}", "Sorting unique subdomains")
    os.remove(f"{base_dir}/recon/f.txt")

    # Probing for alive domains
    run_command(f"cat {final_file} | sort -u | httprobe -s -p https:443 | sed 's/https\\?:\\/\\///' | tr -d ':443' >> {base_dir}/recon/httprobe/a.txt", "Probing alive domains")
    run_command(f"sort -u {base_dir}/recon/httprobe/a.txt > {alive_file}", "Sorting alive domains")
    os.remove(f"{base_dir}/recon/httprobe/a.txt")

    # Validate alive domains
    validate_alive_file(alive_file)

    # Checking for potential subdomain takeovers
    run_command(
        f"subjack -w {final_file} -t 100 -timeout 30 -ssl -c ~/go/src/github.com/haccer/subjack/fingerprints.json -v 3 -o {takeover_file}",
        "Checking for subdomain takeovers",
    )
    if os.stat(takeover_file).st_size == 0:
        print("[+] No potential subdomain takeovers found.")

    # Scanning for open ports
    run_command(f"nmap -iL {alive_file} -T4 -oA {base_dir}/recon/scans/scanned", "Scanning open ports with Nmap")

    # Scraping wayback data
    run_command(f"cat {final_file} | waybackurls >> {wayback_output}", "Scraping Wayback Machine data")
    run_command(f"sort -u {wayback_output} -o {wayback_output}", "Sorting Wayback output")

    # Extracting parameters from wayback data
    params_file = os.path.join(base_dir, "recon/wayback/params/wayback_params.txt")
    run_command(f"cat {wayback_output} | grep '?*=' | cut -d '=' -f 1 | sort -u > {params_file}", "Extracting parameters")
    print("[+] Extracted parameters:")
    with open(params_file, "r") as params:
        for line in params:
            print(f"{line.strip()}=")

    # Extracting files with specific extensions
    extensions = ["js", "html", "json", "php", "aspx"]
    for ext in extensions:
        ext_file = os.path.join(base_dir, f"recon/wayback/extensions/{ext}.txt")
        run_command(f"grep '\\.{ext}$' {wayback_output} > {ext_file}", f"Extracting {ext} files")
        if os.stat(ext_file).st_size == 0:
            print(f"[+] No {ext} files found in wayback data.")

    print("[+] Recon Stage Completed :)")

if __name__ == "__main__":
    main()

