import subprocess
import json

def run_nuclei(target, templates):
    # Make sure 'nuclei' is installed and available in your PATH
    nuclei_path = 'nuclei'  # This should be the path to the Nuclei binary or just 'nuclei' if it's in PATH
    command = [nuclei_path, '-u', target, '-t', templates, '-json']

    try:
        # Run the command and capture the output
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        return json.loads(result.stdout)  # Parse JSON output
    except subprocess.CalledProcessError as e:
        print(f"Error running Nuclei: {e}")
        return None

# Example usage
if __name__ == "__main__":
    target = 'https://www.example.com'  # Replace with your target URL
    templates = 'nuclei/*'    # Path to your Nuclei templates

    # Run the scan
    result = run_nuclei(target, templates)

    # Output result
    if result:
        print(json.dumps(result, indent=2))
    else:
        print("Scan failed.")
