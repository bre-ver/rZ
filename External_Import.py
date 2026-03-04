import requests
import os
import sys

# ============= CONFIGURATION =============
SRC_CONSOLE_URL = "https://console.runzero.com"                  # Source runZero console URL
SRC_API_KEY     = "YOURSAASAPI"                                  # Source Organization API key
DST_CONSOLE_URL = "https://selfhosted.url"                       # Destination runZero console URL
DST_API_KEY     = "YOURSHAPI"                                    # Destination Organization API key
SITE_ID         = "SH-SITE-ID"                                   # Destination site ID for upload. Found in URL header of that site.
SAVE_PATH       = "./"                                           # Local path for temporary file storage

# ============= HELPER FUNCTIONS =============

def get_latest_external_task():
    """
    Retrieve the most recent task with the name "External Scan" from the source console.
    This uses the endpoint GET /api/v1.0/org/tasks and filters the results.
    """
    url = f"{SRC_CONSOLE_URL}/api/v1.0/org/tasks"
    headers = {
        "Authorization": f"Bearer {SRC_API_KEY}",
        "Accept": "application/json",
    }
    # Optionally, you can filter by task status as needed (e.g., 'processed')
    params = {"status": "processed"}
    
    response = requests.get(url, headers=headers, params=params)
    response.raise_for_status()
    tasks = response.json()

    # Filter tasks by name "External Scan"
    external_tasks = [task for task in tasks if task.get("name") == "External Scan"]
    if not external_tasks:
        raise Exception("No 'External Scan' task found in the source console.")

    # Assuming tasks are returned with the most recent first.
    latest_task = external_tasks[0]
    return latest_task

def download_scan_data(task):
    """
    Download the scan data associated with the provided task.
    The data is saved as a gzipped JSON file named 'scan_<task_id>.json.gz'.
    """
    task_id = task["id"]
    url = f"{SRC_CONSOLE_URL}/api/v1.0/org/tasks/{task_id}/data"
    headers = {
        "Authorization": f"Bearer {SRC_API_KEY}",
        "Accept": "application/json",
    }

    response = requests.get(url, headers=headers, stream=True)
    response.raise_for_status()
    
    filename = os.path.join(SAVE_PATH, f"scan_{task_id}.json.gz")
    with open(filename, "wb") as f:
        for chunk in response.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    return filename

def upload_scan_data(file_path):
    """
    Upload the scan data file to the destination console.
    This imports scan data into a specified site.
    """
    file_name = os.path.basename(file_path)
    url = f"{DST_CONSOLE_URL}/api/v1.0/org/sites/{SITE_ID}/import"
    headers = {
        "Authorization": f"Bearer {DST_API_KEY}",
        "Content-Type": "application/octet-stream",
        "Content-Encoding": "gzip",
    }
    params = {
        "name": file_name,
        "description": "Imported External scan data",
    }
    
    with open(file_path, "rb") as f:
        response = requests.put(url, headers=headers, params=params, data=f)
    response.raise_for_status()
    return response.json()

def clean_up(file_path):
    """
    Delete the temporary file used for scan data storage.
    """
    try:
        os.remove(file_path)
    except OSError as err:
        print(f"Error deleting {file_path}: {err}", file=sys.stderr)

# ============= MAIN FUNCTION =============

def main():
    try:
        print("Retrieving the latest 'External Scan' task from the source console...")
        task = get_latest_external_task()
        print(f"Found task with ID: {task['id']}.")

        print("Downloading scan data...")
        file_path = download_scan_data(task)
        print(f"Scan data downloaded to {file_path}.")

        print("Uploading scan data to the destination console...")
        upload_response = upload_scan_data(file_path)
        print("Upload successful. Destination response:")
        print(upload_response)

        print("Cleaning up temporary files...")
        clean_up(file_path)
        print("Done.")

    except Exception as ex:
        print("An error occurred:", ex, file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
