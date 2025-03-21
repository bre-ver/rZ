
#RUNZERO_API_KEY = ""
import requests
import csv
import json

# Replace with your API key
API_KEY = 'APIKEY'
# Base URL for the RunZero API
BASE_URL = 'https://console.runzero.com/api/v1.0'
# Search string
SEARCH = 'source:meraki'
# Output file name
OUTPUT_FILE = 'runzero_export.csv'

def get_assets(api_key, search):
    headers = {
        'Accept': 'application/json',
        'Authorization': f'Bearer {api_key}'
    }

    # Endpoint to fetch assets with search as query parameter
    endpoint = '/export/org/assets.json'
    params = {
        'search': search
    }

    response = requests.get(BASE_URL + endpoint, headers=headers, params=params)

    if response.status_code == 200:
        return response.json()
    else:
        response.raise_for_status()

def main():
    try:
        assets = get_assets(API_KEY, SEARCH)
        
        # Define the CSV header rows based on the requested attributes
        headers = [
            'risk_rank', 'id', 'created_at', 'updated_at', 'organization_id', 
            'site_id', 'alive', 'last_seen', 'first_seen', 'detected_by', 
            'type', 'os_vendor', 'os_product', 'os_version', 'os', 
            'hw_vendor', 'hw_product', 'hw_version', 'hw', 'addresses', 
            'addresses_extra', 'macs', 'mac_vendors', 'names', 'domains', 
            # Meraki network client attributes
            'meraki_description', 'meraki_firstSeen', 'meraki_id', 'meraki_ip',
            'meraki_ip6Local', 'meraki_lastSeen', 'meraki_mac', 'meraki_manufacturer',
            'meraki_match_criteria', 'meraki_networkID', 'meraki_organizationID',
            'meraki_recentDeviceConnection', 'meraki_recentDeviceMAC', 
            'meraki_recentDeviceName', 'meraki_recentDeviceSerial', 'meraki_status',
            'meraki_switchPort', 'meraki_ts', 'meraki_type', 'meraki_usage_recv',
            'meraki_usage_sent', 'meraki_usage_total', 'meraki_vlan',
            'meraki_wirelessCapabilities'
        ]
        
        # Create and write to CSV file
        with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(headers)
            
            for asset in assets:
                # Process basic attributes
                row = [
                    asset.get('risk_rank', ''),
                    asset.get('id', ''),
                    asset.get('created_at', ''),
                    asset.get('updated_at', ''),
                    asset.get('organization_id', ''),
                    asset.get('site_id', ''),
                    asset.get('alive', ''),
                    asset.get('last_seen', ''),
                    asset.get('first_seen', ''),
                    asset.get('detected_by', ''),
                    asset.get('type', ''),
                    asset.get('os_vendor', ''),
                    asset.get('os_product', ''),
                    asset.get('os_version', ''),
                    asset.get('os', ''),
                    asset.get('hw_vendor', ''),
                    asset.get('hw_product', ''),
                    asset.get('hw_version', ''),
                    asset.get('hw', ''),
                    ';'.join(asset.get('addresses', [])),
                    ';'.join(map(str, asset.get('addresses_extra', []))),
                    ';'.join(asset.get('macs', [])),
                    ';'.join(asset.get('mac_vendors', [])),
                    ';'.join(asset.get('names', [])),
                    ';'.join(asset.get('domains', []))
                ]
                
                # Process Meraki network client attributes
                meraki_data = {}
                if 'foreign_attributes' in asset and '@meraki.ntwkclient' in asset['foreign_attributes']:
                    # Take the first Meraki network client entry if there are multiple
                    if asset['foreign_attributes']['@meraki.ntwkclient']:
                        meraki_data = asset['foreign_attributes']['@meraki.ntwkclient'][0]
                
                # Add Meraki attributes to the row
                row.extend([
                    meraki_data.get('description', ''),
                    meraki_data.get('firstSeen', ''),
                    meraki_data.get('id', ''),
                    meraki_data.get('ip', ''),
                    meraki_data.get('ip6Local', ''),
                    meraki_data.get('lastSeen', ''),
                    meraki_data.get('mac', ''),
                    meraki_data.get('manufacturer', ''),
                    meraki_data.get('match.criteria', ''),
                    meraki_data.get('networkID', ''),
                    meraki_data.get('organizationID', ''),
                    meraki_data.get('recentDeviceConnection', ''),
                    meraki_data.get('recentDeviceMAC', ''),
                    meraki_data.get('recentDeviceName', ''),
                    meraki_data.get('recentDeviceSerial', ''),
                    meraki_data.get('status', ''),
                    meraki_data.get('switchPort', ''),
                    meraki_data.get('ts', ''),
                    meraki_data.get('type', ''),
                    meraki_data.get('usage.recv', ''),
                    meraki_data.get('usage.sent', ''),
                    meraki_data.get('usage.total', ''),
                    meraki_data.get('vlan', ''),
                    meraki_data.get('wirelessCapabilities', '')
                ])
                
                writer.writerow(row)
        
        print(f"Export completed: {OUTPUT_FILE}")
        print(f"Total assets exported: {len(assets)}")
        
    except Exception as e:
        print(f'An error occurred: {e}')

if __name__ == "__main__":
    main()