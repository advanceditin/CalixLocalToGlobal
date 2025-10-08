#### IMPORTANT ####
#
# To use this script you must do the following:
#
# Find 123.123.123.123 and replace with IP of your SMx IP address or DNS name
# Find ontlist and replace with the name of the csv file that contains the list of ONTs that need converted
# 
# Find 'Authorization' and update the string after the word Basic, with valid username and password (you can use https://www.base64encode.org/ to encode the username and password)
# See https://www.calix.com/content/dam/calix/mycalix-misc/lib/iae/sm/24x/smx-api/index.htm and search 'Basic Authentication' for more information
#
#

import pandas as pd
import requests
import json
import time
import urllib3

# Suppress only the single InsecureRequestWarning from urllib3 needed for requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Load List of ONTs to be converted using abs CSV file
csv_file_path = 'ontlist.csv' #THIS IS THE LIST OF ONTSerialNo THE SCRIPT WILL REFERENCE FOR CONVERTING ONTSerialNo
ONTs = pd.read_csv(csv_file_path)

# API URLs - This could be consolidated to just the root URL and appended later based on API call
base_url = 'https://123.123.123.123:18443/rest/v1'
svc_url = 'https://123.123.123.123:18443/rest/v1/ems/service'
dvc_url = 'https://123.123.123.123:18443/rest/v1/config/device/'
DelONT_url = 'https://123.123.123.123:18443/rest/v1/config/device/'
AddONT_url = 'https://123.123.123.123:18443/rest/v1/config/device/virtualOLT/ont'

# Define the headers including the Authorization header
headers = {
    'Authorization': 'Basic YWRtaW46dGVzdDEyMw==',  # This is using basic Authentication. See https://www.calix.com/content/dam/calix/mycalix-misc/lib/iae/sm/24x/smx-api/index.htm
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

#A function for removing null values... used later
def filter_null_values(data):
    """Remove keys with null values from the dictionary."""
    return {k: v for k, v in data.items() if v not in [None, '', [], {}]}

# Perform the following for each row/ONT (index) listed in the CSV file
for index, row in ONTs.iterrows():
    device_name = ONTs.at[index, 'OLT']
    ont_id = str(ONTs.at[index, 'ONT ID'])
    serial_number = ONTs.at[index, 'Serial']
    ont_profile_id = ONTs.at[index, 'ONT Profile']

    print(f"\nSTORE LOCAL ONT INFO")
    print(f"    Device Name: {device_name}")
    print(f"    ONT ID: {ont_id}\n")

    #print(f"ONT Description: {ontdescription}\n")

    print(f"\nCOLLECTING SERVICE INFORMATION FOR ONT\n")
    url = f"{svc_url}?device-name={device_name}&ont-id={ont_id}"
    print(f"     GET URL: {url}\n")

    get_response = requests.get(url, headers=headers, verify=False) # get all service information and put it in a data frame(table)

    if get_response.status_code == 200:
        json_data = get_response.json()
    #    print(f"Raw JSON data: {json.dumps(json_data, indent=4)}\n")
    else:
        raise Exception(f"     GET request failed with status code {get_response.status_code}")

    #Check if JSON data is empty
    if not json_data:
        print(f"     No data returned for ONT ID: {ont_id}")
        continue

    data_frame = pd.json_normalize(json_data)
    print(f"     Normalized DataFrame:\n{data_frame}\n")

    available_columns = data_frame.columns.tolist()
	#Adjust the following list as necessary based on what json fields are required for your environments services
    required_columns = ['vlan', 'vlan-mode', 'serviceType', 'ont-port-id', 'admin-state', 'ont-id', 'subscriber-id', 'port-description', 'policy-map', 'transport-service-profile', 'service-name', 'user', 'password', 'uri', 'l2hosts']
    selected_columns = [col for col in required_columns if col in available_columns] #filter the original JSON data and select only the required columns listed directly above

    selected_data = data_frame[selected_columns]
    selected_data = selected_data.fillna('')
    print(f"     Selected DataFrame:\n{selected_data}\n")

    print(f"\nDELETING LOCAL ONT\n")
    DELurl = f"{DelONT_url}{device_name}/ont?ont-id={ont_id}&force-delete=true"
    print(f"     DELETE ONT URL: {DELurl}")

    DEL_response = requests.delete(DELurl, headers=headers, verify=False) # Delete the local ONT
    print(f"     Response for index {index}: {DEL_response.status_code} - {DEL_response.text}")

    print(f"\nCREATING GLOBAL ONT\n")
    print(f"     ONT ID: {ont_id}")
    print(f"     Serial Number: {serial_number}")
    print(f"     ONT Profile: {ont_profile_id}")

    ONTpayload = {
        "ont-id": ont_id,
        "ont-type": "Residential",
        "global-type": "Global",
        "isGlobalOnt": "true",
        "serial-number": serial_number,
        "device-name": "virtualOLT",
        "ont-profile-id": ont_profile_id,
        "vendor-id": "CXNK"
    }
    #print(f"\n     Payload: {ONTpayload}\n")

    ADDresponse = requests.post(AddONT_url, json=ONTpayload, headers=headers, verify=False)
    print(f"     Response for index {index}: {ADDresponse.status_code} - {ADDresponse.text}\n")

    Checkurl = f"{dvc_url}{device_name}/ont?ont-id={ont_id}"
    print(f"     {Checkurl}\n")

    #SMx can take a minute or two to recognize and allocate global ONTs, this loop pauses the process until SMx has finished this process.
    print(f"Starting Validation loop\n")
    while True:
        print(f"     Checking if ONT is present...\n")
        get_response = requests.get(Checkurl, headers=headers, verify=False)
        if get_response.status_code == 200:
            print(f"     {ont_id} Detected on shelf {device_name}, proceeding with service provisioning\n")
            break
        print(f"     Response: {get_response.status_code} - {get_response.text}\n")
        print(f"         ...not detected, waiting 30 secs...\n")
        time.sleep(30)

    print(f"\nRE-ADD SERVICES TO GLOBAL ONT:\n")
    for index2, row in selected_data.iterrows():
        description = str(selected_data.at[index2, 'subscriber-id'])
        vlan = int(selected_data.at[index2, 'vlan'])
        serviceType = selected_data.at[index2, 'serviceType']
        ont_port_id = selected_data.at[index2, 'ont-port-id']
        admin_state = selected_data.at[index2, 'admin-state']
        ont_id = str(selected_data.at[index2, 'ont-id'])
        subscriber_id = str(selected_data.at[index2, 'subscriber-id'])
        vlan_mode = str(selected_data.at[index2, 'vlan-mode']) if 'vlan-mode' in selected_columns else ''
        tsp = str(selected_data.at[index2, 'transport-service-profile']) if 'transport-service-profile' in selected_columns else ''
        port_description = selected_data.at[index2, 'port-description'] if 'port-description' in selected_columns else ''
        service_name = selected_data.at[index2, 'service-name']
        policy_map = str(selected_data.at[index2, 'policy-map'])
        user = selected_data.at[index2, 'user'] if 'user' in selected_columns else []
        password = selected_data.at[index2, 'password'] if 'password' in selected_columns else []
        uri = selected_data.at[index2, 'uri'] if 'uri' in selected_columns else []
        l2hosts = selected_data.at[index2, 'l2hosts'] if 'l2hosts' in selected_columns else []

        SVCpayload = {
            "description": description,
            "vlan": vlan,
            "serviceType": serviceType,
            "device-name": device_name,
            "ont-port-id": ont_port_id,
            "admin-state": admin_state,
            "ont-id": ont_id,
            "subscriber-id": subscriber_id,
            "vlan-mode": vlan_mode,
            "transport-service-profile": tsp,
            "port-description": port_description,
            "policy-map": policy_map,
            "service-name": service_name,
            "user": user,
            "password": password,
            "uri": uri,
            "l2hosts": l2hosts,
            "disable-when-on-battery": "false"
        }

        SVCpayload = filter_null_values(SVCpayload)
        print(f"     Payload: {SVCpayload}\n")

        print(f"     ADD SVC URL: {svc_url}\n")
        SVCresponse = requests.post(svc_url, json=SVCpayload, headers=headers, verify=False)
        print(f"     Response for index2 {index2}: {SVCresponse.status_code} - {SVCresponse.text}\n")
    print(f"\nREBOOTING ONT...")
    reseturl = f"{dvc_url}{device_name}/ont/reset?ont-id={ont_id}&forced=true"
    get_reset_response = requests.put(reseturl, headers=headers, verify=False)
    print(f"     Response: {get_reset_response.status_code} - {get_reset_response.text}\n")
    print(f"\n\n\nMOVING TO NEXT ONT...\n\n\n")
    print(f"---------------------------------------------------------------------------------------------------------------------------\n")
print(f"No More ONTs.... All Done....")
print(f"\nBYE FELICIA!\n")
