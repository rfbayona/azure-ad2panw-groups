#! /usr/bin/env python3

import requests
import urllib
import urllib3
urllib3.disable_warnings()

panw_hostname = "IP OR HOSTNAME FOR NGFW"
panw_apikey = "APIKEY FROM NGFW"
azure_client_id = "AZURE CLIENT ID"
azure_client_secret = "AZURE CLIENT SECRET"
azure_tenant = "YOURTENANT.onmicrosoft.com"

# Get Azure authenrtication token and set in the headers for later use

url = "https://login.microsoftonline.com/" + azure_tenant +  "/oauth2/v2.0/token"
data = {
    "grant_type": "client_credentials",
    "client_id": azure_client_id,
    "scope": "https://graph.microsoft.com/.default",
    "client_secret": azure_client_secret}
r = requests.post(url, data=data)
token = r.json().get("access_token")

headers = {
    "Content-Type" : "application\json",
    "Authorization": "Bearer {}".format(token)
}

# Get List Of Groups from Azure AD

url = "https://graph.microsoft.com/beta/groups"
r = requests.get(url, headers=headers)
result = r.json()
groups = result["value"]

# For each group get a list of the members

xmloutput = "<uid-message><type>update</type><payload><groups>"

for group in groups:
    print("-" * 120)
    print(group["displayName"] + " (" + group["id"] + ")")
    xmloutput = xmloutput + "<entry name=\"" + group["displayName"] + "\">"
    xmloutput = xmloutput + "<members>"
    url = "https://graph.microsoft.com/beta/groups/" + group["id"] + "/members"
    r = requests.get(url, headers=headers)
    result = r.json()
    users = result["value"]
    for user in users:
        print(" - " + user["userPrincipalName"])
        xmloutput = xmloutput + "<entry name=\"" + user["userPrincipalName"] + "\"/>"
    xmloutput = xmloutput + "</members>"
    xmloutput = xmloutput + "</entry>"
xmloutput = xmloutput + "</groups></payload></uid-message>"
print("-" * 120)

# Make API call to PANW Device

encoded = urllib.parse.quote(xmloutput, safe="")
url = "https://" + panw_hostname + "/api/?key=" + panw_apikey + "&type=user-id&cmd=" + encoded
r = requests.get(url, verify=False)



