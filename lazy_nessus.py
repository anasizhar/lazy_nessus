import requests, json, time, urllib3, sys

"""
You need to put site name and ID in below dict format with key as site name and value as folder ID appearing in the URL of nessus folder. 
Lazy_nessus will use this key to rename the report. Like for example on the web interface, URL for your specific report will look like this:
https://127.0.0.1:8834/#/scans/reports/1316/hosts, put the number after /reprots/ in url and place in the site dict in this format: 

sites = {'Report_name_you_want':'1316'}
"""
sites = {
    'Site 1' : '727',
    'Site 2':'708',
    'Site 3':'707',
    'Site 4':'723',
    'Site 5':'719',
    'Site 6':'721',
    'Site 7' : '726',
    'Site 8' : '720',
    'Site 9' : '724',
    'Site 10' : '2073'

}

sleepPeriod = 5

if len(sys.argv) <= 3:
  print('Please give your arguments in this format: lazy_nessus.py <URL> <Username> <Password>')

elif sys.argv[1] == "-h" or sys.argv[1] == "--help":
  print('Please give your arguments in this format: lazy_nessus.py <URL> <Username> <Password>')
else:
  BaseURL=sys.argv[1]
  Username=sys.argv[2]
  Password=sys.argv[3]

  urllib3.disable_warnings()

  URL=BaseURL+"/session"
  TOKENPARAMS = {'username':Username, 'password':Password}
  r = requests.post(url = URL, data = TOKENPARAMS, verify = False)
  jsonData = r.json()
  token = str("token="+jsonData['token'])

  headers = {'X-Cookie': token, 'Content-type': 'application/json', 'Accept': 'text/plain'}
  t = requests.get(url = URL, headers=headers, verify = False)
  data = t.json()

  print("[+] Extracting Report ...\n")

  for site, folder in sites.items():
    URL = BaseURL+"/scans/"+folder+"/export"

    # In this case, we're asking for a:
    #   - HTML Export
    #   - With vulnerabilities greater than CVSS 4.0
    payload = {
      "format": "html",
      "chapters": "custom;vuln_by_host;remediations;vulnerabilities",
      "filter.0.quality": "gt",
      "filter.0.filter": "cvss_base_score",
      "filter.0.value": "4.00",
      "filter.search_type": "or",
      "reportContents": {
        "csvColumns": {},
        "vulnerabilitySections": {
          "synopsis": True,
          "description": True,
          "see_also": True,
          "solution": True,
          "risk_factor": True,
          "cvss3_base_score": True,
          "cvss3_temporal_score": True,
          "cvss_base_score": True,
          "cvss_temporal_score": True,
          "stig_severity": True,
          "references": True,
          "exploitable_with": True,
          "plugin_information": True,
          "plugin_output": True
        },
        "hostSections": {
          "scan_information": True,
          "host_information": True
        },
        "formattingOptions": {
          "page_breaks": True
        }
      },
      "extraFilters": {
        "host_ids": [],
        "plugin_ids": []
      }
    }
    # Pass the POST request in json format. Two items are returned, file and token
    jsonPayload = json.dumps(payload)
    r = requests.post(url = URL, headers=headers, data = jsonPayload, verify = False)
    jsonData = r.json()
    scanFile = str(jsonData['file'])
    scanToken = str(jsonData['token'])

    # Use the file just received and check to see if it's 'ready', otherwise sleep for sleepPeriod seconds and try again
    status = "loading"
    while status != 'ready':
        URL = BaseURL+"/scans/"+folder+"/export/"+scanFile+"/status"
        t = requests.get(url = URL, headers=headers, verify = False)
        data = t.json()
        if data['status'] == 'ready':
            status = 'ready'
        else:
            time.sleep(sleepPeriod)

    # Now that the report is ready, download
    URL = BaseURL+"/scans/"+folder+"/export/"+scanFile+"/download"
    d = requests.get(url = URL, headers=headers, verify = False)
    #Creating the file in "site.html" format 
    filename = site+".html"
    fh = open(filename,'w')
    fh.write(str(d.text))
    fh.close()
    print("[+] "+ site +" Report Extracted")

