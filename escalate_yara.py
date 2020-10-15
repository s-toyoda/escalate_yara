# -*- coding: utf-8 -*-
import sys
cve_name = ""
for tmp in sys.argv:
    if "TrendMicroDsFileSHA1" in tmp:
        p_list = tmp.split(";")
        for param in p_list:
            if param.split("=")[0] == "TrendMicroDsFileSHA1":
                file_sha1 = param.split("=")[1].replace("]", "").replace(",", "").replace("\"", "")
                print file_sha1

yara_text = "import \"hash\"\n\nrule Eicar_rule{\ncondition:\nhash.sha1(0,filesize) == \"" + file_sha1 + "\"\n}"
path_file = "./sha1_rule.yara"
with open(path_file, mode='w') as f:
    f.write(yara_text)

import base64
import jwt
import hashlib
import time
import json
import requests

def create_checksum(http_method, raw_url, headers, request_body):
    string_to_hash = http_method.upper() + '|' + raw_url.lower() + '|' + headers + '|' + request_body
    base64_string = base64.b64encode(hashlib.sha256(str.encode(string_to_hash)).digest()).decode('utf-8')
    return base64_string

def create_jwt_token(appication_id, api_key, http_method, raw_url, headers, request_body,
                     iat=time.time(), algorithm='HS256', version='V1'):
    checksum = create_checksum(http_method, raw_url, headers, request_body)
    payload = {'appid': appication_id,
               'iat': iat,
               'version': version,
               'checksum': checksum}
    token = jwt.encode(payload, api_key, algorithm=algorithm).decode('utf-8')
    return token

file_name = path_file
# Encoding the YARA file to base 64.
print('Encoding the YARA file to base 64.')
with open(file_name, "rb") as f:
    file_string_base64 = base64.b64encode(f.read())

# Upload the YARA file to the Apex Central server.
print('Upload the YARA file to the Apex Central server.')
productAgentAPIPath = '/WebApp/IOCBackend/YARAResource/File'
canonicalRequestHeaders = ''
useQueryString = ''
 
payload = {
  "param":
  [
    {
      "FileName": file_name,
      "FileContentBase64":file_string_base64.decode()
    }
  ]
}
useRequestBody = json.dumps(payload) 

use_application_id = "【あなたの環境のアプリケーションID】"
use_api_key = "【あなたの環境のAPIキー】"
use_url_base = "【あなたの環境のApexOneSaaSのURL】"

jwt_token = create_jwt_token(use_application_id, use_api_key, 'POST',
                              productAgentAPIPath + useQueryString,
                              canonicalRequestHeaders, useRequestBody, iat=time.time())
 
headers = {'Authorization': 'Bearer ' + jwt_token , 'Content-Type': 'application/json;charset=utf-8'}

r = requests.post(use_url_base + productAgentAPIPath + useQueryString, headers=headers, data=useRequestBody, verify=False)

if r.status_code !=200 and r.status_code!=201:
  print('Not successful, please handle your error')
print(r.status_code)
print(json.dumps(r.json(), indent=4))
file_hashID = r.json()["Data"]["UploadedResultInfoList"][0]["FileHashID"]
print('file hashID:',file_hashID)
