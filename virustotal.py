import requests
import json
from config import Config

apikey = Config.VIRUSTOTAL_API


class virus():
    def __init__(self, file_path):
        self.path = file_path
        self.res = True

    def smallfiles(self):
        path = self.path
        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        name = path.split('/')[-1]
        params = {'apikey': apikey}

        files = {'file': (name, open(path, 'rb'))}

        response = requests.post(url, files=files, params=params)
        if response == False:
            self.res = False
            return

        self.sha1 = (response.json()['sha1'])
        print(response.json()['verbose_msg'])
        self.verbose = response.json()['verbose_msg']

    def large_files(self):
        self.large_files_upload()
        self.large_file_analyse()

    def large_files_upload(self):
        path = self.path

        url = 'https://www.virustotal.com/api/v3/files/upload_url'

        headers_get = {
            "Accept": "application/json",
            "x-apikey": apikey
        }

        headers_post = {
            "x-apikey": apikey
        }

        response = requests.get(url, headers=headers_get)
        if response == False:
            self.res = False
            return
        upload_url_json = response.json()
        upload_url = upload_url_json['data']
        print('upload url is', upload_url)
        print(path)
        files = {'file': (path, open(path, 'rb'))}
        response = requests.post(upload_url, files=files, headers=headers_post)
        print(response.text)
        self.id = response.json()["data"]["id"]

    def large_file_analyse(self):
        api_url = f'https://www.virustotal.com/api/v3/analyses/{self.id}'
        headers = {
            "Accept": "application/json",
            "x-apikey": apikey
        }
        response = requests.get(api_url, headers=headers)
        if response == False:
            self.res = False
            return

        print(response.json())
        self.sha1 = response.json()["meta"]["file_info"]["sha1"]

    def get_report(self):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'

        params = {'apikey': apikey, 'resource': self.sha1, 'allinfo': 'false'}

        response = requests.get(url, params=params)
        try:
            self.report = response.json()['scans']
            self.link = response.json()['permalink']
        except Exception as e:
            self.report = e
        print(response.json())

