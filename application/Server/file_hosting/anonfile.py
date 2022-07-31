import requests
import os
from lxml import html
import sys


class AnonFile:
    def UploadFile(self, file_name):
        file_data = {'file': open(file_name, 'rb')}
        file_url = 'https://api.anonfiles.com/upload'
        file_response = requests.post(file_url, files=file_data)
        file_response_json = file_response.json()
        return file_response_json['data']['file']['metadata']['id']


    def DownloadFile(self, file_url):
        link = str.replace(file_url, "\n", "")
        page = requests.get(link)
        tree = html.fromstring(page.content)
        dlink = tree.xpath('//a[@class="btn btn-primary btn-block"]/@href')
        fname = os.path.basename(dlink[0])

        with open(fname, "wb") as file:
            response = requests.get(dlink[0])
            file.write(response.content)
