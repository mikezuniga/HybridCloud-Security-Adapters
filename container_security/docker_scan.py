# Copyright 2016 Symantec Corporation
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.

"""
.. docker scanner adapter 
    :platform: Unix
.. author:: Su Zhang
"""

from collections import OrderedDict
from docker import Client
import json
import pdb
from pprint import pprint
import requests
import tarfile,sys

local_docker_server = 'unix://var/run/docker.sock'

# the base url + port of your docker registry
registry_base = ''

# where you want to pull docker images from
docker_regirstry = ''

# specify proxy here if it is needed in your environment
proxies = {
  'http': '',
  'https': '',
}

# priority order for vulnerabilities
priorities = {
    'Unknown': 0,
    'Negligible': 1,
    'Low': 2,
    'Medium': 3,
    'High': 4,
    'Critical': 5,
    'Defcon1': 6,
}

if len(sys.argv) < 4:
    print "usage: python clean_docker_scan.py MINIMUM_SEVERITY SCANNER_URL STORAGE_URL"
    exit(1)

specified_severity = sys.argv[1]
scanner_url = sys.argv[2]
storage_url = sys.argv[3]

def pull_image(image_location):
    cli = Client(base_url=local_docker_server)
    for line in cli.pull(image_location, stream=True):
        print(json.dumps(json.loads(line), indent=4))

def pull_images():
    images = list_remote_images (docker_registry = docker_regirstry)
    for image in images:
        image_loc = registry_base + image['name']
        pull_image(image_loc)
        print image_loc

def list_local_images():
    cli = Client(base_url=local_docker_server)
    resp = cli.images()
    return resp

def list_remote_images (docker_registry):
    cli = Client(base_url=local_docker_server)
    image_list = cli.search(docker_registry)
    return image_list

# /var/www/html/images/ base storage URL is used here in order to conform apache web service path.
# this is based on the assumption that this script will be running on the same host storing decomposed (decompressed) images
def save_image(image_loc, image_id):
    cli = Client(base_url=local_docker_server)
    image = cli.get_image(image_loc)
    image_tar = open('/var/www/html/images/'+image_id+'.tar','w')
    image_tar.write(image.data)
    image_tar.close()

# save all images pulled from target repo
def save_images():
    local_imgs = list_local_images()
    for image in local_imgs:
        image_loc=image['RepoTags'][0]
        image_id=image['Id'][7:19]
        save_image(image_loc, image_id)

# uncompress tar balls for docker images/layers
def decompose_images():
    local_imgs = list_local_images()
    for image in local_imgs:
        image_id=image['Id'][7:19]
        decompose_image(image_id)

def decompose_image(image_id):
    tar = tarfile.open('/var/www/html/images/'+image_id+'.tar')
    tar.extractall(path='/var/www/html/images/'+image_id, members=None)
    tar.close

def post_layer(url, name, path, parent):
    data={"Layer":{"Name" : name, "Path" : path, "ParentName" : parent, "Format" : "Docker"}}
    resp = requests.post(url, json=data)

'''
post body
{
  "Layer": {
    "Name": "layer_name",
    "Path": "layer storage location",
    "ParentName": "",
    "Format": "Docker"
  }
}

'''

def compare_priority(s1, s2):
    if s2 not in priorities or priorities[s1] -priorities [s2]>= 0:
        return True
    return False


def get_layer(host, layer, image_id):
    url = host+"/"+layer+"?vulnerabilities"
    resp = requests.get(url)
    data = json.loads(resp._content, object_pairs_hook=OrderedDict)
    report = [{'image_id': image_id}]

    if not 'Features' in data['Layer']:
        return 

    for feature in data['Layer']['Features']:
        if not 'Vulnerabilities' in feature:
            continue

        for vuln in feature['Vulnerabilities']:
            if compare_priority(vuln['Severity'], specified_severity):
                report.append(vuln)
    print json.dumps(report, indent=4, separators=(',', ': '))
    f =  open(image_id+'.txt','w')
    f.write(json.dumps(report, indent=4, separators=(',', ': ')))
    f.close

def analyze_meta(fname):
    with open(fname) as data_file:
        data = json.load(data_file)
    layers=data[0]['Layers']
    return layers

# parse the metadata and then post layers one by one in the right order
# location refers to layer storage url
# server url needs to have all url protocol, port, web function included
# for example: http://100.73.151.139:6060/v1/layers/

def post_layers(fname, scanner_url, location):
    layers=analyze_meta(fname)
    parent = ''
    for layer in layers:
        layer_id = layer.split('/')[0]
        path = location + layer
        post_layer(scanner_url, layer_id, path, parent) # post layers one by one in the right order
        parent = layer_id

def get_last_layer(fname, host, image_id):
    layers=analyze_meta(fname)
    last_layer = layers[-1]
    last_layer_id = last_layer.split('/')[0]
    get_layer(host, last_layer_id, image_id)

def pulling_checking():
    pull_images()
    save_images()

def evaluate_image(image_id, clair_url, image_loc, storage_url):
    save_image(image_loc, image_id)
    decompose_image(image_id)
    post_layers("/var/www/html/images/"+image_id+"/manifest.json", clair_url, storage_url+image_id+'/')
    get_last_layer("/var/www/html/images/"+image_id+"/manifest.json", clair_url, image_id)

def evaluate_images(scanner_url, storage_url):
    local_imgs = list_local_images()
    for image in local_imgs:
        image_loc=image['RepoTags'][0]
        image_id=image['Id'][7:19]
        evaluate_image(image_id, scanner_url, image_loc, storage_url)

# pulling_checking()
# evaluate_images("http://100.73.151.139:6060/v1/layers", "http://100.73.151.139/images/")
# 2 steps are needed for container image scanning. first step is to process images (identify images, pull images, convert image format)
# the second step is to scan images (identify right order for image layers, post image in right order to the scanner, get the topmost layer report and finergrain the report to display the most relevant information)

# Step 1
# pulling_checking()

# Step 2
# evaluate_images(scanner_url, storage_url)
