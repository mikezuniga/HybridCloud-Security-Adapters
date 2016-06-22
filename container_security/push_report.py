# Copyright 2016 Symantec, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
"""
.. Security Monkey Data Pusher
    :platform: Unix
.. author:: Su Zhang
"""

import calendar
import fileinput
import json
from json import JSONEncoder
import pprint
from random import randint
import requests
import sys
import time

from security_monkey.datastore import Account, Item, ItemRevision, ItemAudit, Technology, ItemComment
from security_monkey import db
from security_monkey.auditor import Auditor

# configurable stuff: account_id, technology_id
# a configuration file config.txt should reside within the same folder as this code

if len(sys.argv)<3:
    print 'image id and severity need to be provided'
    exit()

# Map vulnerability risk into metrics
risk_score = {'Unknown':1, 'Negligible': 1, 'Low': 3, 'Medium': 5, 'High': 7, 'Critical': 9, 'Defcon1': 10}

image_id = sys.argv[1]
score = risk_score[sys.argv[2]]
region = 'universal'
issue = 'Vulnerable Docker Image'
notes = 'Report of Docker Image Vulnerablity Scan'
tech_id = $TECH_ID
account_id = $ACCOUNT_ID
item_name = 'Docker Image Vulnerability Scan'
item_id=int(time.time())
latest_revision_id=int(time.time())

# current content is stored within ItemRevision config as a json format
# this part can be replaced by json object returned by congress API call
# e.g. curl -X GET localhost:1789/v1/policies/<classification-id>/tables/error/rows
# Policy meta data should be put into the item comment, note or text
# violation info will be put into the config json object
 
# in order to have this json object displayed correctly for external populated 
# data objects, the data type of config in itemrevision (securitymonkey/datastore.py) should be changed to 
# string(512) from Json.

# scanning reports are named based on their image_id
data_file =  open(image_id+'.txt')
report = json.load(data_file)

# Setup audit items and attach it to an item to be displayed
# Be careful to associate latest revision id correctly for item and itemrevision.
item = Item(region=region, name=item_name, tech_id=tech_id, account_id=account_id, id=item_id, latest_revision_id=latest_revision_id)
db.session.add(item)

auditItem = ItemAudit(score=score, issue=issue, notes=notes, justified=False, item_id=item_id)
db.session.add(auditItem)

revision = ItemRevision(active=True, item_id=item_id, id=latest_revision_id, config=json.dumps(report))
db.session.add(revision)
db.session.commit()
