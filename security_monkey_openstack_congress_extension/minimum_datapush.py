# Author: Su Zhang 
from random import randint
from security_monkey.datastore import Account, Item, ItemRevision, ItemAudit, Technology, ItemComment
from security_monkey import db
from security_monkey.auditor import Auditor
import json
from json import JSONEncoder
import requests
import calendar
import time

# configurable stuff: account_id, technology_id
# a configuration file config.txt should reside within the same folder as this code
conf = open('config.txt', 'r')
confs = conf.read().splitlines()
region = confs[0].split(':')[1]
host = confs[1].split(':')[1]
policy = confs[2].split(':')[1]
score = confs[3].split(':')[1]
issue = confs[4].split(':')[1]
notes = confs [5].split(':')[1]
tech_id= confs [6].split(':')[1]
account_id = confs [7].split(':')[1]
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

request = 'http://'+host+':1789/v1/policies/classification/tables/'+policy+'/rows'
result =  requests.get(request)

# tranform to plain text for better display
result_txt = result.text

# Setup account, this may be changed to account association later
# openstack_account = Account(active=True, third_party=False, name="openstack_congress", id=account_id)
# db.session.add(openstack_account)

# Setup security group technology. Similiar to account, once technology is setup, it does not need to be redefined.
# os_sg = Technology(name="openstack_SG", id=tech_id)
# db.session.add(os_sg)

# Setup audit items and attach it to an item to be displayed
# Be careful to associate latest revision id correctly for item and itemrevision.
item = Item(region=region, name='security group monitoring', tech_id=tech_id, account_id=account_id, id=item_id, latest_revision_id=latest_revision_id)

db.session.add(item)

auditItem = ItemAudit(score=score, issue=issue, notes=notes, justified=False, item_id=item_id)
db.session.add(auditItem)

revision = ItemRevision(active=True, item_id=item_id, id=latest_revision_id, config=result_txt)
db.session.add(revision)
db.session.commit()

