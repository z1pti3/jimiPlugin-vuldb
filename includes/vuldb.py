import requests
import json
import time
from pathlib import Path

class _vuldb():
    url = "https://vuldb.com/?api"

    def __init__(self, apiToken, ca=None, requestTimeout=30):
        self.requestTimeout = requestTimeout
        self.apiToken = apiToken
        self.headers = {
            "X-VulDB-ApiKey" : "{0}".format(self.apiToken)
        }
        if ca:
            self.ca = Path(ca)
        else:
            self.ca = None

    def apiCall(self,methord="GET",data=None):
        kwargs={}
        kwargs["timeout"] = self.requestTimeout
        kwargs["headers"] = self.headers
        if self.ca:
            kwargs["verify"] = self.ca
        try:
            url = "{0}".format(self.url)
            if methord == "GET":
                response = requests.get(url, **kwargs)
            elif methord == "POST":
                kwargs["data"] = data
                response = requests.post(url, **kwargs)
            elif methord == "DELETE":
                response = requests.delete(url, **kwargs)
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            return 0, "Connection Timeout"
        if response.status_code == 200 or response.status_code == 202:
            return json.loads(response.text), response.status_code
        return None, response.status_code

    def getVulnerability(self,id,fields=[],details=0,limit=None,sort=None):
        if type(id) is list:
            data = { "id" : ",".join(id), "details" : details }
        else:
            data = { "id" : id, "details" : details }
        if fields:
            data["fields"] = fields
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    def getRecent(self,amount=10,limit=None,sort=None):
        data = { "recent" : amount }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    def getUpdates(self,amount=10,limit=None,sort=None):
        data = { "updates" : amount }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    # date / epoch
    def getAdvisoryByDate(self,value="20180211",limit=None,sort=None):
        data = { "advisory_date" : value }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    # date / epoch
    def getCreatedByDate(self,value="20180211",limit=None,sort=None):
        data = { "entry_timestamp_create" : value }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    # date / epoch
    def getUpdatesByDate(self,value="20180211",limit=None,sort=None):
        data = { "entry_timestamp_change" : value }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    def search(self,query,details=0,limit=None,sort=None):
        data = { "search" : query, "details" : details }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    def advancedSearch(self,query,details=0,limit=None,sort=None):
        data = { "advancedsearch" : query, "details" : details }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

    def getCollections(self,collection,details=0,limit=None,sort=None):
        data = { "collection" : collection, "details" : details }
        if limit:
            data["limit"] = limit
        if sort:
            data["sort"] = sort
        response, statusCode = self.apiCall(methord="POST",data=data)
        return response

