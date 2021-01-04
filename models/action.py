from core.models import action
from core import auth, db, helpers

from plugins.vuldb.includes import vuldb

class _vuldbGetVulnerability(action._action):
    apiToken = str()
    vuldbID = str()
    limit = int()
    sort = str()
    fields = list()
    details = bool()

    def run(self,data,persistentData,actionResult):
        vuldbID = helpers.evalString(self.vuldbID,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        fields = helpers.evalList(self.fields,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        details = 0
        if self.details:
            details = 1

        result = vuldb._vuldb(apiToken).getVulnerability(vuldbID,fields,details,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetVulnerability,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetRecent(action._action):
    apiToken = str()
    amount = 10
    limit = int()
    sort = str()

    def run(self,data,persistentData,actionResult):
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        result = vuldb._vuldb(apiToken).getRecent(self.amount,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetRecent,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetUpdates(action._action):
    apiToken = str()
    amount = 10
    limit = int()
    sort = str()

    def run(self,data,persistentData,actionResult):
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        result = vuldb._vuldb(apiToken).getUpdates(self.amount,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetUpdates,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetAdvisoryByDate(action._action):
    apiToken = str()
    value = str()
    limit = int()
    sort = str()

    def run(self,data,persistentData,actionResult):
        value = helpers.evalString(self.value,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        result = vuldb._vuldb(apiToken).getAdvisoryByDate(value,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetAdvisoryByDate,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetCreatedByDate(action._action):
    apiToken = str()
    value = str()
    limit = int()
    sort = str()

    def run(self,data,persistentData,actionResult):
        value = helpers.evalString(self.value,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        result = vuldb._vuldb(apiToken).getCreatedByDate(value,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetCreatedByDate,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetUpdatesByDate(action._action):
    apiToken = str()
    value = str()
    limit = int()
    sort = str()

    def run(self,data,persistentData,actionResult):
        value = helpers.evalString(self.value,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        result = vuldb._vuldb(apiToken).getUpdatesByDate(value,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetUpdatesByDate,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbSearch(action._action):
    apiToken = str()
    searchQuery = str()
    limit = int()
    sort = str()
    details = bool()

    def run(self,data,persistentData,actionResult):
        searchQuery = helpers.evalString(self.searchQuery,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        details = 0
        if self.details:
            details = 1

        result = vuldb._vuldb(apiToken).search(searchQuery,details,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbSearch,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbAdvancedSearch(action._action):
    apiToken = str()
    searchQuery = str()
    limit = int()
    sort = str()
    details = bool()

    def run(self,data,persistentData,actionResult):
        searchQuery = helpers.evalString(self.searchQuery,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        details = 0
        if self.details:
            details = 1

        result = vuldb._vuldb(apiToken).advancedSearch(searchQuery,details,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbAdvancedSearch,self).setAttribute(attr,value,sessionData=sessionData)

class _vuldbGetCollection(action._action):
    apiToken = str()
    collection = str()
    limit = int()
    sort = str()
    details = bool()

    def run(self,data,persistentData,actionResult):
        collection = helpers.evalString(self.collection,{"data" : data})
        sort = helpers.evalString(self.sort,{"data" : data})
        apiToken = auth.getPasswordFromENC(self.apiToken)

        limit = None
        if self.limit > 0:
            limit = self.limit

        details = 0
        if self.details:
            details = 1

        result = vuldb._vuldb(apiToken).getCollections(collection,details,limit,sort)

        if result:
            actionResult["result"] = True
            actionResult["rc"] = 0
            actionResult["uuid"] = result
        else:
            actionResult["result"] = False
            actionResult["rc"] = 404
            actionResult["msg"] = "Failed to get a valid response from vuldb API"
        return actionResult 

    def setAttribute(self,attr,value,sessionData=None):
        if attr == "apiToken" and not value.startswith("ENC "):
            if db.fieldACLAccess(sessionData,self.acl,attr,accessType="write"):
                self.apiToken = "ENC {0}".format(auth.getENCFromPassword(value))
                return True
            return False
        return super(_vuldbGetCollection,self).setAttribute(attr,value,sessionData=sessionData)