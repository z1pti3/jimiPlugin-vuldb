from core import plugin, model

class _vuldb(plugin._plugin):
    version = 0.1

    def install(self):
        # Register models
        model.registerModel("vuldbGetVulnerability","_vuldbGetVulnerability","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetRecent","_vuldbGetRecent","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetUpdates","_vuldbGetUpdates","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetAdvisoryByDate","_vuldbGetAdvisoryByDate","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetCreatedByDate","_vuldbGetCreatedByDate","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetUpdatesByDate","_vuldbGetUpdatesByDate","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbSearch","_vuldbSearch","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbAdvancedSearch","_vuldbAdvancedSearch","_action","plugins.vuldb.models.action")
        model.registerModel("vuldbGetCollection","_vuldbGetCollection","_action","plugins.vuldb.models.action")
        return True

    def uninstall(self):
        # deregister models
        model.deregisterModel("vuldbGetVulnerability","_vuldbGetVulnerability","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetRecent","_vuldbGetRecent","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetUpdates","_vuldbGetUpdates","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetAdvisoryByDate","_vuldbGetAdvisoryByDate","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetCreatedByDate","_vuldbGetCreatedByDate","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetUpdatesByDate","_vuldbGetUpdatesByDate","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbSearch","_vuldbSearch","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbAdvancedSearch","_vuldbAdvancedSearch","_action","plugins.vuldb.models.action")
        model.deregisterModel("vuldbGetCollection","_vuldbGetCollection","_action","plugins.vuldb.models.action")
        return True

    def upgrade(self,LatestPluginVersion):
        pass
        #if self.version < 0.2:
