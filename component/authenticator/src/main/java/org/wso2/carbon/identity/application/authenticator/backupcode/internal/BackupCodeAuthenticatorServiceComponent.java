/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.backupcode.internal;

import org.osgi.framework.BundleContext;
import org.wso2.carbon.identity.application.authenticator.backupcode.BackupCodeAuthenticator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.backupcode.connector.BackupCodeAuthenticatorConfigImpl;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

import java.util.Hashtable;

/**
 * Backup code service component class.
 */
@Component(name = "identity.application.authenticator.backup.code.component", immediate = true)
public class BackupCodeAuthenticatorServiceComponent {

    private static final Log log = LogFactory.getLog(BackupCodeAuthenticatorServiceComponent.class);

    /**
     * This method is to register the backup code authenticator service.
     *
     * @param ctxt The Component Context
     */
    protected void activate(ComponentContext ctxt) {

        try {
            BackupCodeAuthenticator backupCodeAuth = new BackupCodeAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            BundleContext bundleContext = ctxt.getBundleContext();
            bundleContext.registerService(IdentityConnectorConfig.class.getName(),
                    new BackupCodeAuthenticatorConfigImpl(), null);
            bundleContext.registerService(ApplicationAuthenticator.class.getName(), backupCodeAuth, props);

            if (log.isDebugEnabled()) {
                log.debug("BackupCodeAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("Error while activating the backup code authenticator", e);
        }
    }

    /**
     * This method is to deactivate the backup code authenticator service.
     *
     * @param ctxt The Component Context
     */
    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("BackupCodeAuthenticator bundle is deactivated");
        }
    }

    /**
     * This method is used to set the Configuration Context Service.
     *
     * @param configurationContextService The Configuration Context which needs to set
     */
    @Reference(name = "ConfigurationContextService", service = ConfigurationContextService.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetConfigurationContextService")
    protected void setConfigurationContextService(ConfigurationContextService configurationContextService) {

        BackupCodeDataHolder.setConfigurationContextService(configurationContextService);
    }

    /**
     * This method is used to unset the Configuration Context Service.
     *
     * @param configurationContextService The Configuration Context which needs to unset
     */
    protected void unsetConfigurationContextService(ConfigurationContextService configurationContextService) {

        BackupCodeDataHolder.setConfigurationContextService(null);
    }

    /**
     * This method is used to set the Realm Service.
     *
     * @param realmService The Realm Service which needs to set
     */
    @Reference(name = "RealmService", service = RealmService.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        BackupCodeDataHolder.setRealmService(realmService);
    }

    /**
     * This method is used to unset the Realm Service.
     *
     * @param realmService The Realm Service which needs to unset
     */
    protected void unsetRealmService(RealmService realmService) {

        BackupCodeDataHolder.setRealmService(null);
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {

        BackupCodeDataHolder.setIdentityEventService(null);
    }

    @Reference(name = "EventMgtService", service = IdentityEventService.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetIdentityEventService")
    protected void setIdentityEventService(IdentityEventService eventService) {

        BackupCodeDataHolder.setIdentityEventService(eventService);
    }

    @Reference(name = "IdentityGovernanceService", service = IdentityGovernanceService.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetIdentityGovernanceService")
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        BackupCodeDataHolder.setIdentityGovernanceService(idpManager);
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        BackupCodeDataHolder.setIdentityGovernanceService(null);
    }

    @Reference(name = "AccountLockService", service = AccountLockService.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetAccountLockService")
    protected void setAccountLockService(AccountLockService accountLockService) {

        BackupCodeDataHolder.setAccountLockService(accountLockService);
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        BackupCodeDataHolder.setAccountLockService(null);
    }

    @Reference(name = "org.wso2.carbon.idp.mgt.IdpManager", service = IdpManager.class, cardinality = ReferenceCardinality.MANDATORY, policy = ReferencePolicy.DYNAMIC, unbind = "unsetIdentityProviderManagementService")
    protected void setIdentityProviderManagementService(IdpManager idpManager) {

        BackupCodeDataHolder.setIdpManager(idpManager);
    }

    protected void unsetIdentityProviderManagementService(IdpManager idpManager) {

        BackupCodeDataHolder.setIdpManager(null);
    }
}
