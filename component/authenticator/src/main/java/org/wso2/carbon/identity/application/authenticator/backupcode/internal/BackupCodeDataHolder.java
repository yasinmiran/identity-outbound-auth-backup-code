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

import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.idp.mgt.IdpManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ConfigurationContextService;

/**
 * Data holder class for backup code authenticator.
 */
public class BackupCodeDataHolder {

    private static RealmService realmService;
    private static ConfigurationContextService configurationContextService;
    private static IdentityEventService identityEventService;
    private static AccountLockService accountLockService;
    private static IdentityGovernanceService identityGovernanceService;
    private static IdpManager idpManager;

    /**
     * Returns the Realm service.
     *
     * @return Realm service
     */
    public static RealmService getRealmService() {

        return realmService;
    }

    /**
     * Sets the Realm service.
     *
     * @param realmService Realm service
     */
    public static void setRealmService(RealmService realmService) {

        BackupCodeDataHolder.realmService = realmService;
    }

    /**
     * Returns the ConfigurationContext service.
     *
     * @return ConfigurationContext service
     */
    public static ConfigurationContextService getConfigurationContextService() {

        return configurationContextService;
    }

    /**
     * Sets the ConfigurationContext service.
     *
     * @param configurationContextService The ConfigurationContextService
     */
    public static void setConfigurationContextService(ConfigurationContextService configurationContextService) {

        BackupCodeDataHolder.configurationContextService = configurationContextService;
    }

    public static IdentityEventService getIdentityEventService() {

        return identityEventService;
    }

    public static void setIdentityEventService(IdentityEventService identityEventService) {

        BackupCodeDataHolder.identityEventService = identityEventService;
    }

    /**
     * Get the IdentityGovernance service.
     *
     * @return IdentityGovernance service.
     */
    public static IdentityGovernanceService getIdentityGovernanceService() {

        if (identityGovernanceService == null) {
            throw new RuntimeException("IdentityGovernanceService not available. Component is not started properly.");
        }
        return identityGovernanceService;
    }

    /**
     * Set the IdentityGovernance service.
     *
     * @param identityGovernanceService The IdentityGovernance service.
     */
    public static void setIdentityGovernanceService(IdentityGovernanceService identityGovernanceService) {

        BackupCodeDataHolder.identityGovernanceService = identityGovernanceService;
    }

    /**
     * Get the AccountLock service.
     *
     * @return AccountLock service.
     */
    public static AccountLockService getAccountLockService() {

        return accountLockService;
    }

    /**
     * Set the AccountLock service.
     *
     * @param accountLockService The AccountLock service.
     */
    public static void setAccountLockService(AccountLockService accountLockService) {

        BackupCodeDataHolder.accountLockService = accountLockService;
    }

    /**
     * Set IdpManager.
     *
     * @param idpManager IdpManager.
     */
    public static void setIdpManager(IdpManager idpManager) {

        BackupCodeDataHolder.idpManager = idpManager;
    }

    /**
     * Get IdpManager.
     *
     * @return IdpManager.
     */
    public static IdpManager getIdpManager() {

        if (idpManager == null) {
            throw new RuntimeException("IdpManager not available. Component is not started properly.");
        }
        return idpManager;
    }

}
