/*
 * Copyright (c) 2022, WSO2 Inc. (http://www.wso2.com) All Rights Reserved.
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
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.application.authenticator.backupcode;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeClientException;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_ENABLED_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_ACCESS_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_FIND_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_USERNAME;

/**
 * Handle backup code API related functionalities.
 */
public class BackupCodeAPIHandler {

    /**
     * Returns the number of backup codes remaining for the given user.
     *
     * @param username Username of the user.
     * @return the number of backup codes remaining for the given user.
     * @throws BackupCodeException If an error occurred while getting backup codes.
     */
    public static int getRemainingBackupCodesCount(String username) throws BackupCodeException {

        List<String> remainingBackupCodesList = new ArrayList<>();
        try {
            if (StringUtils.isNotBlank(username)) {
                UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
                if (userRealm != null) {
                    String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                    Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                            .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
                    String backupCodes = userClaimValues.get(BACKUP_CODES_CLAIM);
                    if (StringUtils.isNotBlank(backupCodes)) {
                        remainingBackupCodesList = new ArrayList<>(Arrays.asList(backupCodes.split(",")));
                    }
                }
                return remainingBackupCodesList.size();
            }
            throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(),
                    String.format(ERROR_NO_USERNAME.getMessage()));
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
    }

    /**
     * Generate backup codes for the user.
     *
     * @param username Username of the user.
     * @return list of generated backup codes for the user.
     * @throws BackupCodeException If an error occurred while generating the backup codes.
     */
    public static List<String> generateBackupCodes(String username) throws BackupCodeException {

        List<String> generatedBackupCodes = new ArrayList<>();
        try {
            if (StringUtils.isNotBlank(username)) {
                UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
                String tenantDomain = MultitenantUtils.getTenantDomain(username);
                if (userRealm != null) {
                    generatedBackupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
                    ArrayList<String> hashedBackupCodesList = new ArrayList<>();
                    for (String backupCode : generatedBackupCodes) {
                        hashedBackupCodesList.add(BackupCodeUtil.generateHashBackupCode(backupCode));
                    }
                    updateUserBackupCodes(username, String.join(",", hashedBackupCodesList),
                            "true");
                }
            } else {
                throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(),
                        String.format(ERROR_NO_USERNAME.getMessage()));
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
        return generatedBackupCodes;
    }

    /**
     * Remove the stored remaining backup codes for the user.
     *
     * @param username username of the user.
     * @return true if successfully resetting the claims, false otherwise.
     * @throws BackupCodeException when user realm is null for given tenant domain.
     */
    public static boolean deleteBackupCodes(String username) throws BackupCodeException {

        if (StringUtils.isNotBlank(username)) {
            updateUserBackupCodes(username, "", "false");
            return true;
        }
        throw new BackupCodeClientException(ERROR_NO_USERNAME.getCode(), String.format(ERROR_NO_USERNAME.getMessage()));
    }

    /**
     * Update user claims for the user.
     *
     * @param username username of the user.
     * @throws BackupCodeException when user realm is null for given tenant domain or when an error occurred while
     * updating user claims.
     */
    private static void updateUserBackupCodes(String username, String backupCodes, String isBackupCodesEnabled)
            throws BackupCodeException{

        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            Map<String, String> claims = new HashMap<>();
            if (userRealm != null) {
                claims.put(BACKUP_CODES_CLAIM, backupCodes);
                claims.put(BACKUP_CODES_ENABLED_CLAIM, isBackupCodesEnabled);
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);
            } else {
                throw new BackupCodeException(ERROR_FIND_USER_REALM.getCode(),
                        String.format(ERROR_FIND_USER_REALM.getMessage(), MultitenantUtils.getTenantDomain(username)));
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
    }
}
