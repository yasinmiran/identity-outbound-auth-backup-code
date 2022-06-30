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
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_ENABLED_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.*;

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
            String tenantAwareUsername;
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            if (userRealm != null) {
                tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
                String backupCodes = userClaimValues.get(BACKUP_CODES_CLAIM);
                if (backupCodes != null || StringUtils.isNotBlank(backupCodes)) {
                    remainingBackupCodesList = new ArrayList<>(Arrays.asList(backupCodes.split(",")));
                }
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
        return remainingBackupCodesList.size();
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
        String tenantDomain;
        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            tenantDomain = MultitenantUtils.getTenantDomain(username);
            if (userRealm != null) {
                generatedBackupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
        return generatedBackupCodes;
    }

    /**
     * Update backup code claims and return backup codes for the user.
     *
     * @param generatedBackupCodes Generated backup codes as a comma separated string.
     * @param username Username of the user.
     * @return Backup codes for the user.
     * @throws BackupCodeException If an error occurred while updating backup codes.
     */
    public static List<String> updateBackupCodes(List<String> generatedBackupCodes, String username)
            throws BackupCodeException {

        String tenantAwareUsername;
        ArrayList<String> hashedBackupCodesList = new ArrayList<>();
        Map<String, String> claims = new HashMap<>();

        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            if (userRealm != null) {
                for (String backupCode : generatedBackupCodes) {
                    hashedBackupCodesList.add(BackupCodeUtil.generateHashString(backupCode));
                }
                claims.put(BACKUP_CODES_CLAIM, String.join(",", hashedBackupCodesList));
                claims.put(BACKUP_CODES_ENABLED_CLAIM, "true");
                tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
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

        try {
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            Map<String, String> claims = new HashMap<>();
            if (userRealm != null) {
                claims.put(BACKUP_CODES_CLAIM, "");
                claims.put(BACKUP_CODES_ENABLED_CLAIM, "false");
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);
                return true;
            } else {
                throw new BackupCodeException(ERROR_CODE_ERROR_FIND_USER_REALM.getCode(),
                        String.format(ERROR_CODE_ERROR_FIND_USER_REALM.getMessage(),
                                MultitenantUtils.getTenantDomain(username)));
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
    }
}