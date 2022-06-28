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

import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_ENABLED_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_ACCESS_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_CODE_ERROR_FIND_USER_REALM;

/**
 * Handle backup code API related functionalities.
 */
public class BackupCodeAPIHandler {

    private static final String TOKEN_HASH_METHOD = "SHA-256";

    /**
     * Retrieve backup codes for the given username.
     *
     * @param username Username of the user.
     * @return List of backup code of the user.
     * @throws BackupCodeException If an error occurred while getting backup codes.
     */
    public static List<String> getBackupCodes(String username) throws BackupCodeException {

        String tenantAwareUsername;
        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            if (userRealm != null) {
                tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
                String backupCodes = userClaimValues.get(BACKUP_CODES_CLAIM);
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
        return Collections.emptyList();
    }

    /**
     * Generate backup codes for the user.
     *
     * @param username Username of the user.
     * @param refresh  Boolean type of refreshing the backup codes.
     * @return claims.
     * @throws BackupCodeException If an error occurred while generating the backup codes.
     */
    public static Map<String, String> generateBackupCodes(String username, boolean refresh) throws BackupCodeException {

        String generatedBackupCodes = "";
        String tenantAwareUsername;
        String tenantDomain;
        Map<String, String> claims = new HashMap<>();
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            tenantDomain = MultitenantUtils.getTenantDomain(username);

            if (userRealm != null) {
                generatedBackupCodes = BackupCodeUtil.generateBackupCodes(tenantDomain);
                claims.put(BACKUP_CODES_CLAIM, generatedBackupCodes);
                claims.put(BACKUP_CODES_ENABLED_CLAIM, "true");
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        }
        return claims;
    }

    /**
     * Update backup code claims and return backup codes for the user.
     *
     * @param claims   Map with the backup code claims.
     * @param username Username of the user.
     * @return Backup codes for the user.
     * @throws BackupCodeException If an error occurred while updating backup codes.
     */
    public static List<String> updateBackupCodes(Map<String, String> claims, String username)
            throws BackupCodeException {

        String tenantAwareUsername;
        String generatedBackupCodes = claims.get(BACKUP_CODES_CLAIM);
        ArrayList<String> backupCodesList = new ArrayList<>();
        ArrayList<String> hashedBackupCodesList = new ArrayList<>();

        if (StringUtils.isNotEmpty(generatedBackupCodes)) {
            backupCodesList = new ArrayList<>(Arrays.asList(generatedBackupCodes.split(",")));
        }

        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            if (userRealm != null) {
                for (String backupCode : backupCodesList) {
                    hashedBackupCodesList.add(generateHashString(backupCode));
                }
                claims.put(BACKUP_CODES_CLAIM, String.join(",", hashedBackupCodesList));
                tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
                userRealm.getUserStoreManager().setUserClaimValues(tenantAwareUsername, claims, null);
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_CODE_ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_CODE_ERROR_ACCESS_USER_REALM.getMessage(), username, e));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return backupCodesList;
    }

    /**
     * Remove the stored secret key and encoding method from user claim.
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


    /**
     * Generate the hash value of the given string.
     *
     * @param backupCode String value that needs to hash.
     * @return Hash value of the backupCode.
     * @throws NoSuchAlgorithmException If the algorithms is invalid.
     */
    static String generateHashString(String backupCode) throws NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance(TOKEN_HASH_METHOD);
        byte[] in = messageDigest.digest(backupCode.getBytes(StandardCharsets.UTF_8));
        final StringBuilder builder = new StringBuilder();
        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }
        return builder.toString();
    }
}
