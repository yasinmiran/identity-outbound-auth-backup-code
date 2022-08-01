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
package org.wso2.carbon.identity.application.authenticator.backupcode.constants;

/**
 * Backup code related constants.
 */
public class BackupCodeAuthenticatorConstants {

    public static final String BACKUP_CODE_AUTHENTICATOR_NAME = "backup-code-authenticator";
    public static final String BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME = "Backup Code";
    public static final String BACKUP_CODE_NUMERIC_CHAR_SET = "9245378016";
    public static final int DEFAULT_LENGTH_OF_BACKUP_CODE = 6;
    public static final int DEFAULT_NO_OF_BACKUP_CODES = 10;

    public static final String LENGTH_OF_BACKUP_CODE = "BackupCode.BackupCodeLength";
    public static final String REQUIRED_NO_OF_BACKUP_CODES = "BackupCode.BackupCodeSize";
    public static final String BACKUP_CODE = "BackupCode";
    public static final String SEND_TOKEN = "sendToken";
    public static final String ENABLE_BACKUP_CODE = "ENABLE_BACKUP_CODE";
    public static final String AUTHENTICATED_USER = "authenticatedUser";
    public static final String AUTHENTICATION = "authentication";
    public static final String BASIC = "basic";
    public static final String FEDARETOR = "federator";
    public static final String LOCAL_AUTHENTICATOR = "LOCAL";
    public static final String SUPER_TENANT_DOMAIN = "carbon.super";
    public static final String BACKUP_CODE_ERROR_PREFIX = "BCA";
    public static final String BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL = "BackupCodeAuthenticationEndpointURL";
    public static final String LOGIN_PAGE = "authenticationendpoint/login.do";
    public static final String ERROR_PAGE = "authenticationendpoint/backup_code_error.do";
    public static final String BACKUP_CODE_LOGIN_PAGE = "authenticationendpoint/backup_code.do";
    public static final String BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL = "BackupCodeAuthenticationEndpointErrorPage";
    public static final String IS_INITIAL_FEDERATED_USER_ATTEMPT = "isInitialFederationAttempt";
    public static final String CODE_MISMATCH = "codeMismatch";
    public static final String GET_PROPERTY_FROM_IDENTITY_CONFIG = "getPropertiesFromLocal";

    public enum ErrorMessages {

        ERROR_NO_USERNAME("60001", "Username cannot be empty"),
        INVALID_FEDERATED_AUTHENTICATOR("65001", "No IDP found with the name IDP: " + "%s in tenant: %s"),
        ERROR_NO_FEDERATED_USER("65002", "No federated user found"),
        INVALID_FEDERATED_USER_AUTHENTICATION("65003", "Can not handle federated user " +
                        "authentication with Backup Code as JIT Provision is not enabled for the IDP: in the tenant: %s"),
        ERROR_NO_AUTHENTICATED_USER("65004", "Can not find the authenticated user"),
        ERROR_UPDATING_BACKUP_CODES("65006",
                "Error occurred while updating unused backup codes for user: %s"),
        ERROR_TRIGGERING_EVENT("65007", "Error occurred while triggering event: %s for the user: %s"),
        ERROR_FIND_USER_REALM("65008", "Cannot find the user realm for the given tenant domain : %s"),
        ERROR_ACCESS_USER_REALM("65009",
                "Error occurred failed while trying to access userRealm of the user : %s"),
        ERROR_HASH_BACKUP_CODE("65010", "Error occurred while hashing backup codes"),
        ERROR_GETTING_CONFIG("65011", "Error occurred while getting backup code configurations"),
        ERROR_GETTING_THE_USER_REALM("65012", "Error occurred while getting the user realm"),
        ERROR_GETTING_THE_USER_STORE_MANAGER("65013", "Error occurred while getting the user store manager"),
        ERROR_SETTING_USER_CLAIM_VALUES("65014", "Error occurred while setting user claim values");

        private final String code;
        private final String message;

        ErrorMessages(String code, String message) {

            this.code = code;
            this.message = message;
        }

        public String getCode() {

            return BACKUP_CODE_ERROR_PREFIX + "-" + code;
        }

        public String getMessage() {

            return message;
        }

        @Override
        public String toString() {

            return code + " - " + message;
        }
    }

    /**
     * User claim related constants.
     */
    public static class Claims {

        public static final String BACKUP_CODES_CLAIM = "http://wso2.org/claims/identity/backupCodes";
        public static final String BACKUP_CODES_ENABLED_CLAIM = "http://wso2.org/claims/identity/backupCodeEnabled";
        public static final String BACKUP_CODE_FAILED_ATTEMPTS_CLAIM =
                "http://wso2.org/claims/identity/failedBackupCodeAttempts";
    }
}
