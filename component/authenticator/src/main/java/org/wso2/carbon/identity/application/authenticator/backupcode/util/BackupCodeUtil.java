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
package org.wso2.carbon.identity.application.authenticator.backupcode.util;

import org.apache.commons.lang.math.NumberUtils;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.owasp.encoder.Encode;
import org.wso2.carbon.extension.identity.helper.IdentityHelperConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.REQUIRED_NO_OF_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LENGTH_OF_BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_LOGIN_PAGE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_NUMERIC_CHAR_SET;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.DEFAULT_NO_OF_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.DEFAULT_LENGTH_OF_BACKUP_CODE;
import static org.apache.commons.lang.StringUtils.isNotBlank;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ERROR_PAGE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_GETTING_CONFIG;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_HASH_BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LOCAL_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LOGIN_PAGE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.SUPER_TENANT_DOMAIN;

/**
 * Util class for backup code authenticator.
 */
public class BackupCodeUtil {

    private static final Log log = LogFactory.getLog(BackupCodeUtil.class);
    private static final String TOKEN_HASH_METHOD = "SHA-256";

    /**
     * Returns AuthenticatedUser object from context.
     *
     * @param context AuthenticationContext.
     * @return AuthenticatedUser.
     */
    public static AuthenticatedUser getAuthenticatedUser(AuthenticationContext context) {

        AuthenticatedUser authenticatedUser = null;
        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap != null) {
            for (StepConfig stepConfig : stepConfigMap.values()) {
                AuthenticatedUser authenticatedUserInStepConfig = stepConfig.getAuthenticatedUser();
                if (stepConfig.isSubjectAttributeStep() && authenticatedUserInStepConfig != null) {
                    authenticatedUser = new AuthenticatedUser(stepConfig.getAuthenticatedUser());
                    break;
                }
            }
        }
        return authenticatedUser;
    }

    /**
     * Get realm service.
     *
     * @return Realm service.
     */
    public static RealmService getRealmService() {

        return BackupCodeDataHolder.getRealmService();
    }

    /**
     * Get the user realm of the logged-in user.
     *
     * @param username The Username.
     * @return The userRealm.
     * @throws UserStoreException If an error occurred while getting the user realm.
     */
    public static UserRealm getUserRealm(String username) throws UserStoreException {

        UserRealm userRealm = null;

        if (username != null) {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            int tenantId = IdentityTenantUtil.getTenantId(tenantDomain);
            RealmService realmService = getRealmService();
            userRealm = realmService.getTenantUserRealm(tenantId);
        }
        return userRealm;
    }

    /**
     * Get multi option URI query params.
     *
     * @param request HttpServletRequest.
     * @return Multi option URI query params.
     */
    public static String getMultiOptionURIQueryParam(HttpServletRequest request) {

        String multiOptionURI = "";
        if (request != null) {
            multiOptionURI = request.getParameter("multiOptionURI");
            multiOptionURI = multiOptionURI != null ? "&multiOptionURI=" + Encode.forUriComponent(multiOptionURI) : "";
        }
        return multiOptionURI;
    }

    /**
     * Get the loginPage from authentication.xml file or use the login page from constant file.
     *
     * @param context The AuthenticationContext.
     * @return The loginPage.
     * @throws AuthenticationFailedException If an error occurred while getting the login page.
     */
    public static String getBackupCodeLoginPage(AuthenticationContext context) throws AuthenticationFailedException {

        String loginPageFromConfig = getLoginPageFromXMLFile(context);
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantQualifiedURL(loginPageFromConfig, BACKUP_CODE_LOGIN_PAGE);
        }
        return loginPageFromConfig;
    }

    /**
     * Get the login page url from the application-authentication.xml file.
     *
     * @param context The AuthenticationContext.
     * @return The loginPage.
     */
    public static String getLoginPageFromXMLFile(AuthenticationContext context) {

        Object propertiesFromLocal = null;
        String loginPage;
        String tenantDomain = context.getTenantDomain();
        if (!SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || SUPER_TENANT_DOMAIN.equals(tenantDomain)) &&
                getBackupCodeParameters().containsKey(BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL)) {
            loginPage = getBackupCodeParameters().get(BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL);
        } else if ((context.getProperty(BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL)) != null) {
            loginPage = String.valueOf(context.getProperty(BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL));
        } else {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(LOGIN_PAGE, BACKUP_CODE_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default backup code login page: " + loginPage + " is used.");
            }
        }
        return loginPage;
    }

    /**
     * Get tenant qualified URL.
     *
     * @param urlFromConfig  Url from config.
     * @param defaultContext Context.
     * @return Tenant qualified URL.
     * @throws AuthenticationFailedException If an error occurred while getting the tenant qualified URL.
     */
    private static String getTenantQualifiedURL(String urlFromConfig, String defaultContext)
            throws AuthenticationFailedException {

        String context = null;
        try {
            if (isNotBlank(urlFromConfig)) {
                if (isURLRelative(urlFromConfig)) {
                    // Build tenant qualified URL using the context picked from config.
                    context = urlFromConfig;
                    return buildTenantQualifiedURL(context);
                }
                // The URL picked from configs was an absolute one, we don't have a way to tenant qualify it.
                return urlFromConfig;
            }
            // No URL defined in configs. Build tenant qualified URL using the default context.
            context = defaultContext;
            return buildTenantQualifiedURL(context);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building tenant qualified URL for context: " + context,
                    e);
        }
    }

    private static String buildTenantQualifiedURL(String contextPath) throws URLBuilderException {

        return ServiceURLBuilder.create().addPath(contextPath).build().getAbsolutePublicURL();
    }

    private static boolean isURLRelative(String contextFromConfig) throws URISyntaxException {

        return !new URI(contextFromConfig).isAbsolute();
    }

    /**
     * Get parameter values from local file.
     */
    private static Map<String, String> getBackupCodeParameters() {

        AuthenticatorConfig authConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(BACKUP_CODE_AUTHENTICATOR_NAME);
        return authConfig.getParameterMap();
    }

    /**
     * Get the errorPage from authentication.xml file or use the error page from constant file.
     *
     * @param context The AuthenticationContext.
     * @return The errorPage.
     * @throws AuthenticationFailedException If an error occurred while getting the error page.
     */
    public static String getBackupCodeErrorPage(AuthenticationContext context) throws AuthenticationFailedException {

        String errorUrlFromConfig = getErrorPageFromXMLFile(context);
        if (IdentityTenantUtil.isTenantQualifiedUrlsEnabled()) {
            return getTenantQualifiedURL(errorUrlFromConfig, ERROR_PAGE);
        }
        return errorUrlFromConfig;
    }

    /**
     * Get the error page url from the application-authentication.xml file.
     *
     * @param context The AuthenticationContext.
     * @return The errorPage.
     */
    public static String getErrorPageFromXMLFile(AuthenticationContext context) {

        Object propertiesFromLocal = null;
        String errorPage;
        String tenantDomain = context.getTenantDomain();
        if (!SUPER_TENANT_DOMAIN.equals(tenantDomain)) {
            propertiesFromLocal = context.getProperty(IdentityHelperConstants.GET_PROPERTY_FROM_REGISTRY);
        }
        if ((propertiesFromLocal != null || SUPER_TENANT_DOMAIN.equals(tenantDomain)) &&
                getBackupCodeParameters().containsKey(BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL)) {
            errorPage = getBackupCodeParameters().get(BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL);
        } else if ((context.getProperty(BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL)) != null) {
            errorPage = String.valueOf(context.getProperty(BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL));
        } else {
            errorPage =
                    ConfigurationFacade.getInstance().getAuthenticationEndpointURL().replace(LOGIN_PAGE, ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default error page: " + errorPage + " is used.");
            }
        }
        return errorPage;
    }

    /**
     * Check whether the user being authenticated via a local authenticator or not.
     *
     * @param context Authentication context.
     * @return Whether the user being authenticated via a local authenticator.
     */
    public static boolean isLocalUser(AuthenticationContext context) {

        Map<Integer, StepConfig> stepConfigMap = context.getSequenceConfig().getStepMap();
        if (stepConfigMap == null) {
            return false;
        }
        for (StepConfig stepConfig : stepConfigMap.values()) {
            if (stepConfig.getAuthenticatedUser() != null && stepConfig.isSubjectAttributeStep() &&
                    StringUtils.equals(LOCAL_AUTHENTICATOR, stepConfig.getAuthenticatedIdP())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Check whether the user account is locked.
     *
     * @param userName        The username of the user.
     * @param tenantDomain    The tenant domain.
     * @param userStoreDomain The user store domain.
     * @return True if the account is locked.
     * @throws AuthenticationFailedException Exception on authentication failure.
     */
    public static boolean isAccountLocked(String userName, String tenantDomain, String userStoreDomain)
            throws AuthenticationFailedException {

        try {
            return BackupCodeDataHolder.getAccountLockService()
                    .isAccountLocked(userName, tenantDomain, userStoreDomain);
        } catch (AccountLockServiceException e) {
            throw new AuthenticationFailedException(
                    String.format("Error while validating account lock status of user: %s.", userName), e);
        }
    }

    /**
     * Generate the backup codes according to the configuration parameters.
     *
     * @return Generated backup codes.
     * @throws BackupCodeException If an error occurred while generating backup codes.
     */
    public static List<String> generateBackupCodes(String tenantDomain) throws BackupCodeException {

        int lengthOfBackupCode = getLengthOfBackupCode(tenantDomain);
        int noOfBackupCodes = getRequiredNoOfBackupCodes(tenantDomain);
        List<String> backupCodes = new ArrayList<>();
        for (int i = 0; i < noOfBackupCodes; i++) {
            backupCodes.add(generateBackupCode(lengthOfBackupCode));
        }
        return backupCodes;
    }

    private static String generateBackupCode(int length) {

        char[] chars = BACKUP_CODE_NUMERIC_CHAR_SET.toCharArray();
        SecureRandom rnd = new SecureRandom();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(chars[rnd.nextInt(chars.length)]);
        }
        return sb.toString();
    }

    /**
     * Get length of a backup code.
     *
     * @param tenantDomain Tenant domain.
     * @return Backup code length.
     * @throws BackupCodeException If an error occurred while getting the backup code length.
     */
    private static int getLengthOfBackupCode(String tenantDomain) throws BackupCodeException {

        int lengthOfBackupCode = DEFAULT_LENGTH_OF_BACKUP_CODE;
        String configuredLengthOfBackupCode =
                BackupCodeUtil.getBackupCodeAuthenticatorConfig(LENGTH_OF_BACKUP_CODE, tenantDomain);
        if (NumberUtils.isNumber(configuredLengthOfBackupCode)) {
            lengthOfBackupCode = Integer.parseInt(configuredLengthOfBackupCode);
        }
        return lengthOfBackupCode;
    }

    /**
     * Get size of backup codes.
     *
     * @param tenantDomain Tenant domain.
     * @return Backup codes size.
     * @throws BackupCodeException If an error occurred while getting the backup codes size.
     */
    private static int getRequiredNoOfBackupCodes(String tenantDomain) throws BackupCodeException {

        int noOfRequiredBackupCodes = DEFAULT_NO_OF_BACKUP_CODES;
        String configuredRequiredNoOfBackupCodes =
                BackupCodeUtil.getBackupCodeAuthenticatorConfig(REQUIRED_NO_OF_BACKUP_CODES, tenantDomain);
        if (NumberUtils.isNumber(configuredRequiredNoOfBackupCodes)) {
            noOfRequiredBackupCodes = Integer.parseInt(configuredRequiredNoOfBackupCodes);
        }
        return noOfRequiredBackupCodes;
    }

    /**
     * Get email authenticator config related to the given key.
     *
     * @param key          Authenticator config key.
     * @param tenantDomain Tenant domain.
     * @return Value associated with the given config key.
     * @throws BackupCodeException If an error occurred while getting the config value.
     */
    public static String getBackupCodeAuthenticatorConfig(String key, String tenantDomain) throws BackupCodeException {

        try {
            Property[] connectorConfigs;
            IdentityGovernanceService governanceService = BackupCodeDataHolder.getIdentityGovernanceService();
            connectorConfigs = governanceService.getConfiguration(new String[]{key}, tenantDomain);
            return connectorConfigs[0].getValue();
        } catch (IdentityGovernanceException e) {
            throw new BackupCodeException(ERROR_GETTING_CONFIG.getCode(),
                    ERROR_GETTING_CONFIG.getMessage(), e);
        }
    }

    /**
     * Generate the hash value of the given backupCode.
     *
     * @param backupCode String value that needs to hash.
     * @return Hash value of the backupCode.
     * @throws BackupCodeException If the algorithms is invalid.
     */
    public static String generateHashBackupCode(String backupCode) throws BackupCodeException {

        try {
            MessageDigest messageDigest = MessageDigest.getInstance(TOKEN_HASH_METHOD);
            byte[] in = messageDigest.digest(backupCode.getBytes(StandardCharsets.UTF_8));
            final StringBuilder builder = new StringBuilder();
            for (byte b : in) {
                builder.append(String.format("%02x", b));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new BackupCodeException(ERROR_HASH_BACKUP_CODE.getCode(),
                    ERROR_HASH_BACKUP_CODE.getMessage(), e);
        }
    }
}
