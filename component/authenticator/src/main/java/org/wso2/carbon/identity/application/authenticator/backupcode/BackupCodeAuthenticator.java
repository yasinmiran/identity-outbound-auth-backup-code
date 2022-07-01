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
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.application.authenticator.backupcode.util.BackupCodeUtil;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.extension.identity.helper.FederatedAuthenticatorUtil;
import org.wso2.carbon.extension.identity.helper.util.IdentityHelperUtil;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.AuthenticatorFlowStatus;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.LogoutFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.JustInTimeProvisioningConfig;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.event.IdentityEventConstants;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.SESSION_DATA_KEY;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.CODE_MISMATCH;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODES_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.Claims.BACKUP_CODE_FAILED_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_ACCESS_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_FIND_USER_REALM;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_TRIGGERING_EVENT;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_UPDATING_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.INVALID_FEDERATED_AUTHENTICATOR;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.INVALID_FEDERATED_USER_AUTHENTICATION;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_AUTHENTICATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.ErrorMessages.ERROR_NO_FEDERATED_USER;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.IS_INITIAL_FEDERATED_USER_ATTEMPT;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.SUPER_TENANT_DOMAIN;
import static org.wso2.carbon.identity.event.IdentityEventConstants.Event.POST_NON_BASIC_AUTHENTICATION;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.OPERATION_STATUS;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM;
import static org.wso2.carbon.identity.event.IdentityEventConstants.EventProperty.USER_STORE_MANAGER;

/**
 * Backup code authenticator
 */
public class BackupCodeAuthenticator extends AbstractApplicationAuthenticator implements LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(BackupCodeAuthenticator.class);

    @Override
    public AuthenticatorFlowStatus process(HttpServletRequest request, HttpServletResponse response,
                                           AuthenticationContext context)
            throws AuthenticationFailedException, LogoutFailedException {

        if (context.isLogoutRequest()) {
            return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
        } else if (request.getParameter(BACKUP_CODE) == null) {
            initiateAuthenticationRequest(request, response, context);
            if (context.getProperty(AUTHENTICATION).equals(BACKUP_CODE_AUTHENTICATOR_NAME)) {
                return AuthenticatorFlowStatus.INCOMPLETE;
            } else {
                return AuthenticatorFlowStatus.SUCCESS_COMPLETED;
            }
        } else {
            return super.process(request, response, context);
        }
    }

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        String token = httpServletRequest.getParameter(BACKUP_CODE);
        return (token != null);
    }

    /**
     * Check whether status of retrying authentication.
     *
     * @return true, if retry authentication is enabled
     */
    @Override
    protected boolean retryAuthenticationEnabled() {

        return true;
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter(SESSION_DATA_KEY);
    }

    @Override
    public String getName() {

        return BACKUP_CODE_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String username = null;
        String tenantDomain = context.getTenantDomain();
        context.setProperty(AUTHENTICATION, BACKUP_CODE_AUTHENTICATOR_NAME);
        if (!tenantDomain.equals(SUPER_TENANT_DOMAIN)) {
            IdentityHelperUtil.loadApplicationAuthenticationXMLFromRegistry(context, getName(), tenantDomain);
        }
        AuthenticatedUser authenticatedUserFromContext = BackupCodeUtil.getAuthenticatedUser(context);
        if (authenticatedUserFromContext == null) {
            throw new AuthenticationFailedException(ERROR_NO_AUTHENTICATED_USER.getCode(),
                    ERROR_NO_AUTHENTICATED_USER.getMessage());
        }

        /*
         * The username that the server is using to identify the user, is needed to be identified, as
         * for the federated users, the username in the authentication context may not be same as the
         * username when the user is provisioned to the server.
         */
        String mappedLocalUsername = getMappedLocalUsername(authenticatedUserFromContext, context);

        /*
         * If the mappedLocalUsername is blank, that means this is an initial login attempt by a non-provisioned
         * federated user.
         */
        boolean isInitialFederationAttempt = StringUtils.isBlank(mappedLocalUsername);

        try {
            AuthenticatedUser authenticatingUser =
                    resolveAuthenticatingUser(context, authenticatedUserFromContext, mappedLocalUsername, tenantDomain,
                            isInitialFederationAttempt);
            username = UserCoreUtil.addTenantDomainToEntry(authenticatingUser.getUserName(), tenantDomain);
            context.setProperty(AUTHENTICATED_USER, authenticatingUser);

            String retryParam = "";
            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }
            boolean isBackupCodesExistForUser = false;

            // Not required to check the backup code enable state for the initial login of the federated users.
            if (!isInitialFederationAttempt) {
                isBackupCodesExistForUser = isBackupCodesExistForUser(
                        UserCoreUtil.addDomainToName(username, authenticatingUser.getUserStoreDomain()));
            }
            if (isBackupCodesExistForUser) {
                if (log.isDebugEnabled()) {
                    log.debug("Backup codes exists for the user: " + username);
                }
            }

            /*
             * This multi option URI is used to navigate back to multi option page to select a different
             * authentication option from backup code pages.
             */
            String multiOptionURI = BackupCodeUtil.getMultiOptionURIQueryParam(request);

            if (isBackupCodesExistForUser) {
                // If backup code is enabled for the user.
                String backupCodeLoginPageUrl =
                        buildBackupCodeLoginPageURL(context, username, retryParam, multiOptionURI);
                response.sendRedirect(backupCodeLoginPageUrl);
            } else {
                String backupCodeErrorPageUrl =
                        buildBackupCodeErrorPageURL(context, username, retryParam, multiOptionURI);
                response.sendRedirect(backupCodeErrorPageUrl);
            }
        } catch (IOException e) {
            throw new AuthenticationFailedException(
                    "Error when redirecting the backup code login response, user : " + username, e);
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException(
                    "Error when checking backup code enabled for the user : " + username, e);
        } catch (AuthenticationFailedException e) {
            throw new AuthenticationFailedException("Authentication failed!. Cannot get the username from first step.",
                    e);
        } catch (URLBuilderException | URISyntaxException e) {
            throw new AuthenticationFailedException("Error while building backup code page URL.", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
                                                 AuthenticationContext context) throws AuthenticationFailedException {

        String token = request.getParameter(BACKUP_CODE);
        AuthenticatedUser authenticatingUser = (AuthenticatedUser) context.getProperty(AUTHENTICATED_USER);

        String username = authenticatingUser.toFullQualifiedUsername();
        validateAccountLockStatusForLocalUser(context, username);

        if (StringUtils.isBlank(token)) {
            try {
                handleBackupCodeVerificationFail(authenticatingUser);
            } catch (BackupCodeException e) {
                throw new AuthenticationFailedException(e.getMessage());
            }
            throw new AuthenticationFailedException(
                    "Empty Backup code in the request. Authentication Failed for user: " + username);
        }
        try {
            String backupCodes;
            if (isInitialFederationAttempt(context)) {
                backupCodes = backupCodesForFederatedUser(context);
                if (!isValidBackupCode(token, context, username, backupCodes)) {
                    throw new AuthenticationFailedException(
                            "Invalid Token. Authentication failed for federated user: " + username);
                }
            } else {
                backupCodes = backupCodesForLocalUser(username);
                if (!isValidBackupCode(token, context, username, backupCodes)) {
                    handleBackupCodeVerificationFail(authenticatingUser);
                    throw new AuthenticationFailedException(
                            "Invalid Token. Authentication failed, user :  " + username);
                }
            }
            // Removing used backup code from the list.
            removeUsedBackupCode(token, username, backupCodes);
            if (StringUtils.isNotBlank(username)) {
                AuthenticatedUser authenticatedUser = new AuthenticatedUser();
                authenticatedUser.setAuthenticatedSubjectIdentifier(username);
                authenticatedUser.setUserName(
                        UserCoreUtil.removeDomainFromName(MultitenantUtils.getTenantAwareUsername(username)));
                authenticatedUser.setUserStoreDomain(UserCoreUtil.extractDomainFromName(username));
                authenticatedUser.setTenantDomain(MultitenantUtils.getTenantDomain(username));
                context.setSubject(authenticatedUser);
            } else {
                context.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
            }
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException("Backup code Authentication process failed for user " + username,
                    e);
        }
        // It reached here means the authentication was successful.
        try {
            resetBackupCodeFailedAttempts(authenticatingUser);
        } catch (BackupCodeException e) {
            throw new AuthenticationFailedException("Error occurred while resetting account lock claim");
        }
    }

    private boolean isJitProvisioningEnabled(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return false;
        }
        return provisioningConfig.isProvisioningEnabled();
    }

    private IdentityProvider getIdentityProvider(String idpName, String tenantDomain)
            throws AuthenticationFailedException {

        try {
            IdentityProvider idp = BackupCodeDataHolder.getIdpManager().getIdPByName(idpName, tenantDomain);
            if (idp == null) {
                throw new AuthenticationFailedException(
                        String.format(INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
            }
            return idp;
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(
                    String.format(INVALID_FEDERATED_AUTHENTICATOR.getMessage(), idpName, tenantDomain));
        }
    }

    /**
     * Retrieve the provisioned username of the authenticated user. If this is a federated scenario, the
     * authenticated username will be same as the username in context. If the flow is for a JIT provisioned user, the
     * provisioned username will be returned.
     *
     * @param authenticatedUser AuthenticatedUser.
     * @param context           AuthenticationContext.
     * @return Provisioned username.
     * @throws AuthenticationFailedException If an error occurred while getting the provisioned username.
     */
    private String getMappedLocalUsername(AuthenticatedUser authenticatedUser, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (!authenticatedUser.isFederatedUser()) {
            return authenticatedUser.getUserName();
        }

        // If the user is federated, we need to check whether the user is already provisioned to the organization.
        String federatedUsername = FederatedAuthenticatorUtil.getLoggedInFederatedUser(context);
        if (StringUtils.isBlank(federatedUsername)) {
            throw new AuthenticationFailedException(ERROR_NO_FEDERATED_USER.getCode(),
                    ERROR_NO_FEDERATED_USER.getMessage());
        }
        String associatedLocalUsername = FederatedAuthenticatorUtil.getLocalUsernameAssociatedWithFederatedUser(
                MultitenantUtils.getTenantAwareUsername(federatedUsername), context);
        if (StringUtils.isNotBlank(associatedLocalUsername)) {
            return associatedLocalUsername;
        }
        return null;
    }

    /**
     * Identify the AuthenticatedUser that the authenticator trying to authenticate. This needs to be done to
     * identify the locally mapped user for federated authentication scenarios.
     *
     * @param context                    Authentication context.
     * @param authenticatedUserInContext AuthenticatedUser retrieved from context.
     * @param mappedLocalUsername        Mapped local username if available.
     * @param tenantDomain               Application tenant domain.
     * @param isInitialFederationAttempt Whether auth attempt by a not JIT provisioned federated user.
     * @return AuthenticatedUser that the authenticator trying to authenticate.
     * @throws AuthenticationFailedException If an error occurred.
     */
    private AuthenticatedUser resolveAuthenticatingUser(AuthenticationContext context,
                                                        AuthenticatedUser authenticatedUserInContext,
                                                        String mappedLocalUsername, String tenantDomain,
                                                        boolean isInitialFederationAttempt)
            throws AuthenticationFailedException {

        // Handle local users.
        if (!authenticatedUserInContext.isFederatedUser()) {
            return authenticatedUserInContext;
        }

        if (!isJitProvisioningEnabled(authenticatedUserInContext, tenantDomain)) {
            throw new AuthenticationFailedException(INVALID_FEDERATED_USER_AUTHENTICATION.getCode(),
                    INVALID_FEDERATED_USER_AUTHENTICATION.getMessage());
        }

        // This is a federated initial authentication scenario.
        if (isInitialFederationAttempt) {
            context.setProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT, true);
            return authenticatedUserInContext;
        }

        /*
         * At this point, the authenticating user is in our system but can have a different mapped username compared to the
         * identifier that is in the authentication context. Therefore, we need to have a new AuthenticatedUser object
         * with the mapped local username to identify the user.
         */
        AuthenticatedUser authenticatingUser = new AuthenticatedUser(authenticatedUserInContext);
        authenticatingUser.setUserName(mappedLocalUsername);
        authenticatingUser.setUserStoreDomain(getFederatedUserStoreDomain(authenticatedUserInContext, tenantDomain));
        return authenticatingUser;
    }

    private String getFederatedUserStoreDomain(AuthenticatedUser user, String tenantDomain)
            throws AuthenticationFailedException {

        String federatedIdp = user.getFederatedIdPName();
        IdentityProvider idp = getIdentityProvider(federatedIdp, tenantDomain);
        JustInTimeProvisioningConfig provisioningConfig = idp.getJustInTimeProvisioningConfig();
        if (provisioningConfig == null) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("No JIT provisioning configs for idp: %s in tenant: %s", federatedIdp,
                        tenantDomain));
            }
            return null;
        }
        String provisionedUserStore = provisioningConfig.getProvisioningUserStore();
        if (log.isDebugEnabled()) {
            log.debug(String.format("Setting user store: %s as the provisioning user store for user: %s in tenant: %s",
                    provisionedUserStore, user.getUserName(), tenantDomain));
        }
        return provisionedUserStore;
    }

    /**
     * Check whether backup code is enabled for local user or not.
     *
     * @param username Username of the user.
     * @return true, if backup code enable for local user.
     * @throws BackupCodeException when user realm is null or could not find user.
     */
    private boolean isBackupCodesExistForUser(String username)
            throws BackupCodeException, AuthenticationFailedException {

        String tenantAwareUsername = null;
        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            if (userRealm != null) {
                Map<String, String> UserClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
                String encryptedBackupCodes = UserClaimValues.get(BACKUP_CODES_CLAIM);
                return StringUtils.isNotBlank(encryptedBackupCodes);
            } else {
                throw new BackupCodeException(ERROR_FIND_USER_REALM.getCode(),
                        String.format(ERROR_FIND_USER_REALM.getMessage(),
                                CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
            }
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), tenantAwareUsername, e));
        }
    }

    private String buildBackupCodeLoginPageURL(AuthenticationContext context, String username, String retryParam,
                                               String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName() +
                "&type=backup-code" + retryParam + "&username=" + username + multiOptionURI;
        String loginPage = FrameworkUtils.appendQueryParamsStringToUrl(BackupCodeUtil.getBackupCodeLoginPage(context),
                queryString);
        return buildAbsoluteURL(loginPage);
    }

    private String buildAbsoluteURL(String redirectUrl) throws URISyntaxException, URLBuilderException {

        URI uri = new URI(redirectUrl);
        if (uri.isAbsolute()) {
            return redirectUrl;
        } else {
            return ServiceURLBuilder.create().addPath(redirectUrl).build().getAbsolutePublicURL();
        }
    }

    private String buildBackupCodeErrorPageURL(AuthenticationContext context, String username, String retryParam,
                                               String multiOptionURI)
            throws AuthenticationFailedException, URISyntaxException, URLBuilderException {

        String queryString = "sessionDataKey=" + context.getContextIdentifier() + "&authenticators=" + getName() +
                "&type=backup_code_error" + retryParam + "&username=" + username + multiOptionURI;
        String errorPage = FrameworkUtils.appendQueryParamsStringToUrl(BackupCodeUtil.getBackupCodeErrorPage(context),
                queryString);
        return buildAbsoluteURL(errorPage);
    }

    private void validateAccountLockStatusForLocalUser(AuthenticationContext context, String username)
            throws AuthenticationFailedException {

        boolean isLocalUser = BackupCodeUtil.isLocalUser(context);
        AuthenticatedUser authenticatedUserObject = (AuthenticatedUser) context.getProperty(AUTHENTICATED_USER);
        String tenantDomain = MultitenantUtils.getTenantDomain(username);
        String userStoreDomain = UserCoreUtil.extractDomainFromName(username);
        if (isLocalUser &&
                BackupCodeUtil.isAccountLocked(authenticatedUserObject.getUserName(), tenantDomain, userStoreDomain)) {
            String errorMessage =
                    String.format("Authentication failed since authenticated user: %s, account is locked.",
                            getUserStoreAppendedName(username));
            if (log.isDebugEnabled()) {
                log.debug(errorMessage);
            }
            throw new AuthenticationFailedException(errorMessage);
        }
    }

    private boolean isInitialFederationAttempt(AuthenticationContext context) {

        if (context.getProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT) != null) {
            return Boolean.parseBoolean(context.getProperty(IS_INITIAL_FEDERATED_USER_ATTEMPT).toString());
        }
        return false;
    }

    /**
     * Verify whether a given token is valid for the federated user.
     *
     * @param context  Authentication context.
     * @return true if backup code is valid otherwise false.
     */
    private String backupCodesForFederatedUser(AuthenticationContext context) {

        String backupCodes = null;
        if (context.getProperty(BACKUP_CODES_CLAIM) != null) {
            backupCodes = context.getProperty(BACKUP_CODES_CLAIM).toString();
        }
        return backupCodes;
    }

    /**
     * Verify whether a given token is valid for a stored local user.
     *
     * @param username Username of the user.
     * @return true if code is valid otherwise false.
     * @throws BackupCodeException UserRealm for user or tenant domain is null.
     */
    private String backupCodesForLocalUser(String username) throws BackupCodeException {

        String tenantAwareUsername = null;
        try {
            tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            if (userRealm != null) {
                Map<String, String> userClaimValues = userRealm.getUserStoreManager()
                        .getUserClaimValues(tenantAwareUsername, new String[]{BACKUP_CODES_CLAIM}, null);
                return userClaimValues.get(BACKUP_CODES_CLAIM);
            }
            throw new BackupCodeException(ERROR_FIND_USER_REALM.getCode(),
                    String.format(ERROR_FIND_USER_REALM.getMessage(),
                            CarbonContext.getThreadLocalCarbonContext().getTenantDomain()));
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getCode(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), tenantAwareUsername, e));
        }
    }

    private boolean isValidBackupCode(String token, AuthenticationContext context, String userName,
                                      String hashedBackupCodes) throws BackupCodeException {

        if (StringUtils.isBlank(hashedBackupCodes)) {
            if (log.isDebugEnabled()) {
                log.debug("No backup codes found for user: " + userName);
            }
            return false;
        }
        List<String> backupCodeList = new ArrayList<>(Arrays.asList(hashedBackupCodes.split(",")));
        if (!backupCodeList.contains(BackupCodeUtil.generateHashBackupCode(token))) {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Given code: %s does not match with any saved backup codes codes for user: %s",
                        token, userName));
            }
            context.setProperty(CODE_MISMATCH, true);
            return false;
        }
        if (log.isDebugEnabled()) {
            log.debug("Saved backup code found for the user: " + userName);
        }
        return true;
    }

    /**
     * Remove the used code from the saved backup code list for the user.
     *
     * @param code   Backup code given by the user.
     * @param username    Username.
     * @param hashedBackupCodes Existing hashed backup codes in a comma separated string.
     * @throws BackupCodeException If an error occurred while removing the used backup code.
     */
    private void removeUsedBackupCode(String code, String username, String hashedBackupCodes)
            throws BackupCodeException {

        List<String> backupCodeList = new ArrayList<>(Arrays.asList(hashedBackupCodes.split(",")));

        backupCodeList.remove(BackupCodeUtil.generateHashBackupCode(code));
        String unusedBackupCodes = String.join(",", backupCodeList);
        String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
        try {
            if (log.isDebugEnabled()) {
                log.debug(String.format("Removing used token: %s from the backup code list of user: %s", code,
                        username));
            }
            UserRealm userRealm = BackupCodeUtil.getUserRealm(username);
            UserStoreManager userStoreManager = userRealm.getUserStoreManager();
            Map<String, String> claimsToUpdate = new HashMap<>();
            claimsToUpdate.put(BACKUP_CODES_CLAIM, unusedBackupCodes);
            userStoreManager.setUserClaimValues(tenantAwareUsername, claimsToUpdate, null);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_UPDATING_BACKUP_CODES.getCode(),
                    ERROR_UPDATING_BACKUP_CODES.getMessage(), e);
        }
    }

    /**
     * Reset Backup code Failed Attempts count upon successful completion of the backup code verification. By default,
     * the backup code authenticator will support account lock on failed attempts if the account locking is enabled
     * for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws BackupCodeException If an error occurred while resetting the backup code failed attempts.
     */
    private void resetBackupCodeFailedAttempts(AuthenticatedUser user) throws BackupCodeException {

        UserStoreManager userStoreManager;
        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(user.toFullQualifiedUsername());
            userStoreManager = userRealm.getUserStoreManager();
            // Add required meta properties to the event.
            Map<String, Object> metaProperties = new HashMap<>();
            metaProperties.put(AUTHENTICATOR_NAME, BACKUP_CODE_AUTHENTICATOR_NAME);
            metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, BACKUP_CODE_FAILED_ATTEMPTS_CLAIM);
            metaProperties.put(USER_STORE_MANAGER, userStoreManager);
            metaProperties.put(OPERATION_STATUS, true);

            triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getMessage(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), user.getUserName()), e);
        }
    }

    /**
     * Execute account lock flow for backup code verification failures. By default, the backup code
     * authenticator will support account lock on failed attempts if the account locking is enabled for the tenant.
     *
     * @param user AuthenticatedUser.
     * @throws BackupCodeException If an error occurred while resetting the backup code failed attempts.
     */
    private void handleBackupCodeVerificationFail(AuthenticatedUser user) throws BackupCodeException {

        UserStoreManager userStoreManager;
        try {
            UserRealm userRealm = BackupCodeUtil.getUserRealm(user.toFullQualifiedUsername());
            userStoreManager = userRealm.getUserStoreManager();
            // Add required meta properties to the event.
            Map<String, Object> metaProperties = new HashMap<>();
            metaProperties.put(AUTHENTICATOR_NAME, BACKUP_CODE_AUTHENTICATOR_NAME);
            metaProperties.put(PROPERTY_FAILED_LOGIN_ATTEMPTS_CLAIM, BACKUP_CODE_FAILED_ATTEMPTS_CLAIM);
            metaProperties.put(USER_STORE_MANAGER, userStoreManager);
            metaProperties.put(OPERATION_STATUS, false);

            triggerEvent(POST_NON_BASIC_AUTHENTICATION, user, metaProperties);
        } catch (UserStoreException e) {
            throw new BackupCodeException(ERROR_ACCESS_USER_REALM.getMessage(),
                    String.format(ERROR_ACCESS_USER_REALM.getMessage(), user.getUserName()), e);
        }
    }

    /**
     * Trigger event.
     *
     * @param eventName      Event name.
     * @param user           Authenticated user.
     * @param metaProperties Meta details.
     * @throws BackupCodeException If an error occurred while triggering the event.
     */
    private void triggerEvent(String eventName, AuthenticatedUser user, Map<String, Object> metaProperties)
            throws BackupCodeException {

        HashMap<String, Object> properties = new HashMap<>();
        properties.put(IdentityEventConstants.EventProperty.USER_NAME, user.getUserName());
        properties.put(IdentityEventConstants.EventProperty.USER_STORE_DOMAIN, user.getUserStoreDomain());
        properties.put(IdentityEventConstants.EventProperty.TENANT_DOMAIN, user.getTenantDomain());
        if (metaProperties != null) {
            for (Map.Entry<String, Object> metaProperty : metaProperties.entrySet()) {
                if (StringUtils.isNotBlank(metaProperty.getKey()) && metaProperty.getValue() != null) {
                    properties.put(metaProperty.getKey(), metaProperty.getValue());
                }
            }
        }
        Event identityMgtEvent = new Event(eventName, properties);
        try {
            BackupCodeDataHolder.getIdentityEventService().handleEvent(identityMgtEvent);
        } catch (IdentityEventException e) {
            throw new BackupCodeException(ERROR_TRIGGERING_EVENT.getCode(),
                    String.format(ERROR_TRIGGERING_EVENT.getMessage(), eventName, user.getUserName()), e);
        }
    }
}
