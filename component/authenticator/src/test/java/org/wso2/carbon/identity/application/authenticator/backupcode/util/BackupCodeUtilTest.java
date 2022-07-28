/*
 * Copyright (c) 2022, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authenticator.backupcode.util;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.SequenceConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.StepConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.backupcode.exception.BackupCodeException;
import org.wso2.carbon.identity.application.authenticator.backupcode.internal.BackupCodeDataHolder;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.exception.AccountLockServiceException;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Matchers.*;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.AssertJUnit.*;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.*;

@PrepareForTest({BackupCodeUtil.class, BackupCodeDataHolder.class, MultitenantUtils.class, IdentityTenantUtil.class,
        FileBasedConfigurationBuilder.class, ConfigurationFacade.class, ServiceURLBuilder.class})
public class BackupCodeUtilTest extends PowerMockTestCase {

    private String username = "test";
    private String tenantDomain = "test.domain";
    private String userStoreDomain = "test.userStore";
    private int tenantId = -1234;

    BackupCodeUtil backupCodeUtil = new BackupCodeUtil();

    @Mock
    RealmService realmService;

    @Mock
    UserRealm userRealm;

    @Mock
    IdentityGovernanceService identityGovernanceService;

    @Mock
    HttpServletRequest httpServletRequest;

    @Mock
    AccountLockService accountLockService;

    @Mock
    AuthenticatorConfig authenticatorConfig;

    @Mock
    FileBasedConfigurationBuilder fileBasedConfigurationBuilder;

    @Mock
    ConfigurationFacade configurationFacade;

    @Mock
    ServiceURLBuilder serviceURLBuilder;

    @Mock
    ServiceURL serviceURL;

    @Test(dataProvider = "hashStringData")
    public void testGenerateHashString(String backupCode) throws BackupCodeException {

        String hashedCode = backupCodeUtil.generateHashBackupCode(backupCode);
        String duplicatedHashedCode = backupCodeUtil.generateHashBackupCode(backupCode);
        assertEquals(hashedCode, duplicatedHashedCode);
    }

    @DataProvider(name = "hashStringData")
    public Object[][] hashStringData(){

        return new Object[][] {
                {" "},
                {""},
                {"234563"},
                {"!@#(*"}
        };
    }

    @Test(dataProvider = "authenticatedUserData")
    public void testGetAuthenticatedUser(Object authenticationContext, Object authenticatedUser) {


        AuthenticatedUser authenticatedUser1 = backupCodeUtil.getAuthenticatedUser((AuthenticationContext) authenticationContext);
        if (((AuthenticatedUser) authenticatedUser).getUserName() == null) {
            assertNull(authenticatedUser1);
        } else {
            assertEquals(((AuthenticatedUser) authenticatedUser).getUserName(), authenticatedUser1.getUserName());
        }
    }

    @DataProvider(name = "authenticatedUserData")
    public Object[][] dataForAuthenticatedUser() {

        AuthenticatedUser authenticatedUser = new AuthenticatedUser();
        authenticatedUser.setUserName("admin");
        StepConfig stepConfig = new StepConfig();
        stepConfig.setAuthenticatedUser(authenticatedUser);
        stepConfig.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap = new HashMap<>();
        stepConfigMap.put(1,stepConfig);
        SequenceConfig sequenceConfig = new SequenceConfig();
        sequenceConfig.setStepMap(stepConfigMap);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setSequenceConfig(sequenceConfig);

        AuthenticatedUser authenticatedUser2 = new AuthenticatedUser();
        StepConfig stepConfig2 = new StepConfig();
        stepConfig2.setAuthenticatedUser(authenticatedUser2);
        stepConfig2.setSubjectAttributeStep(false);
        Map<Integer, StepConfig> stepConfigMap2 = new HashMap<>();
        stepConfigMap2.put(1,stepConfig2);
        SequenceConfig sequenceConfig2 = new SequenceConfig();
        sequenceConfig2.setStepMap(stepConfigMap2);
        AuthenticationContext authenticationContext2 = new AuthenticationContext();
        authenticationContext2.setSequenceConfig(sequenceConfig2);

        AuthenticatedUser authenticatedUser3 = new AuthenticatedUser();
        StepConfig stepConfig3 = new StepConfig();
        stepConfig3.setAuthenticatedUser(authenticatedUser3);
        stepConfig3.setSubjectAttributeStep(true);
        SequenceConfig sequenceConfig3 = new SequenceConfig();
        sequenceConfig3.setStepMap(null);
        AuthenticationContext authenticationContext3 = new AuthenticationContext();
        authenticationContext3.setSequenceConfig(sequenceConfig3);

        AuthenticatedUser authenticatedUser4 = new AuthenticatedUser();
        authenticatedUser4.setUserName("admin");
        StepConfig stepConfig4 = new StepConfig();
        stepConfig4.setAuthenticatedUser(authenticatedUser4);
        stepConfig4.setSubjectAttributeStep(false);
        Map<Integer, StepConfig> stepConfigMap4 = new HashMap<>();
        stepConfigMap4.put(1,stepConfig4);
        SequenceConfig sequenceConfig4 = new SequenceConfig();
        sequenceConfig4.setStepMap(stepConfigMap4);
        AuthenticationContext authenticationContext4 = new AuthenticationContext();
        authenticationContext4.setSequenceConfig(sequenceConfig4);

        AuthenticatedUser authenticatedUser5 = new AuthenticatedUser();
        StepConfig stepConfig5 = new StepConfig();
        stepConfig5.setAuthenticatedUser(null);
        stepConfig5.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap5 = new HashMap<>();
        stepConfigMap5.put(1,stepConfig5);
        SequenceConfig sequenceConfig5 = new SequenceConfig();
        sequenceConfig5.setStepMap(stepConfigMap5);
        AuthenticationContext authenticationContext5 = new AuthenticationContext();
        authenticationContext5.setSequenceConfig(sequenceConfig5);

        return new Object[][] {
                {authenticationContext, authenticatedUser},
                {authenticationContext2, authenticatedUser2},
                {authenticationContext3, authenticatedUser3},
                {authenticationContext4, authenticatedUser2},
                {authenticationContext5, authenticatedUser5},
        };
    }

    @Test
    public void testGetRealmService() {

        mockStatic(BackupCodeDataHolder.class);
        when(BackupCodeDataHolder.getRealmService()).thenReturn(realmService);
        assertEquals(realmService, backupCodeUtil.getRealmService());
    }

    @Test(dataProvider = "getUserRealmData")
    public void testGetUserRealm(String username) throws UserStoreException, BackupCodeException {

        mockStatic(MultitenantUtils.class);
        mockStatic(IdentityTenantUtil.class);
        mockStatic(BackupCodeDataHolder.class);
        if (username != null) {
            when(MultitenantUtils.getTenantDomain(username)).thenReturn(tenantDomain);
            when(IdentityTenantUtil.getTenantId(tenantDomain)).thenReturn(tenantId);
            when(realmService.getTenantUserRealm(tenantId)).thenReturn(userRealm);
            when(BackupCodeDataHolder.getRealmService()).thenReturn(realmService);
            assertEquals(userRealm, backupCodeUtil.getUserRealm(username));
        }
        else {
            when(BackupCodeDataHolder.getRealmService()).thenReturn(realmService);
            assertEquals(null, backupCodeUtil.getUserRealm(null));
        }
    }

    @DataProvider(name = "getUserRealmData")
    public Object[][] dataForGetUserRealm() {

        String username1 = "test1";

        return new Object[][] {
                {username1},
                {null}
        };
    }

    @Test
    public void testGetMultiOptionURIQueryParam() {

        when(httpServletRequest.getParameter("multiOptionURI")).thenReturn("testURI");
        String result = backupCodeUtil.getMultiOptionURIQueryParam(httpServletRequest);
        assertNotNull(result);

        when(httpServletRequest.getParameter("multiOptionURI")).thenReturn(null);
        String result1 = backupCodeUtil.getMultiOptionURIQueryParam(httpServletRequest);
        assertNotNull(result1);

        String result2 = backupCodeUtil.getMultiOptionURIQueryParam(null);
        assertNotNull(result2);
    }

    @Test(dataProvider = "backupCodeLoginPageData")
    public void testGetBackupCodeLoginPage(String tenantDomain, boolean isTenantQualifiedURL) throws AuthenticationFailedException, URLBuilderException {

        mockStatic(IdentityTenantUtil.class);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(ServiceURLBuilder.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(tenantDomain);
        authenticationContext.setProperty(BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL,
                "backupcodeauthenticationendpoint/custom/error.jsp");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(BACKUP_CODE_AUTHENTICATOR_NAME)).
                thenReturn(authenticatorConfig);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURL);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(BACKUP_CODE_LOGIN_PAGE);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn("testURL");
        String result = BackupCodeUtil.getBackupCodeLoginPage(authenticationContext);
        assertNotNull(result);
    }

    @DataProvider(name = "backupCodeLoginPageData")
    public Object[][] dataForBackupCodeLoginPage() {

        return new Object[][] {
                {"carbon.super", false},
                {"carbon.super", true},
                {"wso2.org", false},
                {"wso2.org", true},
        };
    }

    @Test(dataProvider = "getLoginPageFromXMLFileData")
    public void testGetLoginPageFromXMLFile(Object authenticationContext) throws Exception {


        assertEquals("backupCodeauthenticationendpoint/custom/backupCode.jsp",
                backupCodeUtil.getLoginPageFromXMLFile((AuthenticationContext) authenticationContext));
    }

    @DataProvider(name = "getLoginPageFromXMLFileData")
    public Object[][] dataForGetLoginPageFromXMLFile() {

        AuthenticationContext authenticationContext1 = new AuthenticationContext();
        authenticationContext1.setTenantDomain("wso2.org");
        authenticationContext1.setProperty(BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL,
                "backupCodeauthenticationendpoint/custom/backupCode.jsp");
        authenticationContext1.setProperty("getPropertiesFromLocal", "testProperty");

        AuthenticationContext authenticationContext2 = new AuthenticationContext();
        authenticationContext2.setTenantDomain("wso2.org");
        authenticationContext2.setProperty(BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ENDPOINT_URL,
                "backupCodeauthenticationendpoint/custom/backupCode.jsp");
        authenticationContext1.setProperty("getPropertiesFromLocal", null);

        return new Object[][] {
                {authenticationContext1},
                {authenticationContext2},
        };
    }

    @Test(dataProvider = "backupCodeLoginPageData")
    public void testGetBackupCodeErrorPage(String tenantDomain, boolean isTenantQualifiedURL) throws
            AuthenticationFailedException, URLBuilderException {
        mockStatic(IdentityTenantUtil.class);
        mockStatic(FileBasedConfigurationBuilder.class);
        mockStatic(ConfigurationFacade.class);
        mockStatic(ServiceURLBuilder.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain(tenantDomain);
        authenticationContext.setProperty(BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL,
                "totpauthenticationendpoint/custom/error.jsp");
        when(FileBasedConfigurationBuilder.getInstance()).thenReturn(fileBasedConfigurationBuilder);
        when(fileBasedConfigurationBuilder.getAuthenticatorBean(BACKUP_CODE_AUTHENTICATOR_NAME)).
                thenReturn(authenticatorConfig);
        when(IdentityTenantUtil.isTenantQualifiedUrlsEnabled()).thenReturn(isTenantQualifiedURL);
        when(ConfigurationFacade.getInstance()).thenReturn(configurationFacade);
        when(configurationFacade.getAuthenticationEndpointURL()).thenReturn(BACKUP_CODE_LOGIN_PAGE);
        when(ServiceURLBuilder.create()).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.addPath(anyString())).thenReturn(serviceURLBuilder);
        when(serviceURLBuilder.build()).thenReturn(serviceURL);
        when(serviceURL.getAbsolutePublicURL()).thenReturn("testURL");
        String result = BackupCodeUtil.getBackupCodeErrorPage(authenticationContext);
        assertNotNull(result);
    }

    @Test(description = "Test case for getErrorPageFromXMLFile(): getErrorPage from registry file.")
    public void testGetErrorPageFromXMLFile() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        authenticationContext.setTenantDomain("wso2.org");
        authenticationContext.setProperty(BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATION_ERROR_PAGE_URL,
                "totpauthenticationendpoint/custom/error.jsp");
        assertEquals(backupCodeUtil.getErrorPageFromXMLFile(authenticationContext),
                "totpauthenticationendpoint/custom/error.jsp");
    }

    @Test(dataProvider = "localUserData")
    public void testIsLocalUser(Object authenticationContext, boolean expectedVal) {

        boolean result = backupCodeUtil.isLocalUser((AuthenticationContext) authenticationContext);
        assertEquals(expectedVal, result);

    }

    @DataProvider(name = "localUserData")
    public Object[][] datForLocalUser() {

//        test case #1
        AuthenticationContext authenticationContext1 = new AuthenticationContext();
        SequenceConfig sequenceConfig1 = new SequenceConfig();
        AuthenticatedUser authenticatedUser1 = new AuthenticatedUser();
        authenticatedUser1.setUserName("admin");
        StepConfig stepConfig1 = new StepConfig();
        stepConfig1.setAuthenticatedUser(authenticatedUser1);
        stepConfig1.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap1 = new HashMap<>();
        stepConfigMap1.put(1,stepConfig1);
        sequenceConfig1.setStepMap(stepConfigMap1);
        authenticationContext1.setSequenceConfig(sequenceConfig1);

//        test case #2
        AuthenticationContext authenticationContext2 = new AuthenticationContext();
        SequenceConfig sequenceConfig2 = new SequenceConfig();
        AuthenticatedUser authenticatedUser2 = new AuthenticatedUser();
        authenticatedUser2.setUserName("admin");
        StepConfig stepConfig2 = new StepConfig();
        stepConfig2.setAuthenticatedUser(authenticatedUser2);
        stepConfig2.setSubjectAttributeStep(true);
        sequenceConfig2.setStepMap(null);
        authenticationContext2.setSequenceConfig(sequenceConfig2);

//        test case #1
        AuthenticationContext authenticationContext3 = new AuthenticationContext();
        SequenceConfig sequenceConfig3 = new SequenceConfig();

        StepConfig stepConfig3 = new StepConfig();
        stepConfig3.setAuthenticatedUser(null);
        stepConfig3.setSubjectAttributeStep(true);
        stepConfig3.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
        Map<Integer, StepConfig> stepConfigMap3 = new HashMap<>();
        stepConfigMap3.put(1,stepConfig3);
        sequenceConfig3.setStepMap(stepConfigMap3);
        authenticationContext3.setSequenceConfig(sequenceConfig3);

//        test case #4
        AuthenticationContext authenticationContext4 = new AuthenticationContext();
        SequenceConfig sequenceConfig4 = new SequenceConfig();
        AuthenticatedUser authenticatedUser4 = new AuthenticatedUser();
        authenticatedUser4.setUserName("admin");
        StepConfig stepConfig4 = new StepConfig();
        stepConfig4.setAuthenticatedUser(authenticatedUser4);
        stepConfig4.setSubjectAttributeStep(true);
        stepConfig4.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
        Map<Integer, StepConfig> stepConfigMap4 = new HashMap<>();
        stepConfigMap4.put(1,stepConfig4);
        sequenceConfig4.setStepMap(stepConfigMap4);
        authenticationContext4.setSequenceConfig(sequenceConfig4);

        //        test case #1
        AuthenticationContext authenticationContext5 = new AuthenticationContext();
        SequenceConfig sequenceConfig5 = new SequenceConfig();

        StepConfig stepConfig5 = new StepConfig();
        stepConfig5.setAuthenticatedUser(null);
        stepConfig5.setSubjectAttributeStep(false);
        stepConfig5.setAuthenticatedIdP(LOCAL_AUTHENTICATOR);
        Map<Integer, StepConfig> stepConfigMap5 = new HashMap<>();
        stepConfigMap5.put(1,stepConfig5);
        sequenceConfig5.setStepMap(stepConfigMap5);
        authenticationContext5.setSequenceConfig(sequenceConfig5);

        //        test case #1
        AuthenticationContext authenticationContext6 = new AuthenticationContext();
        SequenceConfig sequenceConfig6 = new SequenceConfig();
        AuthenticatedUser authenticatedUser6 = new AuthenticatedUser();
        authenticatedUser6.setUserName("admin");
        StepConfig stepConfig6 = new StepConfig();
        stepConfig6.setAuthenticatedUser(authenticatedUser6);
        stepConfig6.setSubjectAttributeStep(false);
        Map<Integer, StepConfig> stepConfigMap6 = new HashMap<>();
        stepConfigMap6.put(1,stepConfig6);
        sequenceConfig6.setStepMap(stepConfigMap6);
        authenticationContext6.setSequenceConfig(sequenceConfig6);

        //        test case #1
        AuthenticationContext authenticationContext8 = new AuthenticationContext();
        SequenceConfig sequenceConfig8 = new SequenceConfig();

        StepConfig stepConfig8 = new StepConfig();
        stepConfig8.setAuthenticatedUser(null);
        stepConfig8.setSubjectAttributeStep(true);
        Map<Integer, StepConfig> stepConfigMap8 = new HashMap<>();
        stepConfigMap8.put(1,stepConfig8);
        sequenceConfig8.setStepMap(stepConfigMap8);
        authenticationContext8.setSequenceConfig(sequenceConfig8);

        return new Object[][] {
                {authenticationContext1, false},
                {authenticationContext2, false},
                {authenticationContext3, false},
                {authenticationContext4, true},
                {authenticationContext5, false},
                {authenticationContext6, false},
                {authenticationContext8, false}
        };
    }

    @Test(dataProvider = "accountLockedData")
    public void testIsAccountLocked(boolean expectedResult, boolean result) throws AccountLockServiceException,
            AuthenticationFailedException {

        mockStatic(BackupCodeDataHolder.class);
        when(BackupCodeDataHolder.getAccountLockService()).thenReturn(accountLockService);
        when(accountLockService.isAccountLocked(username, tenantDomain, userStoreDomain)).thenReturn(result);
        assertEquals(expectedResult, backupCodeUtil.isAccountLocked(username, tenantDomain, userStoreDomain));
    }

    @DataProvider(name = "accountLockedData")
    public Object[][] DataForAccountLocked() {

        return new Object[][] {
                {true, true},
                {false, false}
        };
    }

    @Test(dataProvider = "generatedBackupCodesData")
    public void testGenerateBackupCodes(Object connectorConfigs, Object connectorConfigs1,
                                        Object connectorConfigs2) throws IdentityGovernanceException,
            BackupCodeException {

        mockStatic(BackupCodeDataHolder.class);
        when(BackupCodeDataHolder.getIdentityGovernanceService()).thenReturn(identityGovernanceService);
        when(identityGovernanceService.getConfiguration(anyObject(), anyString())).thenAnswer(arg -> {
            String[] argArray = (String[]) arg.getArguments()[0];
            if ((argArray[0]).equals(REQUIRED_NO_OF_BACKUP_CODES)) {
                return connectorConfigs;
            } else if ((argArray[0]).equals(LENGTH_OF_BACKUP_CODE)) {
                return connectorConfigs1;
            }
            return connectorConfigs2;
        });

        List<String> backupCodes = backupCodeUtil.generateBackupCodes(tenantDomain);
        assertEquals(10, backupCodes.size());
        assertEquals(6, backupCodes.get(0).length());
    }

    @DataProvider(name = "generatedBackupCodesData")
    public Object[][] dataForGenerateBackupCodes() {


        Property[] connectorConfigs =  new Property[1];

        Property property = new Property();
        property.setValue("10");
        connectorConfigs[0] = property;

        Property[] connectorConfigs1 =  new Property[1];

        Property property1 = new Property();
        property1.setValue("6");
        connectorConfigs1[0] = property1;

        Property[] connectorConfigs2 =  new Property[1];

        Property[] connectorConfigs3 =  new Property[1];

        Property property3 = new Property();
        property3.setValue("test");
        connectorConfigs3[0] = property3;

        Property[] connectorConfigs4 =  new Property[1];

        Property property4 = new Property();
        property4.setValue("test");
        connectorConfigs4[0] = property4;

        return new Object[][] {
                {connectorConfigs, connectorConfigs1, connectorConfigs2},
                {connectorConfigs3, connectorConfigs4, connectorConfigs2}

        };
    }
    @Test
    public void testGetBackupCodeAuthenticatorConfig() {
    }
}
