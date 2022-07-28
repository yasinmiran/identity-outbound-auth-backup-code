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

package org.wso2.carbon.identity.application.authenticator.backupcode.connector;

import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.testng.AssertJUnit.assertEquals;
import static org.mockito.Mockito.when;
import static org.powermock.api.mockito.PowerMockito.mockStatic;
import static org.testng.AssertJUnit.assertNull;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.REQUIRED_NO_OF_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LENGTH_OF_BACKUP_CODE;

@PrepareForTest({BackupCodeAuthenticatorConfigImpl.class, IdentityUtil.class})
public class BackupCodeAuthenticatorConfigImplTest extends PowerMockTestCase {

    BackupCodeAuthenticatorConfigImpl backupCodeAuthenticatorConfig = new BackupCodeAuthenticatorConfigImpl();

    @Test
    public void testGetName() {

        assertEquals("backup-code-authenticator", backupCodeAuthenticatorConfig.getName());
    }

    @Test
    public void testGetFriendlyName() {

        assertEquals(  "Backup Code Authenticator", backupCodeAuthenticatorConfig.getFriendlyName());
    }

    @Test
    public void testGetCategory() {

        assertEquals("Multi Factor Authenticators", backupCodeAuthenticatorConfig.getCategory());
    }

    @Test
    public void testGetSubCategory() {

        assertEquals("DEFAULT", backupCodeAuthenticatorConfig.getSubCategory());
    }

    @Test
    public void testGetOrder() {

        assertEquals(0, backupCodeAuthenticatorConfig.getOrder());
    }

    @Test
    public void testGetPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(LENGTH_OF_BACKUP_CODE, "Backup code length");
        nameMapping.put(REQUIRED_NO_OF_BACKUP_CODES, "Backup code size");

        assertEquals(nameMapping, backupCodeAuthenticatorConfig.getPropertyNameMapping());
    }

    @Test
    public void testGetPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put("BackupCode.BackupCodeLength", "Length of a backup code");
        descriptionMapping.put("BackupCode.BackupCodeSize", "Maximum number of backup codes");

        assertEquals(descriptionMapping, backupCodeAuthenticatorConfig.getPropertyDescriptionMapping());

    }

    @Test
    public void testGetPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add("BackupCode.BackupCodeLength");
        properties.add("BackupCode.BackupCodeSize");

        String[] expectedResult = properties.toArray(new String[0]);
        assertEquals(expectedResult[0], backupCodeAuthenticatorConfig.getPropertyNames()[0]);
        assertEquals(expectedResult[1], backupCodeAuthenticatorConfig.getPropertyNames()[1]);
    }

    @Test(dataProvider = "defaultPropertyValuesData")
    public void testGetDefaultPropertyValues(Properties properties, String backupCodeLength, String backupCodeSize)
            throws IdentityGovernanceException {


        mockStatic(IdentityUtil.class);
        when(IdentityUtil.getProperty(LENGTH_OF_BACKUP_CODE)).thenReturn(backupCodeLength);
        when(IdentityUtil.getProperty(REQUIRED_NO_OF_BACKUP_CODES)).thenReturn(backupCodeSize);

        Properties result = backupCodeAuthenticatorConfig.getDefaultPropertyValues("test");
        assertEquals(properties, result);

    }

    @DataProvider(name = "defaultPropertyValuesData")
    public Object[][] dataForDefaultPropertyValues(){

        Map<String, String> defaultProperties1 = new HashMap<>();
        defaultProperties1.put("BackupCode.BackupCodeLength", "6");
        defaultProperties1.put("BackupCode.BackupCodeSize", "10");

        Properties properties1 = new Properties();
        properties1.putAll(defaultProperties1);

        Map<String, String> defaultProperties2 = new HashMap<>();
        defaultProperties2.put("BackupCode.BackupCodeLength", "5");
        defaultProperties2.put("BackupCode.BackupCodeSize", "5");

        Properties properties2 = new Properties();
        properties2.putAll(defaultProperties2);

        return new Object[][] {
                {properties1, null, null},
                {properties1, "", ""},
                {properties1, " ", " "},
                {properties2, "5", "5"},
        };
    }

    @Test
    public void testGetDefaultPropertyValues() throws IdentityGovernanceException {

        Map<String, String> result = backupCodeAuthenticatorConfig.getDefaultPropertyValues(new String[0], "test");
        assertNull(result);
    }
}
