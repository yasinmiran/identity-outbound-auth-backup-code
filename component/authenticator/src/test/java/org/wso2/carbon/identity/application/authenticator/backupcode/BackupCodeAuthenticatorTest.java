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

package org.wso2.carbon.identity.application.authenticator.backupcode;

import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.testng.PowerMockTestCase;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.servlet.http.HttpServletRequest;

import static org.mockito.Mockito.when;
import static org.testng.AssertJUnit.assertEquals;

@PrepareForTest({BackupCodeAuthenticator.class})
public class BackupCodeAuthenticatorTest extends PowerMockTestCase {


    @Mock
    HttpServletRequest httpServletRequest;

    @Test(dataProvider = "canHandleData")
    public void testCanHandle(String backupCode, boolean expectedValue) {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        when(httpServletRequest.getParameter("BackupCode")).thenReturn(backupCode);
        assertEquals(expectedValue, backupCodeAuthenticator.canHandle(httpServletRequest));
    }

    @DataProvider(name = "canHandleData")
    public Object[][] dataForCanHandle() {

        return new Object[][] {
                {"123567", true},
                {null, false}
        };
    }

    @Test
    public void testTestGetName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals(  "backup-code-authenticator", backupCodeAuthenticator.getName());
    }

    @Test
    public void testGetFriendlyName() {

        BackupCodeAuthenticator backupCodeAuthenticator = new BackupCodeAuthenticator();
        assertEquals(  "Backup Code Authenticator", backupCodeAuthenticator.getFriendlyName());
    }
}
