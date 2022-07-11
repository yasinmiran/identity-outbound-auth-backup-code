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
