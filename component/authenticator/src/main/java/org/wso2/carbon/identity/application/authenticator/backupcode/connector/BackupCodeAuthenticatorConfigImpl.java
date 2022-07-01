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
package org.wso2.carbon.identity.application.authenticator.backupcode.connector;

import org.apache.commons.lang.StringUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.governance.IdentityGovernanceException;
import org.wso2.carbon.identity.governance.common.IdentityConnectorConfig;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.REQUIRED_NO_OF_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.BACKUP_CODE_AUTHENTICATOR_NAME;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.LENGTH_OF_BACKUP_CODE;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.DEFAULT_NO_OF_BACKUP_CODES;
import static org.wso2.carbon.identity.application.authenticator.backupcode.constants.BackupCodeAuthenticatorConstants.DEFAULT_LENGTH_OF_BACKUP_CODE;

/**
 * This class contains the authenticator config implementation.
 */
public class BackupCodeAuthenticatorConfigImpl implements IdentityConnectorConfig {

    @Override
    public String getName() {

        return BACKUP_CODE_AUTHENTICATOR_NAME;
    }

    @Override
    public String getFriendlyName() {

        return BACKUP_CODE_AUTHENTICATOR_FRIENDLY_NAME;
    }

    @Override
    public String getCategory() {

        return "Multi Factor Authenticators";
    }

    @Override
    public String getSubCategory() {

        return "DEFAULT";
    }

    @Override
    public int getOrder() {

        return 0;
    }

    @Override
    public Map<String, String> getPropertyNameMapping() {

        Map<String, String> nameMapping = new HashMap<>();
        nameMapping.put(LENGTH_OF_BACKUP_CODE, "Backup code length");
        nameMapping.put(REQUIRED_NO_OF_BACKUP_CODES, "Backup code size");
        return nameMapping;
    }

    @Override
    public Map<String, String> getPropertyDescriptionMapping() {

        Map<String, String> descriptionMapping = new HashMap<>();
        descriptionMapping.put(LENGTH_OF_BACKUP_CODE, "Length of a backup code");
        descriptionMapping.put(REQUIRED_NO_OF_BACKUP_CODES, "Maximum number of backup codes");
        return descriptionMapping;
    }

    @Override
    public String[] getPropertyNames() {

        List<String> properties = new ArrayList<>();
        properties.add(LENGTH_OF_BACKUP_CODE);
        properties.add(REQUIRED_NO_OF_BACKUP_CODES);
        return properties.toArray(new String[0]);
    }

    @Override
    public Properties getDefaultPropertyValues(String s) throws IdentityGovernanceException {

        String backupCodeLength = String.valueOf(DEFAULT_LENGTH_OF_BACKUP_CODE);
        String backupCodesSize = String.valueOf(DEFAULT_NO_OF_BACKUP_CODES);

        String backupCodeLengthProperty = IdentityUtil.getProperty(LENGTH_OF_BACKUP_CODE);
        String backupCodesSizeProperty = IdentityUtil.getProperty(REQUIRED_NO_OF_BACKUP_CODES);

        if (StringUtils.isNotBlank(backupCodeLengthProperty)) {
            backupCodeLength = backupCodeLengthProperty;
        }
        if (StringUtils.isNotBlank(backupCodesSizeProperty)) {
            backupCodesSize = backupCodesSizeProperty;
        }

        Map<String, String> defaultProperties = new HashMap<>();
        defaultProperties.put(LENGTH_OF_BACKUP_CODE, backupCodeLength);
        defaultProperties.put(REQUIRED_NO_OF_BACKUP_CODES, backupCodesSize);

        Properties properties = new Properties();
        properties.putAll(defaultProperties);
        return properties;
    }

    @Override
    public Map<String, String> getDefaultPropertyValues(String[] strings, String s) throws IdentityGovernanceException {

        return null;
    }
}
