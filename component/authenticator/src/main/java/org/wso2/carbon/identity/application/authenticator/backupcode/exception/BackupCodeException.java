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
package org.wso2.carbon.identity.application.authenticator.backupcode.exception;

import org.wso2.carbon.identity.base.IdentityException;

/**
 * Backup code related exceptions.
 */
public class BackupCodeException extends IdentityException {

    /**
     * Backup code related exceptions.
     *
     * @param errorCode Error code.
     * @param msg       Error message.
     */
    public BackupCodeException(String errorCode, String msg) {

        super(errorCode, msg);
    }

    /**
     * Backup code related exceptions.
     *
     * @param errorCode Error code.
     * @param msg       Error message.
     * @param cause     Throwable the cause for the exception.
     */
    public BackupCodeException(String errorCode, String msg, Throwable cause) {

        super(errorCode, msg, cause);
    }
}
