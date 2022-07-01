package org.wso2.carbon.identity.application.authenticator.backupcode.exception;

/**
 * Backup code client related exceptions.
 */
public class BackupCodeClientException extends BackupCodeException{

    /**
     * Backup code client related exceptions.
     *
     * @param errorCode Error code.
     * @param msg       Error message.
     */
    public BackupCodeClientException(String errorCode, String msg) {
        super(errorCode, msg);
    }
}
