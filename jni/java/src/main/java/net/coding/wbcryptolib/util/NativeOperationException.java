package net.coding.wbcryptolib.util;

import static java.lang.String.format;

public class NativeOperationException extends RuntimeException {

    private final int errorCode;

    public NativeOperationException(int errorCode){
        super(format("error running native function, errorCode: %d", errorCode));
        this.errorCode = errorCode;
    }

    public int getErrorCode() {
        return errorCode;
    }

}
