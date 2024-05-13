package net.coding.wbcryptolib.rbg;

/**
 * the random bit generator interface
 *    classes implementing this interfaces is a container of a C++ object ptr,
 *    which implements the rbg interface in C++
 */
public interface RBG extends AutoCloseable {

    /**
     * gets the native handle(the underlying pointer in C++)
     * @return the ptr to class that implements RBG interface
     */
    long getNativeHandle();

}
