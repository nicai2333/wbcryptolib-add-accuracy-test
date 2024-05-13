package net.coding.wbcryptolib.nativelib;

import java.io.*;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.SystemUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DLLLoader {

    private static volatile boolean isLoaded = false;

    private static void loadLib(String libname) {
        Logger log = LoggerFactory.getLogger(DLLLoader.class);
        String fullname = System.mapLibraryName(libname); // extends name with .dll, .so or .dylib
        log.trace("loading crypto native library from: {} in jar", fullname);
        try(InputStream in = DLLLoader.class.getResourceAsStream(fullname)){
            File tmp = File.createTempFile(fullname,".");
            FileUtils.copyInputStreamToFile(in, tmp);
            System.load(tmp.getAbsolutePath());// loading goes here
            log.info("loaded: {}", fullname);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void loadWBcryptoDLL() {
        if(!isLoaded){
            if (SystemUtils.IS_OS_WINDOWS||SystemUtils.IS_OS_LINUX) {
                loadLib("wbcryptoJNI");
            } else {
                throw new RuntimeException("this os is currently not supported by this jar!");
            }
            isLoaded = true;
        }
    }
}
