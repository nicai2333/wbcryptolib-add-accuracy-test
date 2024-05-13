package ayssl.test;

public class Main {
    public static void main(String[] args) {
        Sm4test test1 = new Sm4test();
       
        // test1.testsm4_bs256_ecb();
        // test1.testsm4_bs256_ctr();
        // test1.testsm4_bs256_gcm();
        // System.out.println("\n\n");
        // test1.testsm4_bsro256_ecb();
        // test1.testsm4_bsro256_ctr();
        // test1.testsm4_bsro256_gcm();
        //test1.performance_test_sm4_lut();
        test1.performance_test_sm4_bsro256();
    }
}
