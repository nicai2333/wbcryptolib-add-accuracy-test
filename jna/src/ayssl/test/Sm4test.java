package ayssl.test;

import ayssl.Crypto;

public class Sm4test{
    public void testsm4_bsro256_ecb(){
        byte[] output = new byte[16];
        byte[] input = {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10};
        byte[] key_vector = {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10};
        Crypto.INSTANCE.sm4_bsro256_ecb(output, input, 16, key_vector);
        // 正确输出：
        // 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46
        Crypto.INSTANCE.dump_hex(output, 16);

        byte[] test_output = new byte[16384*16];
        byte[] test_input = new byte[16384*16];
        long startTime, endTime;
        double TIMES = 10000.0;  // 进行多次测试取平均值
        int[] sizes = {1, 4, 16, 64, 512, 1024};  // 针对不同block数量的加密性能测试
        for(int size: sizes){
            System.out.println("测试加密" + size + "组block速度...");
            startTime = System.currentTimeMillis(); // 获取开始时间
            for(long j = 0; j < TIMES; ++j){
                Crypto.INSTANCE.sm4_bsro256_ecb(test_output, test_input, size*16, key_vector);
            }
            endTime = System.currentTimeMillis(); // 获取结束时间
            System.out.println("加密速度为: " + (size*1.0/10000)/((endTime - startTime)/TIMES/1000.0) + "万次/s");
        }   
    }

    // void sm4_bs256_ctr(byte []output, byte []input, int size, byte []key_vector, byte []iv);
    public void testsm4_bsro256_ctr(){
        byte[] output = new byte[64];
        byte[] input = {(byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB,
                        (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xCC, (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD, (byte)0xDD,
                        (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xEE, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF, (byte)0xFF,
                        (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xAA, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB, (byte)0xBB};
        byte[] key = {(byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67, (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef, (byte)0xfe, (byte)0xdc, (byte)0xba, (byte)0x98, (byte)0x76, (byte)0x54, (byte)0x32, (byte)0x10};
        byte[] iv = {(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F};
        Crypto.INSTANCE.sm4_bsro256_ctr(output, input, 64, key, iv);
        // 正确输出：
        // ac 32 36 cb 97 0c c2 07 91 36 4c 39 5a 13 42 d1
        // a3 cb c1 87 8c 6f 30 cd 07 4c ce 38 5c dd 70 c7
        // f2 34 bc 0e 24 c1 19 80 fd 12 86 31 0c e3 7b 92
        // 6e 02 fc d0 fa a0 ba f3 8b 29 33 85 1d 82 45 14
        Crypto.INSTANCE.dump_hex(output, 64);

        byte[] test_output = new byte[1024*16];
        byte[] test_input = new byte[1024*16];
        long startTime, endTime;
        double TIMES = 10000.0;  // 进行多次测试取平均值
        int[] sizes = {1, 4, 16, 64, 512, 1024};  // 针对不同block数量的加密性能测试
        for(int size: sizes){
            System.out.println("测试加密" + size + "组block速度...");
            startTime = System.currentTimeMillis(); // 获取开始时间
            for(long j = 0; j < TIMES; ++j){
                Crypto.INSTANCE.sm4_bsro256_ctr(test_output, test_input, size*16, key, iv);
            }
            endTime = System.currentTimeMillis(); // 获取结束时间
            System.out.println("加密速度为: " + (size*1.0/10000)/((endTime - startTime)/TIMES/1000.0) + "万次/s");
        }

    }

    // void sm4_bs256_gcm(byte []output, byte []input, int size, byte []key_vector, int key_len, byte []iv, int iv_len, byte []tag, int tag_len, byte []Associated_Data, int add_len);
    public void testsm4_bsro256_gcm(){
        byte[] output = new byte[48];
        byte[] input = {
            (byte)0x08, (byte)0x06, (byte)0x00, (byte)0x01, (byte)0x08, (byte)0x00, (byte)0x06, (byte)0x04, (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x03, (byte)0x7f, (byte)0xff, (byte)0xff, (byte)0xfe,
            (byte)0xc0, (byte)0xa8, (byte)0x14, (byte)0x0a, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0xc0, (byte)0xa8, (byte)0x14, (byte)0x0d, (byte)0x00, (byte)0x00,
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };
        byte[] key = {
            (byte)0x00, (byte)0x01, (byte)0x00, (byte)0x02, (byte)0x00, (byte)0x03, (byte)0x00, (byte)0x04,
            (byte)0x00, (byte)0x05, (byte)0x00, (byte)0x06, (byte)0x00, (byte)0x07, (byte)0x00, (byte)0x08
        };
        byte[] iv = {
            (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };
        byte[] associated_data = {
            (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0xff, (byte)0x00, (byte)0x03, (byte)0x7f, (byte)0xff, (byte)0xff, (byte)0xfe, (byte)0x89, (byte)0x2c, (byte)0x38, (byte)0x00,
            (byte)0x00, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36, (byte)0x5c, (byte)0x36    
        };
        byte[] tag = {
            (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00
        };
        Crypto.INSTANCE.sm4_bsro256_gcm(output, input, 48, key, 16, iv, 16, tag, 16, associated_data, 23);
        // 正确输出：
        // 0a 59 91 a6 70 dc 0e a2 6f 84 e4 55 a1 c0 61 47 
        // 8a a0 9f 2f be 90 49 46 29 bc 58 e7 5b e5 e9 1d 
        // bc 6d 21 49 bc 1f ba ca ca a9 72 2d 61 0f de 1d
        Crypto.INSTANCE.dump_hex(output, 48);

        byte[] test_output = new byte[1024*16];
        byte[] test_input = new byte[1024*16];
        long startTime, endTime;
        double TIMES = 10000.0;  // 进行多次测试取平均值
        int[] sizes = {1, 4, 16, 64, 512, 1024};  // 针对不同block数量的加密性能测试
        for(int size: sizes){
            System.out.println("测试加密" + size + "组block速度...");
            startTime = System.currentTimeMillis(); // 获取开始时间
            for(long j = 0; j < TIMES; ++j){
                Crypto.INSTANCE.sm4_bsro256_gcm(test_output, test_input, size*16, key, 16, iv, 16, tag, 16, associated_data, 23);
            }
            endTime = System.currentTimeMillis(); // 获取结束时间
            System.out.println("加密速度为: " + (size*1.0/10000)/((endTime - startTime)/TIMES/1000.0) + "万次/s");
        }
    }
    public void performance_test_sm4_lut(){
        Crypto.INSTANCE.performance_test_sm4_lut();
    }
    public void performance_test_sm4_bsro256(){
        Crypto.INSTANCE.performance_test_sm4_bsro256();
    }
}