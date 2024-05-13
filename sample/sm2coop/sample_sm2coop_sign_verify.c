#include "string.h"
#include "keygen.h"
#include "../hex_utils.h"
#include "wbcrypto/sm2coop.h"
#include <omp.h>
char rand_value[] = "4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F";

int test_sign_verify(wbcrypto_sm2coop_context* client, wbcrypto_sm2coop_context* server, int thread_num) {
    int ret = 0;
    char msg_buf[] = "signature standard";
    unsigned char sig_buf[1024] = { 0 };
    size_t sig_len = 0;
    unsigned char dgst_buf[1024] = { 0 };
    size_t dgst_len = 0;
    unsigned char req_buf[1024] = { 0 };
    size_t req_len = 0;
    unsigned char resp_buf[1024] = { 0 };
    size_t resp_len = 0;

    double begin, end;
    size_t count=1000;
    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for (size_t i = 0; i < count; i++)
    {
        wbcrypto_sm2coop_sign_client_session sign_ctx;
        wbcrypto_sm2coop_sign_client_session_init(&sign_ctx);

        wbcrypto_sm2coop_sign_client_start(
                client,
                &sign_ctx,
                (uint8_t*)msg_buf, sizeof(msg_buf) - 1,
                dgst_buf, sizeof(dgst_buf), &dgst_len,
                req_buf, sizeof(req_buf), &req_len,
                mock_rand_hex, rand_value
        );

        wbcrypto_sm2coop_sign_server_respond(
                server,
                dgst_buf, dgst_len,
                req_buf, req_len,
                resp_buf, sizeof(resp_buf), &resp_len,
                mock_rand_hex, rand_value
        );

        wbcrypto_sm2coop_sign_client_complete(
                client,
                &sign_ctx,
                resp_buf, resp_len,
                sig_buf, sizeof(sig_buf), &sig_len
        );
    }
    // sm9_pairing_omp_t(r_arr, Ppub_arr, g1_arr, count, threads_num);
    end = omp_get_wtime();
    printf("sign - %d threads: run %d times, total time: %f s, per second do: %f times\n", \
                thread_num, count, 1.0*(end-begin), count/(end-begin));

    begin = omp_get_wtime();
    #pragma omp parallel for num_threads(thread_num)
    for (size_t i = 0; i < count; i++){
        wbcrypto_sm2coop_verify(
                client,
                (uint8_t*)msg_buf, sizeof(msg_buf) - 1,
                sig_buf, sig_len
        );
    }
    end = omp_get_wtime();
    printf("verify - %d threads: run %d times, total time: %f s, per second do: %f times\n", \
                thread_num, count, 1.0*(end-begin), count/(end-begin));


//    wbcrypto_sm2coop_sign_client_session_free(&sign_ctx);
    return ret;
}

int main() {
    int ret = 0;
    wbcrypto_sm2coop_context client, server;
    wbcrypto_sm2coop_context_init(&client);
    wbcrypto_sm2coop_load_default_group(&client.grp);
    wbcrypto_sm2coop_context_init(&server);
    wbcrypto_sm2coop_load_default_group(&server.grp);

    MBEDTLS_MPI_CHK(keygen(&client, &server, rand_value));

    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 1));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 2));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 4));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 8));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 12));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 16));
    MBEDTLS_MPI_CHK(test_sign_verify(&client, &server, 32));

    cleanup:
    wbcrypto_sm2coop_context_free(&client);
    wbcrypto_sm2coop_context_free(&server);
    return ret;
}