#include <stdio.h>
#include <string.h>
#include "CryptoAPI.h"

#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define MY_RSA_KEY_SIZE 4096
#define MY_RSA_EXPONENT 65537

static const char *TAG = "Main";

static const unsigned char message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
static const size_t message_length = sizeof(message);

CryptoAPI crypto_api;

struct TestMetrics {
    int64_t gen_keys_time_us;
    int64_t sign_time_us;
    int64_t verify_time_us;
    size_t pub_key_size;
    size_t priv_key_size;
    size_t sig_size;
};

void run_benchmark_cycle(Algorithms algorithm, Hashes hash, const char* alg_name, const char* hash_name)
{
    const int ITERATIONS = 10;
    TestMetrics metrics_sum = {0};
    size_t pub_size = 0, priv_size = 0, sig_size = 0;
    bool success_once = false;

    // Run iterations
    for (int i = 0; i < ITERATIONS; i++) {
        size_t shake_len = (hash == Hashes::MY_SHAKE_256) ? 32 : 0; // Default 32 bytes for shake if used as digest
        if (crypto_api.init(Libraries::LIBOQS_LIB, algorithm, hash, shake_len) != 0) {
            printf("Error init\n");
            continue;
        }

        int64_t start = esp_timer_get_time();
        if (crypto_api.gen_keys() != 0) {
             printf("Error gen_keys\n");
             continue;
        }
        metrics_sum.gen_keys_time_us += (esp_timer_get_time() - start);

        // Capture sizes only once
        if (i == 0) {
            pub_size = crypto_api.get_public_key_size();
            priv_size = crypto_api.get_private_key_size();
            sig_size = crypto_api.get_signature_size();
        }

        unsigned char *signature = (unsigned char *)malloc(crypto_api.get_signature_size());
        if (signature == NULL) {
            printf("Error malloc signature\n");
            continue;
        }
        size_t sig_len_out = 0;

        start = esp_timer_get_time();
        if (crypto_api.sign(message, message_length, signature, &sig_len_out) != 0) {
            printf("Error sign\n");
            free(signature);
            continue;
        }
        metrics_sum.sign_time_us += (esp_timer_get_time() - start);

        start = esp_timer_get_time();
        if (crypto_api.verify(message, message_length, signature, sig_len_out) != 0) {
            printf("Error verify\n");
            free(signature);
            continue;
        }
        metrics_sum.verify_time_us += (esp_timer_get_time() - start);
        
        free(signature);
        crypto_api.close();
        success_once = true;
        
        // Small delay to prevent WDT issues
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (!success_once) {
        printf("%s, %s, FAILED, -, -, -, -, -, -\n", alg_name, hash_name);
        return;
    }

    // Averages in ms
    double avg_gen = (double)metrics_sum.gen_keys_time_us / ITERATIONS / 1000.0;
    double avg_sign = (double)metrics_sum.sign_time_us / ITERATIONS / 1000.0;
    double avg_verify = (double)metrics_sum.verify_time_us / ITERATIONS / 1000.0;

    // CSV Output: Algorithm, Hash, TimeGen(ms), TimeSign(ms), TimeVerify(ms), PubKey(B), PrivKey(B), Sig(B)
    printf("%s, %s, %.2f, %.2f, %.2f, %zu, %zu, %zu\n", 
           alg_name, hash_name, avg_gen, avg_sign, avg_verify, pub_size, priv_size, sig_size);
}

extern "C" void app_main(void)
{
    vTaskDelay(pdMS_TO_TICKS(2000)); // Wait for monitor to attach

    printf("\n\n========== PQC BENCHMARK RESULTS ==========\n");
    printf("Algorithm, HashDigest, AvgGenKey(ms), AvgSign(ms), AvgVerify(ms), PubKeyBytes, PrivKeyBytes, SigBytes\n");

    Algorithms algs[] = {
        Algorithms::SPHINCS_PLUS_SHA2,
        Algorithms::SPHINCS_PLUS_SHAKE,
        Algorithms::ML_DSA,
        Algorithms::FALCON,
        Algorithms::SLH_DSA_SHA2,
        Algorithms::SLH_DSA_SHAKE
    };
    const char* alg_names[] = {
        "SPHINCS+-SHA2",
        "SPHINCS+-SHAKE",
        "ML-DSA",
        "FALCON",
        "SLH-DSA-SHA2",
        "SLH-DSA-SHAKE"
    };

    Hashes hashes[] = {
        Hashes::MY_SHA_256,
        Hashes::MY_SHA_512,
        Hashes::MY_SHA3_256,
        Hashes::MY_SHAKE_256
    };
    const char* hash_names[] = {
        "SHA_256",
        "SHA_512",
        "SHA3_256",
        "SHAKE_256"
    };

    for (int a = 0; a < 6; a++) {
        for (int h = 0; h < 4; h++) {
            run_benchmark_cycle(algs[a], hashes[h], alg_names[a], hash_names[h]);
            vTaskDelay(pdMS_TO_TICKS(500)); // Cool down
        }
    }

    printf("========== BENCHMARK COMPLETE ==========\n");
}
