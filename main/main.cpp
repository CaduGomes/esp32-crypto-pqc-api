#include <stdio.h>
#include "CryptoAPI.h"

#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#define MY_RSA_KEY_SIZE 4096
#define MY_RSA_EXPONENT 65537

static const char *TAG = "Main";

static const char private_key_path[] = "/littlefs/private_key.pem";
static const char public_key_path[] = "/littlefs/public_key.pem";
static const char signature_path[] = "/littlefs/signature.bin";

static const unsigned char message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
static const size_t message_length = sizeof(message);

CryptoAPI crypto_api;

int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length);

extern "C" void app_main(void)
{
    // Original test (reduced iterations for brevity if desired, keeping as is for now)
    /*
    for (int i = 1; i <= 1; i++)
    {
        printf("---------- Beggining operation %d (Original) ----------\n", i);
        
        int ret = perform_tests(Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_512, 512);
        ESP_LOGI(TAG, "Finished status: %d", ret);
        
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    */

    // New PQC Tests
    int ret;

    printf("---------- Testing SPHINCS+ (liboqs) ----------\n");
    ret = perform_tests(Libraries::LIBOQS_LIB, Algorithms::SPHINCS_PLUS, Hashes::MY_SHA_256, 0);
    ESP_LOGI(TAG, "SPHINCS+ Status: %d", ret);
    vTaskDelay(pdMS_TO_TICKS(1000));

    printf("---------- Testing ML-DSA (liboqs) ----------\n");
    ret = perform_tests(Libraries::LIBOQS_LIB, Algorithms::ML_DSA, Hashes::MY_SHA_256, 0);
    ESP_LOGI(TAG, "ML-DSA Status: %d", ret);
    vTaskDelay(pdMS_TO_TICKS(1000));

    printf("---------- Testing FALCON (liboqs) ----------\n");
    ret = perform_tests(Libraries::LIBOQS_LIB, Algorithms::FALCON, Hashes::MY_SHA_256, 0);
    ESP_LOGI(TAG, "FALCON Status: %d", ret);
    vTaskDelay(pdMS_TO_TICKS(1000));

    printf("---------- Testing SLH-DSA (liboqs) ----------\n");
    ret = perform_tests(Libraries::LIBOQS_LIB, Algorithms::SLH_DSA, Hashes::MY_SHA_256, 0);
    ESP_LOGI(TAG, "SLH-DSA Status: %d", ret);
    vTaskDelay(pdMS_TO_TICKS(1000));
}

int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length)
{
    int ret = crypto_api.init(library, algorithm, hash, shake_256_length);
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Init failed");
        return ret;
    }

    if (crypto_api.get_chosen_algorithm() == Algorithms::RSA)
    {
        ret = crypto_api.gen_rsa_keys(MY_RSA_KEY_SIZE, MY_RSA_EXPONENT);
    }
    else
    {
        ret = crypto_api.gen_keys();
    }

    if (ret != 0)
    {
        ESP_LOGE(TAG, "Key gen failed");
        return ret;
    }

    // getting public key pem (Optional, might fail/be empty for liboqs if unimplemented properly, but we implemented a basic one)
    size_t public_key_pem_size = crypto_api.get_public_key_pem_size();
    if (public_key_pem_size > 0) {
        unsigned char *public_key_pem = (unsigned char *)malloc(public_key_pem_size * sizeof(unsigned char));
        ret = crypto_api.get_public_key_pem(public_key_pem);
        if (ret == 0)
        {
             // ESP_LOGI(TAG, "public_key_pem:\n%s", public_key_pem);
        }
        free(public_key_pem);
    }

    // // saving keys and signature
    // size_t private_key_size = crypto_api.get_private_key_size();
    // unsigned char *private_key = (unsigned char *)malloc(private_key_size * sizeof(unsigned char));
    // crypto_api.save_private_key(private_key_path, private_key, private_key_size); // This populates the buffer now for liboqs
    // // ESP_LOGI(TAG, "Saved Private Key (PEM):\n%s", private_key);
    // free(private_key);

    // size_t public_key_size = crypto_api.get_public_key_size();
    // unsigned char *public_key = (unsigned char *)malloc(public_key_size * sizeof(unsigned char));
    // crypto_api.save_public_key(public_key_path, public_key, public_key_size);
    // // ESP_LOGI(TAG, "Saved Public Key (PEM):\n%s", (char *)public_key);
    // free(public_key);

    size_t signature_length = crypto_api.get_signature_size();
    // ESP_LOGI(TAG, "signature_length: %zu", signature_length);

    unsigned char *signature = (unsigned char *)malloc(signature_length * sizeof(unsigned char));

    ret = crypto_api.sign(message, message_length, signature, &signature_length);
    
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Sign failed");
        free(signature);
        return ret;
    }

    // ESP_LOG_BUFFER_HEX("Signature", signature, signature_length);
    // crypto_api.save_signature(signature_path, signature, signature_length);

    ret = crypto_api.verify(message, message_length, signature, signature_length);
    
    if (ret != 0)
    {
        ESP_LOGE(TAG, "Verify failed");
        free(signature);
        return ret;
    }
    
    free(signature);

    crypto_api.close();

    return 0;
}
