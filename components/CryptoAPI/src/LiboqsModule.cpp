#include "LiboqsModule.h"
#include "esp_log.h"
#include "mbedtls/base64.h"
#include "esp_random.h"
#include "oqs/rand.h"
#include <string.h>

static const char *TAG = "LiboqsModule";

static void oqs_esp32_randombytes(uint8_t *random_array, size_t bytes_to_read)
{
    esp_fill_random(random_array, bytes_to_read);
}

LiboqsModule::LiboqsModule(CryptoApiCommons &commons) : commons(commons), sig_ctx(nullptr), public_key(nullptr), secret_key(nullptr)
{
}

LiboqsModule::~LiboqsModule()
{
    close();
}

int LiboqsModule::init(Algorithms algorithm, Hashes hash, size_t length_of_shake256)
{
    const char *alg_name = nullptr;
    switch (algorithm)
    {
    case SPHINCS_PLUS_SHA2:
        alg_name = OQS_SIG_alg_sphincs_sha2_128f_simple;
        break;
    case SPHINCS_PLUS_SHAKE:
        alg_name = OQS_SIG_alg_sphincs_shake_128f_simple;
        break;
    case ML_DSA:
        alg_name = OQS_SIG_alg_ml_dsa_44;
        break;
    case FALCON:
        alg_name = OQS_SIG_alg_falcon_512;
        break;
    case SLH_DSA_SHA2:
        alg_name = OQS_SIG_alg_slh_dsa_pure_sha2_128f;
        break;
    case SLH_DSA_SHAKE:
        alg_name = OQS_SIG_alg_slh_dsa_pure_shake_128f;
        break;
    default:
        ESP_LOGE(TAG, "Unknown algorithm for Liboqs");
        return -1;
    }

    if (!OQS_SIG_alg_is_enabled(alg_name))
    {
        ESP_LOGE(TAG, "Algorithm %s is not enabled in liboqs", alg_name);
        return -1;
    }

    sig_ctx = OQS_SIG_new(alg_name);
    if (sig_ctx == nullptr)
    {
        ESP_LOGE(TAG, "Failed to create OQS_SIG object for %s", alg_name);
        return -1;
    }

    // Use ESP32 hardware RNG
    OQS_randombytes_custom_algorithm(oqs_esp32_randombytes);

    commons.set_chosen_algorithm(algorithm);
    commons.set_chosen_hash(hash);

    ESP_LOGI(TAG, "Initialized liboqs with %s", alg_name);
    return 0;
}

int LiboqsModule::get_signature_size()
{
    if (sig_ctx)
    {
        return sig_ctx->length_signature;
    }
    return 0;
}

int LiboqsModule::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
    return -1; // Not RSA
}

int LiboqsModule::gen_keys()
{
    if (!sig_ctx) return -1;

    unsigned long start_time = esp_timer_get_time() / 1000;
    
    if (public_key) free(public_key);
    if (secret_key) free(secret_key);

    public_key = (unsigned char *)malloc(sig_ctx->length_public_key);
    secret_key = (unsigned char *)malloc(sig_ctx->length_secret_key);

    OQS_STATUS status = OQS_SIG_keypair(sig_ctx, public_key, secret_key);
    
    unsigned long end_time = esp_timer_get_time() / 1000;
    // commons.print_elapsed_time(start_time, end_time, "liboqs_gen_keys");

    if (status != OQS_SUCCESS)
    {
        ESP_LOGE(TAG, "OQS_SIG_keypair failed");
        return -1;
    }

    // commons.log_success("gen_keys");
    return 0;
}

int LiboqsModule::sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length)
{
    if (!sig_ctx || !secret_key) return -1;

    unsigned long start_time = esp_timer_get_time() / 1000;

    OQS_STATUS status = OQS_SIG_sign(sig_ctx, signature, signature_length, message, message_length, secret_key);

    unsigned long end_time = esp_timer_get_time() / 1000;
    // commons.print_elapsed_time(start_time, end_time, "liboqs_sign");

    if (status != OQS_SUCCESS)
    {
        ESP_LOGE(TAG, "OQS_SIG_sign failed");
        return -1;
    }
    
    return 0;
}

int LiboqsModule::verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length)
{
    if (!sig_ctx || !public_key) return -1;

    unsigned long start_time = esp_timer_get_time() / 1000;

    OQS_STATUS status = OQS_SIG_verify(sig_ctx, message, message_length, signature, signature_length, public_key);

    unsigned long end_time = esp_timer_get_time() / 1000;
    // commons.print_elapsed_time(start_time, end_time, "liboqs_verify");

    if (status != OQS_SUCCESS)
    {
        ESP_LOGE(TAG, "OQS_SIG_verify failed");
        return -1;
    }

    return 0;
}

void LiboqsModule::close()
{
    if (sig_ctx)
    {
        OQS_SIG_free(sig_ctx);
        sig_ctx = nullptr;
    }
    if (public_key)
    {
        free(public_key);
        public_key = nullptr;
    }
    if (secret_key)
    {
        free(secret_key);
        secret_key = nullptr;
    }
}

size_t LiboqsModule::get_public_key_size()
{
    if (sig_ctx) return sig_ctx->length_public_key;
    return 0;
}

size_t LiboqsModule::get_private_key_size()
{
    if (sig_ctx) return sig_ctx->length_secret_key;
    return 0;
}

// PEM helpers
int LiboqsModule::key_to_pem(const unsigned char *key, size_t key_len, unsigned char *pem_buf, const char *label)
{
    size_t dlen = 0;
    size_t olen = 0;
    
    size_t base64_len = (key_len * 4 / 3) + 4;
    unsigned char *base64_out = (unsigned char*)malloc(base64_len + 10);
    
    int ret = mbedtls_base64_encode(base64_out, base64_len + 10, &olen, key, key_len);
    if (ret != 0) {
        free(base64_out);
        return ret;
    }

    int offset = sprintf((char*)pem_buf, "-----BEGIN %s-----\n", label);
    
    for(size_t i=0; i<olen; i+=64) {
        size_t chunk = (olen - i > 64) ? 64 : (olen - i);
        memcpy(pem_buf + offset, base64_out + i, chunk);
        offset += chunk;
        pem_buf[offset++] = '\n';
    }
    
    offset += sprintf((char*)pem_buf + offset, "-----END %s-----\n", label);
    
    free(base64_out);
    return 0;
}


size_t LiboqsModule::get_public_key_pem_size()
{
    if (!sig_ctx) return 0;
    return (sig_ctx->length_public_key * 2) + 100;
}

int LiboqsModule::get_public_key_pem(unsigned char *public_key_pem)
{
    if (!sig_ctx || !public_key) return -1;
    return key_to_pem(public_key, sig_ctx->length_public_key, public_key_pem, "PUBLIC KEY");
}

void LiboqsModule::save_private_key(const char *file_path, unsigned char *private_key_buf, size_t private_key_size)
{
    if (!sig_ctx || !secret_key) return;
    key_to_pem(this->secret_key, this->get_private_key_size(), private_key_buf, "PRIVATE KEY");
}

void LiboqsModule::save_public_key(const char *file_path, unsigned char *public_key_buf, size_t public_key_size)
{
    if (!sig_ctx || !public_key) return;
    key_to_pem(this->public_key, this->get_public_key_size(), public_key_buf, "PUBLIC KEY");
}

void LiboqsModule::save_signature(const char *file_path, const unsigned char *signature, size_t sig_len)
{
    commons.write_binary_file(file_path, signature, sig_len);
}

void LiboqsModule::load_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
    commons.read_file(file_path, buffer, buffer_size);
}

