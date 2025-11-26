#include "MbedtlsModule.h"
#include <mbedtls/platform.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/sha3.h>
#include <mbedtls/error.h>
#include <mbedtls/base64.h>

static const char *TAG = "MbedtlsModule";

MbedtlsModule::MbedtlsModule(CryptoApiCommons &commons) : commons(commons) {}

int MbedtlsModule::init(Algorithms algorithm, Hashes hash, size_t _)
{
  int initial_memory = esp_get_minimum_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;
  size_t cycle_count_before = esp_cpu_get_cycle_count();

  commons.set_chosen_algorithm(algorithm);
  commons.set_chosen_hash(hash);

  mbedtls_pk_type_t pk_type;
  if (commons.get_chosen_algorithm() == Algorithms::RSA)
  {
    pk_type = MBEDTLS_PK_RSA;
  }
  else
  {
    pk_type = MBEDTLS_PK_ECKEY;
  }

  mbedtls_pk_init(&pk_ctx);
  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);

  const unsigned char pers[] = "seed";

  int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, pers, sizeof(pers));
  if (ret != 0)
  {
    commons.log_error("mbedtls_ctr_drbg_seed");
    return ret;
  }

  ret = mbedtls_pk_setup(&pk_ctx, mbedtls_pk_info_from_type(pk_type));
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_setup");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_minimum_free_heap_size();
  size_t cycle_count_after = esp_cpu_get_cycle_count();

  // commons.print_elapsed_time(start_time, end_time, "init");
  // commons.print_used_memory(initial_memory, final_memory, "init");
  // commons.print_total_cycles(cycle_count_before, cycle_count_after, "init");

  commons.log_success("init");
  return 0;
}

int MbedtlsModule::gen_keys()
{
  mbedtls_ecp_group_id group_id = get_ecc_group_id();

  heap_caps_monitor_local_minimum_free_size_start();
  int initial_memory = esp_get_minimum_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;
  unsigned long cycle_count_before = esp_cpu_get_cycle_count();

  int ret = mbedtls_ecp_gen_key(group_id, mbedtls_pk_ec(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0)
  {
    commons.log_error("mbedtls_ecp_gen_key");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_minimum_free_heap_size();
  unsigned long cycle_count_after = esp_cpu_get_cycle_count();
  heap_caps_monitor_local_minimum_free_size_stop();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_gen_keys");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_gen_keys");
  commons.print_total_cycles(cycle_count_before, cycle_count_after, "mbedtls_gen_keys");

  commons.log_success("gen_keys");
  return 0;
}

int MbedtlsModule::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
  this->rsa_key_size = rsa_key_size;

  heap_caps_monitor_local_minimum_free_size_start();
  int initial_memory = esp_get_minimum_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t cycle_count_before = esp_cpu_get_cycle_count();

  int ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(pk_ctx), mbedtls_ctr_drbg_random, &ctr_drbg, rsa_key_size, rsa_exponent);
  if (ret != 0)
  {
    commons.log_error("mbedtls_rsa_gen_key");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_minimum_free_heap_size();
  size_t cycle_count_after = esp_cpu_get_cycle_count();
  heap_caps_monitor_local_minimum_free_size_stop();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_gen_keys");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_gen_keys");
  commons.print_total_cycles(cycle_count_before, cycle_count_after, "mbedtls_gen_keys");

  commons.log_success("gen_keys");
  return 0;
}

int MbedtlsModule::sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length)
{
  int hash_initial_memory = esp_get_minimum_free_heap_size();
  unsigned long hash_start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  unsigned long hash_end_time = esp_timer_get_time() / 1000;
  int hash_final_memory = esp_get_minimum_free_heap_size();

  commons.print_elapsed_time(hash_start_time, hash_end_time, "hash_message");
  commons.print_used_memory(hash_initial_memory, hash_final_memory, "hash_message");

  heap_caps_monitor_local_minimum_free_size_start();
  int initial_memory = esp_get_minimum_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t cycle_count_before = esp_cpu_get_cycle_count();

  ret = mbedtls_pk_sign(&pk_ctx, get_hash_type(), hash, hash_length, signature, get_signature_size(), signature_length, mbedtls_ctr_drbg_random, &ctr_drbg);
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_sign");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_minimum_free_heap_size();
  size_t cycle_count_after = esp_cpu_get_cycle_count();
  heap_caps_monitor_local_minimum_free_size_stop();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_sign");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_sign");
  commons.print_total_cycles(cycle_count_before, cycle_count_after, "mbedtls_sign");

  free(hash);

  commons.log_success("sign");
  return 0;
}

int MbedtlsModule::verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length)
{
  int hash_initial_memory = esp_get_minimum_free_heap_size();
  unsigned long hash_start_time = esp_timer_get_time() / 1000;

  size_t hash_length = commons.get_hash_length();
  unsigned char *hash = (unsigned char *)malloc(hash_length * sizeof(unsigned char));

  int ret = hash_message(message, message_length, hash);
  if (ret != 0)
  {
    commons.log_error("hash_message");
    return ret;
  }

  unsigned long hash_end_time = esp_timer_get_time() / 1000;
  int hash_final_memory = esp_get_minimum_free_heap_size();

  commons.print_elapsed_time(hash_start_time, hash_end_time, "hash_message");
  commons.print_used_memory(hash_initial_memory, hash_final_memory, "hash_message");

  heap_caps_monitor_local_minimum_free_size_start();
  int initial_memory = esp_get_minimum_free_heap_size();
  unsigned long start_time = esp_timer_get_time() / 1000;

  size_t cycle_count_before = esp_cpu_get_cycle_count();

  ret = mbedtls_pk_verify(&pk_ctx, get_hash_type(), hash, hash_length, signature, signature_length);
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_verify");
    return ret;
  }

  unsigned long end_time = esp_timer_get_time() / 1000;
  int final_memory = esp_get_minimum_free_heap_size();
  size_t cycle_count_after = esp_cpu_get_cycle_count();
  heap_caps_monitor_local_minimum_free_size_stop();

  commons.print_elapsed_time(start_time, end_time, "mbedtls_verify");
  commons.print_used_memory(initial_memory, final_memory, "mbedtls_verify");
  commons.print_total_cycles(cycle_count_before, cycle_count_after, "mbedtls_verify");

  free(hash);

  commons.log_success("verify");
  return 0;
}

int MbedtlsModule::hash_message(const unsigned char *message, size_t message_length, unsigned char *hash)
{
  switch (commons.get_chosen_hash())
  {
  case Hashes::MY_SHA_256:
    return mbedtls_sha256(message, message_length, hash, 0);
  case Hashes::MY_SHA_512:
    return mbedtls_sha512(message, message_length, hash, 0);
  case Hashes::MY_SHA3_256:
    return mbedtls_sha3(MBEDTLS_SHA3_256, message, message_length, hash, 32);
  default:
    return mbedtls_sha256(message, message_length, hash, 0);
  }
}

mbedtls_md_type_t MbedtlsModule::get_hash_type()
{
  switch (commons.get_chosen_hash())
  {
  case Hashes::MY_SHA_256:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA256;
  case Hashes::MY_SHA_512:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA512;
  case Hashes::MY_SHA3_256:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA3_256;
  default:
    return mbedtls_md_type_t::MBEDTLS_MD_SHA256;
  }
}

mbedtls_ecp_group_id MbedtlsModule::get_ecc_group_id()
{
  switch (commons.get_chosen_algorithm())
  {
  case ECDSA_SECP256R1:
    return MBEDTLS_ECP_DP_SECP256R1;
  case ECDSA_SECP521R1:
    return MBEDTLS_ECP_DP_SECP521R1;
  case ECDSA_BP256R1:
    return MBEDTLS_ECP_DP_BP256R1;
  default:
    return MBEDTLS_ECP_DP_BP512R1;
  }
}

int MbedtlsModule::get_public_key_pem(unsigned char *public_key_pem)
{
  int ret = mbedtls_pk_write_pubkey_pem(&pk_ctx, public_key_pem, get_public_key_pem_size());
  if (ret != 0)
  {
    commons.log_error("mbedtls_pk_write_pubkey_pem");
    return ret;
  }

  commons.log_success("get_public_key_pem");
  return 0;
}

int MbedtlsModule::get_signature_size()
{
  return commons.get_chosen_algorithm() == Algorithms::RSA ? rsa_key_size / 8 : ecdsa_sig_max_len;
}

void MbedtlsModule::close()
{
  mbedtls_pk_free(&pk_ctx);
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  ESP_LOGI(TAG, "> mbedtls closed.");
}

int MbedtlsModule::base64_encode(unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen)
{
  return mbedtls_base64_encode(dst, dlen, olen, src, slen);
}

void MbedtlsModule::save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size)
{
  int ret = mbedtls_pk_write_key_pem(&pk_ctx, private_key, private_key_size);
  if (ret == 0)
  {
    // commons.write_file(file_path, private_key);
    ESP_LOGW(TAG, "LittleFS disabled: private key not saved to %s", file_path);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to write private key to PEM format, mbedtls error code: %d", ret);
  }
}

void MbedtlsModule::save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size)
{
  int ret = mbedtls_pk_write_pubkey_pem(&pk_ctx, public_key, public_key_size);
  if (ret == 0)
  {
    // commons.write_file(file_path, public_key);
    ESP_LOGW(TAG, "LittleFS disabled: public key not saved to %s", file_path);
  }
  else
  {
    ESP_LOGE(TAG, "Failed to write public key to PEM format, mbedtls error code: %d", ret);
  }
}

void MbedtlsModule::save_signature(const char *file_path, const unsigned char *signature, size_t sig_len)
{
  // commons.write_binary_file(file_path, signature, sig_len);
  ESP_LOGW(TAG, "LittleFS disabled: signature not saved to %s", file_path);
}

void MbedtlsModule::load_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
  // commons.read_file(file_path, buffer, buffer_size);
  ESP_LOGW(TAG, "LittleFS disabled: cannot load file from %s", file_path);
}

size_t MbedtlsModule::get_private_key_size()
{
  size_t private_key_size;
  if (mbedtls_pk_get_type(&pk_ctx) == MBEDTLS_PK_ECKEY)
  {
    mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk_ctx);
    private_key_size = (ec_key->private_grp.pbits + 7) / 8; // 7 is used to correctly round the byte up
  }
  else
  {
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk_ctx);
    private_key_size = mbedtls_rsa_get_len(rsa) * 5; // 5 accounts for all of the components in pem format
  }

  ESP_LOGI("ECC_KEY_INFO", "Private Key Size: %zu bytes", private_key_size * 8);
  return private_key_size * 8;
}

size_t MbedtlsModule::get_public_key_size()
{
  size_t public_key_size;
  if (mbedtls_pk_get_type(&pk_ctx) == MBEDTLS_PK_ECKEY)
  {
    mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk_ctx);
    public_key_size = 2 * ((ec_key->private_grp.pbits + 7) / 8) + 1; // 1 byte for prefix
  }
  else
  {
    mbedtls_rsa_context *rsa = mbedtls_pk_rsa(pk_ctx);
    public_key_size = mbedtls_rsa_get_len(rsa);
  }

  ESP_LOGI("ECC_KEY_INFO", "Public Key Size: %zu bytes", public_key_size);
  return public_key_size;
}

size_t MbedtlsModule::get_public_key_pem_size()
{
  return get_public_key_size() * 8;
}