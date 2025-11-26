#include "CryptoAPI.h"
#include "MbedtlsModule.h"
#include "WolfsslModule.h"
#include "MicroeccModule.h"

static const char *TAG = "CryptoAPI";

CryptoAPI::CryptoAPI()
{
  mbedtls_module = new MbedtlsModule(commons);
  wolfssl_module = new WolfsslModule(commons);
  microecc_module = new MicroeccModule(commons, *mbedtls_module);
}

CryptoAPI::~CryptoAPI()
{
  delete mbedtls_module;
  delete wolfssl_module;
  delete microecc_module;
}

int CryptoAPI::init(Algorithms algorithm, Hashes hash, size_t length_of_shake256)
{
  // Try to initialize LittleFS, but continue even if it fails
  // (LittleFS is not currently being used, so failure is not critical)
  // esp_err_t littlefs_ret = commons.init_littlefs();
  // if (littlefs_ret != ESP_OK)
  // {
  //   ESP_LOGW(TAG, "LittleFS initialization failed, continuing without filesystem support");
  // }

  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->init(algorithm, hash, 0);
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->init(algorithm, hash, length_of_shake256);
  }

  return microecc_module->init(Algorithms::ECDSA_SECP256R1, hash, 0);
}

int CryptoAPI::init(Libraries library, Algorithms algorithm, Hashes hash, size_t length_of_shake256)
{
  this->print_init_configuration(library, algorithm, hash, length_of_shake256);
  this->chosen_library = library;

  return init(algorithm, hash, length_of_shake256);
}

int CryptoAPI::get_signature_size()
{
  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->get_signature_size();
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->get_signature_size();
  }

  return microecc_module->get_signature_size();
}

int CryptoAPI::gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent)
{
  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->gen_rsa_keys(rsa_key_size, rsa_exponent);
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->gen_rsa_keys(rsa_key_size, rsa_exponent);
  }

  return -1;
}

int CryptoAPI::gen_keys()
{
  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->gen_keys();
  }

  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->gen_keys();
  }

  return microecc_module->gen_keys();
}

int CryptoAPI::get_public_key_pem(unsigned char *public_key_pem)
{
  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->get_public_key_pem(public_key_pem);
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->get_public_key_pem(public_key_pem);
  }

  return microecc_module->get_public_key_pem(public_key_pem);
}

int CryptoAPI::sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length)
{
  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->sign(message, message_length, signature, signature_length);
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->sign(message, message_length, signature, signature_length);
  }

  return microecc_module->sign(message, message_length, signature, 0);
}

int CryptoAPI::verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length)
{
  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    return mbedtls_module->verify(message, message_length, signature, signature_length);
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    return wolfssl_module->verify(message, message_length, signature, signature_length);
  }

  return microecc_module->verify(message, message_length, signature, 0);
}

void CryptoAPI::close()
{
  // commons.close_littlefs();

  if (this->chosen_library == Libraries::MBEDTLS_LIB)
  {
    mbedtls_module->close();
    return;
  }

  if (this->chosen_library == Libraries::WOLFSSL_LIB)
  {
    wolfssl_module->close();
    return;
  }

  microecc_module->close();
}

void CryptoAPI::save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size)
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    this->mbedtls_module->save_private_key(file_path, private_key, private_key_size);
    return;
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    this->wolfssl_module->save_private_key(file_path, private_key, private_key_size);
    return;
  }

  this->microecc_module->save_private_key(file_path, private_key, private_key_size);
}

void CryptoAPI::save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size)
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    this->mbedtls_module->save_public_key(file_path, public_key, public_key_size);
    return;
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    this->wolfssl_module->save_public_key(file_path, public_key, public_key_size);
    return;
  }

  this->microecc_module->save_public_key(file_path, public_key, public_key_size);
}

void CryptoAPI::save_signature(const char *file_path, const unsigned char *signature, size_t sig_len)
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    this->mbedtls_module->save_signature(file_path, signature, sig_len);
    return;
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    this->wolfssl_module->save_signature(file_path, signature, sig_len);
    return;
  }

  this->microecc_module->save_signature(file_path, signature, sig_len);
}

void CryptoAPI::load_file(const char *file_path, unsigned char *buffer, size_t buffer_size)
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    this->mbedtls_module->load_file(file_path, buffer, buffer_size);
    return;
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    this->wolfssl_module->load_file(file_path, buffer, buffer_size);
    return;
  }

  this->microecc_module->load_file(file_path, buffer, buffer_size);
}

size_t CryptoAPI::get_private_key_size()
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    return this->mbedtls_module->get_private_key_size();
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    return this->wolfssl_module->get_private_key_pem_size();
  }

  return this->microecc_module->get_private_key_size();
}

size_t CryptoAPI::get_public_key_size()
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    return this->mbedtls_module->get_public_key_pem_size();
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    return this->wolfssl_module->get_public_key_pem_size();
  }

  return this->microecc_module->get_public_key_size();
}

size_t CryptoAPI::get_public_key_pem_size()
{
  if (get_chosen_library() == Libraries::MBEDTLS_LIB)
  {
    return this->mbedtls_module->get_public_key_pem_size();
  }

  if (get_chosen_library() == Libraries::WOLFSSL_LIB)
  {
    return this->wolfssl_module->get_public_key_pem_size();
  }

  return this->microecc_module->get_public_key_pem_size();
}

Algorithms CryptoAPI::get_chosen_algorithm()
{
  return commons.get_chosen_algorithm();
}

Libraries CryptoAPI::get_chosen_library()
{
  return this->chosen_library;
}

long CryptoAPI::get_file_size(const char *file_path)
{
  // return commons.get_file_size(file_path);
  return 0;
}

void CryptoAPI::print_init_configuration(Libraries library, Algorithms algorithm, Hashes hash, size_t length_of_shake256)
{
  const char *library_str;
  switch (library)
  {
  case MBEDTLS_LIB:
    library_str = "MBEDTLS";
    break;
  case WOLFSSL_LIB:
    library_str = "WOLFSSL";
    break;
  case MICROECC_LIB:
    library_str = "MICROECC";
    break;
  default:
    library_str = "UNKNOWN";
    break;
  }

  const char *algorithm_str;
  switch (algorithm)
  {
  case ECDSA_BP256R1:
    algorithm_str = "ECDSA_BP256R1";
    break;
  case ECDSA_BP512R1:
    algorithm_str = "ECDSA_BP512R1";
    break;
  case ECDSA_SECP256R1:
    algorithm_str = "ECDSA_SECP256R1";
    break;
  case ECDSA_SECP521R1:
    algorithm_str = "ECDSA_SECP521R1";
    break;
  case EDDSA_25519:
    algorithm_str = "EDDSA_25519";
    break;
  case EDDSA_448:
    algorithm_str = "EDDSA_448";
    break;
  case RSA:
    algorithm_str = "RSA";
    break;
  default:
    algorithm_str = "UNKNOWN";
    break;
  }

  const char *hash_str;
  switch (hash)
  {
  case MY_SHA_256:
    hash_str = "SHA_256";
    break;
  case MY_SHA_512:
    hash_str = "SHA_512";
    break;
  case MY_SHA3_256:
    hash_str = "SHA3_256";
    break;
  case MY_SHAKE_256:
    hash_str = "SHAKE_256";
    break;
  default:
    hash_str = "UNKNOWN";
    break;
  }

  ESP_LOGI(TAG, "INITIALIZED LIBRARY [ %s ] WITH ALGORITHM [ %s ] AND HASH [ %s ]", library_str, algorithm_str, hash_str);

  if (hash == Hashes::MY_SHAKE_256)
  {
    ESP_LOGI(TAG, "SHAKE_256 LENGTH [ %zu ]", length_of_shake256);
  }
}