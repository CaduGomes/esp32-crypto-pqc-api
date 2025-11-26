#ifndef LIBOQS_MODULE_H
#define LIBOQS_MODULE_H

#include "ICryptoModule.h"
#include <oqs/oqs.h>

class LiboqsModule : public ICryptoModule
{
public:
    LiboqsModule(CryptoApiCommons &commons);
    ~LiboqsModule();

    int init(Algorithms algorithm, Hashes hash, size_t length_of_shake256) override;
    int get_signature_size() override;
    int gen_rsa_keys(unsigned int rsa_key_size, int rsa_exponent) override;
    int gen_keys() override;
    int sign(const unsigned char *message, size_t message_length, unsigned char *signature, size_t *signature_length) override;
    int verify(const unsigned char *message, size_t message_length, unsigned char *signature, size_t signature_length) override;
    void close() override;

    size_t get_public_key_size() override;
    size_t get_public_key_pem_size() override;
    int get_public_key_pem(unsigned char *public_key_pem) override;
    size_t get_private_key_size() override;

    void save_private_key(const char *file_path, unsigned char *private_key, size_t private_key_size) override;
    void save_public_key(const char *file_path, unsigned char *public_key, size_t public_key_size) override;
    void save_signature(const char *file_path, const unsigned char *signature, size_t sig_len) override;
    void load_file(const char *file_path, unsigned char *buffer, size_t buffer_size) override;

private:
    CryptoApiCommons &commons;
    OQS_SIG *sig_ctx;
    unsigned char *public_key;
    unsigned char *secret_key;
    
    int key_to_pem(const unsigned char *key, size_t key_len, unsigned char *pem_buf, const char *label);
};

#endif

