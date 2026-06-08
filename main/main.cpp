#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include "CryptoAPI.h"
#include "cose.h"

#include "esp_system.h"

#define MY_RSA_KEY_SIZE 4096
#define MY_RSA_EXPONENT 65537

using namespace std;

static const char *TAG = "Main";

static const char private_key_path[] = "/littlefs/private_key.pem";
static const char public_key_path[] = "/littlefs/public_key.pem";
static const char signature_path[] = "/littlefs/signature.bin";

static const unsigned char message[] = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
static const size_t message_length = sizeof(message);

CryptoAPI crypto_api;

void cose_test();   // Function prototype for COSE encryption/decryption test
int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length);

extern "C" void app_main(void)
{
    /* for (int i = 1; i <= 10; i++)
    {
        printf("---------- Beggining operation %d ----------", i);
        int ret = perform_tests(Libraries::WOLFSSL_LIB, Algorithms::ECDSA_BP256R1, Hashes::MY_SHA_512, 512);
        ESP_LOGI(TAG, "Finished status: %d", ret);
    } */

    cose_test();
}

void cose_test() {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Starting COSE Encrypt0 Validation");
    ESP_LOGI(TAG, "========================================");

    // Sample 256-bit Key (32 bytes) for AES-GCM
    const vector<uint8_t> sym_key = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Sample Data
    vector<uint8_t> parsed_string(message, message + (sizeof(message) / sizeof(message[0])));

    ESP_LOGI(TAG, "Original Plaintext: %s", message);
    ESP_LOGI(TAG, "Plaintext Length: %d bytes", parsed_string.size());
    ESP_LOGI(TAG, "Symmetric Key Length: %d bytes", sym_key.size());

    // Encryption Test
    vector<uint8_t> cose_message;
    esp_err_t err = CoseCrypto::encrypt(parsed_string, sym_key, cose_message);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Encryption Failed! Error: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "Encryption Success!");
    ESP_LOGI(TAG, "COSE Encrypt0 Message Size: %d bytes", cose_message.size());
    
    // Decryption Test
    vector<uint8_t> decrypted_payload;
    err = CoseCrypto::decrypt(cose_message, sym_key, decrypted_payload);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Decryption Failed! Error: %s", esp_err_to_name(err));
        return;
    }

    if (parsed_string == decrypted_payload) {
        ESP_LOGI(TAG, "ENCRYPT TEST PASSED: Data matches perfectly.");
    } else {
        ESP_LOGE(TAG, "ENCRYPT TEST FAILED: Data mismatch.");
    }

    // Signing Test
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Starting COSE Sign1 Validation");
    ESP_LOGI(TAG, "========================================");

    // Dynamically generate a mathematically guaranteed keypair
    vector<uint8_t> ecc_priv_key;
    vector<uint8_t> ecc_pub_key;
    if (CoseCrypto::generate_test_keypair(ecc_priv_key, ecc_pub_key) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to generate test keypair!");
        return;
    }

    ESP_LOGI(TAG, "Test Keypair Generated Successfully.");

    vector<uint8_t> cose_sign_message;
    err = CoseCrypto::sign(parsed_string, ecc_priv_key, cose_sign_message);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Signing Failed! Error: %s", esp_err_to_name(err));
        return;
    }

    ESP_LOGI(TAG, "Signing Success!");
    ESP_LOGI(TAG, "COSE Sign1 Message Size: %d bytes", cose_sign_message.size());

    // Verification Test
    vector<uint8_t> verified_payload;
    err = CoseCrypto::verify(cose_sign_message, ecc_pub_key, verified_payload);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Signature Verification Failed! Error: %s", esp_err_to_name(err));
        return;
    }

    if (parsed_string == verified_payload) {
        ESP_LOGI(TAG, "SIGN TEST PASSED: Signature verified & payload matches.");
    } else {
        ESP_LOGE(TAG, "SIGN TEST FAILED: Payload mismatch after verification.");
    }
}

/* int perform_tests(Libraries library, Algorithms algorithm, Hashes hash, size_t shake_256_length)
{
    int ret = crypto_api.init(library, algorithm, hash, shake_256_length);
    if (ret != 0)
    {
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
        return ret;
    }

    // getting public key pem
    // size_t public_key_pem_size = crypto_api.get_public_key_pem_size();
    // unsigned char *public_key_pem = (unsigned char *)malloc(public_key_pem_size * sizeof(unsigned char));
    // ret = crypto_api.get_public_key_pem(public_key_pem);
    // if (ret != 0)
    // {
    //     return ret;
    // }
    // ESP_LOGI(TAG, "public_key_pem_size: %d", public_key_pem_size);
    // ESP_LOGI(TAG, "public_key_pem:\n%s", public_key_pem);

    // // saving keys and signature
    // size_t private_key_size = crypto_api.get_private_key_size();
    // ESP_LOGI(TAG, "private_key_size: %d", private_key_size);

    // unsigned char *private_key = (unsigned char *)malloc(private_key_size * sizeof(unsigned char));
    // crypto_api.save_private_key(private_key_path, private_key, private_key_size);
    // ESP_LOGI(TAG, "Saved Private Key (PEM):\n%s", private_key);

    // size_t public_key_size = crypto_api.get_public_key_size();
    // ESP_LOGI(TAG, "public_key_size size: %d", public_key_size);

    // unsigned char *public_key = (unsigned char *)malloc(public_key_size * sizeof(unsigned char));
    // crypto_api.save_public_key(public_key_path, public_key, public_key_size);
    // ESP_LOGI(TAG, "Saved Public Key (PEM):\n%s", (char *)public_key);

    size_t signature_length = crypto_api.get_signature_size();
    // ESP_LOGI(TAG, "signature_length: %zu", signature_length);

    unsigned char *signature = (unsigned char *)malloc(signature_length * sizeof(unsigned char));

    ret = crypto_api.sign(message, message_length, signature, &signature_length);
    if (ret != 0)
    {
        return ret;
    }

    // ESP_LOG_BUFFER_HEX("Signature", signature, signature_length);
    // crypto_api.save_signature(signature_path, signature, signature_length);

    ret = crypto_api.verify(message, message_length, signature, signature_length);
    if (ret != 0)
    {
        return ret;
    }

    // loading keys and signature from memory

    // long loaded_private_key_size = crypto_api.get_file_size(private_key_path); // crypto_api.get_private_key_size();
    // ESP_LOGI(TAG, "private_key_file_size: %ld", loaded_private_key_size);

    // unsigned char *loaded_private_key = (unsigned char *)malloc(loaded_private_key_size * sizeof(unsigned char)); // +1 for null terminator

    // crypto_api.load_file(private_key_path, loaded_private_key, loaded_private_key_size);
    // ESP_LOGI(TAG, "Loaded Private Key (PEM):\n%s", (char *)loaded_private_key);

    // long loaded_public_key_size = crypto_api.get_file_size(public_key_path); // crypto_api.get_public_key_size();
    // ESP_LOGI(TAG, "private_key_file_size: %ld", loaded_public_key_size);

    // unsigned char *loaded_public_key = (unsigned char *)malloc(loaded_public_key_size * sizeof(unsigned char)); // +1 for null terminator

    // crypto_api.load_file(public_key_path, loaded_public_key, loaded_public_key_size);
    // ESP_LOGI(TAG, "Loaded Public Key (PEM):\n%s", (char *)loaded_public_key);

    // long loaded_signature_size = crypto_api.get_file_size(signature_path); // crypto_api.get_signature_size();
    // ESP_LOGI(TAG, "loaded_signature_size: %ld", loaded_signature_size);

    // unsigned char *loaded_signature = (unsigned char *)malloc(loaded_signature_size * sizeof(unsigned char));
    // crypto_api.load_file(signature_path, loaded_signature, loaded_signature_size);
    // ESP_LOG_BUFFER_HEX("Signature", loaded_signature, loaded_signature_size);

    crypto_api.close();

    // free(public_key_pem);
    // free(private_key);
    // free(public_key);
    // free(signature);

    // free(loaded_private_key);
    // free(loaded_public_key);
    // free(loaded_signature);

    return 0;
} */