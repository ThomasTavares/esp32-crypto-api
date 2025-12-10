#include "cose.h"
#include <cbor.h>
#include <mbedtls/gcm.h>
#include <esp_system.h>
#include <esp_random.h>
#include <esp_log.h>
#include <cstring>
#include <vector>

using namespace std;

static const char* TAG = "CoseCrypto";
static const int COSE_ALG_AES_256_GCM = 3; 

// Helper to build the Enc_structure for AAD (RFC 9052 Section 5.3)
// Enc_structure = [ "Encrypt0", protected_headers, external_aad ]
static vector<uint8_t> get_aad(const uint8_t* protected_hdr, size_t protected_len) {
    vector<uint8_t> aad_buffer(20 + protected_len); 
    
    CborEncoder encoder, array_encoder;
    cbor_encoder_init(&encoder, aad_buffer.data(), aad_buffer.size(), 0);
    
    // Create Array of 3 items
    cbor_encoder_create_array(&encoder, &array_encoder, 3);
    
    // 1. Context String: "Encrypt0"
    cbor_encode_text_stringz(&array_encoder, "Encrypt0");
    
    // 2. Protected Headers (as bstr)
    // Note: If protected_len is 0, it must still be a zero-length bstr
    cbor_encode_byte_string(&array_encoder, protected_hdr, protected_len);
    
    // 3. External AAD (as bstr) - empty for this implementation
    cbor_encode_byte_string(&array_encoder, NULL, 0);
    
    cbor_encoder_close_container(&encoder, &array_encoder);
    
    // Resize to actual length used
    size_t len = cbor_encoder_get_buffer_size(&encoder, aad_buffer.data());
    aad_buffer.resize(len);
    
    return aad_buffer;
}

esp_err_t CoseCrypto::encrypt(const vector<uint8_t>& plaintext, 
                              const vector<uint8_t>& key, 
                              vector<uint8_t>& out_cose_data) {
    if (key.size() != KEY_SIZE) {
        ESP_LOGE(TAG, "Invalid key size");
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t iv[IV_SIZE];
    esp_fill_random(iv, IV_SIZE);

    size_t estimated_size = plaintext.size() + TAG_SIZE + 100;
    out_cose_data.resize(estimated_size);

    CborEncoder encoder, array_encoder, map_encoder;
    cbor_encoder_init(&encoder, out_cose_data.data(), out_cose_data.size(), 0);

    // Outer Structure
    cbor_encode_tag(&encoder, COSE_TAG_ENCRYPT0);
    cbor_encoder_create_array(&encoder, &array_encoder, 3);

    // 1. Protected Headers
    uint8_t protected_header_buf[32]; // Small buffer for just the Alg ID
    CborEncoder prot_enc, prot_map;
    cbor_encoder_init(&prot_enc, protected_header_buf, sizeof(protected_header_buf), 0);
    cbor_encoder_create_map(&prot_enc, &prot_map, 1);
    cbor_encode_int(&prot_map, 1); // Label 1: Alg
    cbor_encode_int(&prot_map, COSE_ALG_AES_256_GCM);
    cbor_encoder_close_container(&prot_enc, &prot_map);
    size_t protected_len = cbor_encoder_get_buffer_size(&prot_enc, protected_header_buf);

    cbor_encode_byte_string(&array_encoder, protected_header_buf, protected_len);

    // 2. Unprotected Headers (IV)
    cbor_encoder_create_map(&array_encoder, &map_encoder, 1);
    cbor_encode_int(&map_encoder, 5); // Label 5: IV
    cbor_encode_byte_string(&map_encoder, iv, IV_SIZE);
    cbor_encoder_close_container(&array_encoder, &map_encoder);

    // 3. Ciphertext + Tag calculation
    vector<uint8_t> aad = get_aad(protected_header_buf, protected_len);

    size_t total_encrypted_len = plaintext.size() + TAG_SIZE;
    vector<uint8_t> encrypted_buf(total_encrypted_len);
    
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), KEY_SIZE * 8);

    int ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, plaintext.size(), 
                                        iv, IV_SIZE, 
                                        aad.data(), aad.size(), 
                                        plaintext.data(), encrypted_buf.data(), 
                                        TAG_SIZE, encrypted_buf.data() + plaintext.size());

    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "Encryption failed: -0x%04x", -ret);
        return ESP_FAIL;
    }

    cbor_encode_byte_string(&array_encoder, encrypted_buf.data(), total_encrypted_len);
    cbor_encoder_close_container(&encoder, &array_encoder);

    out_cose_data.resize(cbor_encoder_get_buffer_size(&encoder, out_cose_data.data()));
    return ESP_OK;
}

esp_err_t CoseCrypto::decrypt(const vector<uint8_t>& cose_data, 
                              const vector<uint8_t>& key, 
                              vector<uint8_t>& out_plaintext) {
    if (key.size() != KEY_SIZE) return ESP_ERR_INVALID_ARG;

    CborParser parser;
    CborValue it, array_it;
    CborError err;

    // 1. Init Parser
    if ((err = cbor_parser_init(cose_data.data(), cose_data.size(), 0, &parser, &it)) != CborNoError) {
        ESP_LOGE(TAG, "CBOR Parser init failed: %d", err);
        return ESP_FAIL;
    }

    // 2. Check Tag (COSE_Encrypt0 = 16)
    CborTag tag;
    if (cbor_value_get_tag(&it, &tag) == CborNoError) {
        if (tag != COSE_TAG_ENCRYPT0) {
            ESP_LOGW(TAG, "Wrong Tag: %llu (Expected %d)", tag, COSE_TAG_ENCRYPT0);
            return ESP_FAIL;
        }
        cbor_value_advance(&it);
    }

    // 3. Enter Array
    if (!cbor_value_is_array(&it)) {
        ESP_LOGE(TAG, "Not an array");
        return ESP_FAIL;
    }
    
    size_t array_len;
    cbor_value_get_array_length(&it, &array_len);
    if (array_len < 3) { 
        ESP_LOGE(TAG, "Array too short: %d", (int)array_len);
        return ESP_FAIL;
    }

    if ((err = cbor_value_enter_container(&it, &array_it)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to enter array: %d", err);
        return ESP_FAIL;
    }

    // 4. Get Protected Headers (Item 0)
    vector<uint8_t> protected_header;
    size_t prot_len;
    
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Protected header is not a byte string");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_calculate_string_length(&array_it, &prot_len)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to calculate protected header length: %d", err);
        return ESP_FAIL;
    }
    
    protected_header.resize(prot_len);
    size_t actual_len = prot_len;
    if ((err = cbor_value_copy_byte_string(&array_it, protected_header.data(), &actual_len, NULL)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to read Protected Headers: %d", err);
        return ESP_FAIL;
    }
    
    cbor_value_advance(&array_it);

    // 5. Get Unprotected Headers (Item 1)
    CborValue map_it;
    if (!cbor_value_is_map(&array_it)) {
        ESP_LOGE(TAG, "Header 2 is NOT a map");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_enter_container(&array_it, &map_it)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to enter Unprotected Map: %d", err);
        return ESP_FAIL;
    }
    
    uint8_t iv[IV_SIZE];
    bool iv_found = false;

    while (!cbor_value_at_end(&map_it)) {
        if (!cbor_value_is_integer(&map_it)) {
            cbor_value_advance(&map_it); 
            cbor_value_advance(&map_it); 
            continue;
        }

        int label;
        cbor_value_get_int(&map_it, &label);
        cbor_value_advance(&map_it);

        if (label == 5) { // Label 5 = IV
            if (cbor_value_is_byte_string(&map_it)) {
                size_t len = IV_SIZE;
                err = cbor_value_copy_byte_string(&map_it, iv, &len, NULL);
                
                if (err == CborNoError && len == IV_SIZE) {
                    iv_found = true;
                } else {
                    ESP_LOGE(TAG, "IV error: err=%d, len=%d", err, (int)len);
                }
            } else {
                ESP_LOGW(TAG, "Key 5 found but not a bstr");
            }
        }
        
        if ((err = cbor_value_advance(&map_it)) != CborNoError) {
            ESP_LOGE(TAG, "Map iteration error: %d", err);
            break;
        }
    }
    cbor_value_leave_container(&array_it, &map_it);

    if (!iv_found) {
        ESP_LOGE(TAG, "IV not found in headers");
        return ESP_FAIL;
    }

    // 6. Get Ciphertext (Item 2)
    vector<uint8_t> ciphertext_with_tag;
    size_t ct_len;
    
    if (!cbor_value_is_byte_string(&array_it)) {
        ESP_LOGE(TAG, "Ciphertext is not a byte string");
        return ESP_FAIL;
    }
    
    if ((err = cbor_value_calculate_string_length(&array_it, &ct_len)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to calculate ciphertext length: %d", err);
        return ESP_FAIL;
    }
    
    ciphertext_with_tag.resize(ct_len);
    size_t actual_ct_len = ct_len;
    if ((err = cbor_value_copy_byte_string(&array_it, ciphertext_with_tag.data(), &actual_ct_len, NULL)) != CborNoError) {
        ESP_LOGE(TAG, "Failed to read Ciphertext: %d", err);
        return ESP_FAIL;
    }

    if (ct_len < TAG_SIZE) {
        ESP_LOGE(TAG, "Ciphertext too short");
        return ESP_FAIL;
    }

    // 7. Decrypt
    vector<uint8_t> aad = get_aad(protected_header.data(), protected_header.size());

    size_t cipher_len = ct_len - TAG_SIZE;
    out_plaintext.resize(cipher_len);
    const uint8_t* tag_ptr = ciphertext_with_tag.data() + cipher_len;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key.data(), KEY_SIZE * 8);

    int ret = mbedtls_gcm_auth_decrypt(&gcm, cipher_len, 
                                       iv, IV_SIZE, 
                                       aad.data(), aad.size(),
                                       tag_ptr, TAG_SIZE, 
                                       ciphertext_with_tag.data(), out_plaintext.data());
    
    mbedtls_gcm_free(&gcm);

    if (ret != 0) {
        ESP_LOGE(TAG, "Auth/Decryption failed: -0x%04x", -ret);
        return ESP_FAIL;
    }

    return ESP_OK;
}