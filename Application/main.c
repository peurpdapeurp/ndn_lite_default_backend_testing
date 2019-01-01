


#include "app-init-files/app_definitions.h"
#include "app-init-files/app_initialization_functions.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"

// includes for sign on client ble
#include "hardcoded-experimentation.h"
#include "ndn_standalone/app-support/bootstrapping.h"

// includes for ndn standalone library
#include "ndn_standalone/encode/data.h"
#include "ndn_standalone/encode/encoder.h"
#include "ndn_standalone/encode/interest.h"
#include "ndn_standalone/face/direct-face.h"
#include "ndn_standalone/face/ndn-nrf-ble-face.h"
#include "ndn_standalone/forwarder/forwarder.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"

// includes for ndn standalone library
#include "ndn_standalone/security/ndn-lite-crypto-key.h"
#include "ndn_standalone/security/detail/sec-lib/micro-ecc/uECC.h"
#include "ndn_standalone/security/detail/detail-aes/ndn-lite-aes-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-sha256/ndn-lite-sha256-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-hmac/ndn-lite-hmac-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-rng/ndn-lite-rng-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-ecc/ndn-lite-ecc-microecc-impl.h"
#include "ndn_standalone/security/detail/detail-rng/ndn-lite-rng-nrf-crypto-impl.h"
#include "ndn_standalone/security/detail/detail-ecc/ndn-lite-ecc-tinycrypt-impl.h"
#include "ndn_standalone/ndn-enums.h"
#include "ndn_standalone/ndn-error-code.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"

bool m_aes_test_success = false;
bool m_sha256_test_success = false;
bool m_hmac_test_success = false;
bool m_rng_hkdf_test_success = false;
bool m_rng_hmacprng_test_success = false;
bool m_ecc_microecc_test_success = false;
bool m_ecc_tinycrypt_test_success = false;

static uint8_t m_raw_ecc_private_key_1[] =
{
    0x4E, 0x34, 0x08, 0xA6, 0xB1, 0x7C, 0xA2, 0x1A, 0x70, 0xE7, 
    0x6B, 0xE0, 0x91, 0xA9, 0x83, 0xEA, 0xF9, 0xE7, 0xCE, 0x56, 
    0xB4, 0xDC, 0x05, 0xFA, 0xFB, 0x67, 0xD7, 0x57, 0xFC, 0xFB, 
    0xB3, 0xB5
};

static uint8_t m_raw_ecc_public_key_1[] =
{
    0x01, 0x98, 0x69, 0x63, 0xD0, 0x01, 0x00, 0xB5, 0xAE, 0xBF, 
    0x23, 0x6E, 0xC4, 0xEA, 0xBB, 0x10, 0xC5, 0xCF, 0x2C, 0xB3, 
    0xBB, 0xEB, 0xB1, 0x0E, 0x04, 0x1C, 0x33, 0x92, 0x73, 0x6B, 
    0x45, 0x1A, 0x1F, 0xFE, 0xBF, 0xD3, 0xFB, 0xBD, 0x36, 0xB0, 
    0x27, 0x47, 0xA0, 0x3B, 0x8A, 0x7A, 0x50, 0x20, 0xFC, 0xEA, 
    0xBD, 0x4D, 0x28, 0x0F, 0x2E, 0x00, 0x78, 0xCE, 0xFC, 0x74, 
    0x9B, 0xF5, 0x86, 0x73
};

static uint8_t m_raw_ecc_private_key_2[32];

static uint8_t m_raw_ecc_public_key_2[64];

static const uint8_t m_raw_sym_key[] =
{
  0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10,
  0x10, 0x10, 0x10, 0x10, 0x10, 0x10
};

static uint8_t m_signature[64];

static const uint8_t m_message[16] =
{
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
  0x03, 0x03, 0x03, 0x03, 0x03, 0x03
};

static uint8_t m_encrypted_message[64];
static uint8_t m_decrypted_message[64];

static uint8_t m_aes_iv[16] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
};

static uint8_t m_sha256_result[NDN_SEC_SHA256_HASH_SIZE];
static uint8_t m_hmac_result[NDN_SEC_SHA256_HASH_SIZE];

#define RNG_TEST_BUFFER_SIZE 32
static uint8_t m_rng_seed_1[] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};
static uint8_t m_rng_seed_2[] = {
  0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17
};
static uint8_t m_rng_additional_val_1[] = {
  0x04, 0x05, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x14
};
static uint8_t m_rng_additional_val_2[] = {
  0x09, 0x21, 0x02, 0x06, 0x90, 0x01, 0x01, 0x19, 0x87
};
static uint8_t m_rng_result_1[RNG_TEST_BUFFER_SIZE];
static uint8_t m_rng_result_2[RNG_TEST_BUFFER_SIZE];

#define ECC_SHARED_SECRET_BUFFER_SIZE 32
static uint8_t m_gen_shared_secret_1[ECC_SHARED_SECRET_BUFFER_SIZE];
static uint8_t m_gen_shared_secret_2[ECC_SHARED_SECRET_BUFFER_SIZE];

/**@brief Function for application main entry.
 */
int main(void) {

  // Initialize the log.
  log_init();

  // Initialize timers.
  timers_init();

  // Initialize power management.
  power_management_init();

  int ret_val;

  // AES test
  ///////////////////////////////////////////////////////////////////////////////////

  ret_val = ndn_lite_aes_cbc_encrypt_tinycrypt(m_message, sizeof(m_message), 
                                m_encrypted_message, sizeof(m_encrypted_message), 
                                m_aes_iv, 
                                m_raw_sym_key, sizeof(m_raw_sym_key));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_lite_aes_cbc_encrypt_tinycrypt failed, error code: %d\n", ret_val); 
  }
  else {
    APP_LOG("ndn_lite_aes_cbc_encrypt_tinycrypt succeeded.\n");
    APP_LOG_HEX("Original text:", m_message, sizeof(m_message));
    APP_LOG_HEX("Encrypted text:", m_encrypted_message, sizeof(m_encrypted_message));
  }

  ret_val = ndn_lite_aes_cbc_decrypt_tinycrypt(m_encrypted_message, sizeof(m_encrypted_message), 
                                m_decrypted_message, sizeof(m_decrypted_message), 
                                m_aes_iv, 
                                m_raw_sym_key, sizeof(m_raw_sym_key));
  if (ret_val != NDN_SUCCESS) {
    APP_LOG("ndn_lite_aes_cbc_decrypt_tinycrypt failed, error code: %d\n", ret_val); 
  }
  else {
    APP_LOG("ndn_lite_aes_cbc_decrypt_tinycrypt succeeded.\n");
    APP_LOG_HEX("Decrypted text:", m_decrypted_message, sizeof(m_decrypted_message));
  }
  
  if (memcmp(m_message, m_decrypted_message, sizeof(m_message)) == 0) {
    m_aes_test_success = true;
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Sha256 test
  ///////////////////////////////////////////////////////////////////////////////////

  ret_val = ndn_lite_sha256_tinycrypt(m_message, sizeof(m_message), m_sha256_result);
  if (ret_val == NDN_SUCCESS) {
    m_sha256_test_success = true;
    APP_LOG("Call to ndn_lite_sha256_tinycrypt succeeded.\n");
    APP_LOG_HEX("Hash of message:", m_sha256_result, NDN_SEC_SHA256_HASH_SIZE);
  }
  else {
    APP_LOG("Call to ndn_lite_sha256_tinycrypt failed, error code: %d\n", ret_val);
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Hmac test
  ///////////////////////////////////////////////////////////////////////////////////

  bool ndn_lite_hmac_sha256_tinycrypt_call_success = false;
  bool ndn_lite_hmac_make_key_tinycrypt_call_success = false;

  ret_val = ndn_lite_hmac_sha256_tinycrypt(m_raw_sym_key, sizeof(m_raw_sym_key),
                                           m_message, sizeof(m_message), 
                                           m_hmac_result);
  if (ret_val == NDN_SUCCESS) {
    ndn_lite_hmac_sha256_tinycrypt_call_success = true;
    APP_LOG("Call to ndn_lite_hmac_sign_tinycrypt succeeded.\n");
    APP_LOG_HEX("Hmac signature of message:", m_hmac_result, NDN_SEC_SHA256_HASH_SIZE);
  }
  else {
    APP_LOG("Call to ndn_lite_hmac_sign_tinycrypt failed, error code: %d\n", ret_val);
  }

  ndn_hmac_key_t ndn_hmac_key_1;
  uint32_t random_key_id_1 = 5;

  // I just passed random buffers / values in for most of these arguments
  ret_val = ndn_lite_hmac_make_key_tinycrypt(&ndn_hmac_key_1, random_key_id_1,
                                             m_message, sizeof(m_message),
                                             m_rng_seed_1, sizeof(m_rng_seed_1),
                                             m_rng_seed_2, sizeof(m_rng_seed_2),
                                             m_raw_sym_key, sizeof(m_raw_sym_key),
                                             4);
  if (ret_val == NDN_SUCCESS) {
    ndn_lite_hmac_make_key_tinycrypt_call_success = true;
    APP_LOG("Call to ndn_lite_hmac_make_key_tinycrypt succeeded.\n");
    APP_LOG_HEX("Bytes of generated hmac key:", ndn_hmac_key_1.key_value, ndn_hmac_key_1.key_size);
  }
  else {
    APP_LOG("Call to ndn_lite_hmac_make_key_tinycrypt failed, error code: %d\n", ret_val);
  }

  if (ndn_lite_hmac_sha256_tinycrypt_call_success &&
      ndn_lite_hmac_make_key_tinycrypt_call_success) {
    APP_LOG("Both ndn_lite_hmac_sha256_tinycrypt_call_success "
            "and ndn_lite_hmac_make_key_tinycrypt_call_success were "
            "true, considering this a success.\n");
    m_hmac_test_success = true;
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Rng hkdf test
  ///////////////////////////////////////////////////////////////////////////////////

  bool first_ndn_lite_random_hkdf_tinycrypt_call_succeeded = false;
  bool second_ndn_lite_random_hkdf_tinycrypt_call_succeeded = false;

  ret_val = ndn_lite_random_hkdf_tinycrypt(m_message, sizeof(m_message), 
                                 m_rng_result_1, sizeof(m_rng_result_1), 
                                 m_rng_seed_1, sizeof(m_rng_seed_1));
  if (ret_val == NDN_SUCCESS) {
    first_ndn_lite_random_hkdf_tinycrypt_call_succeeded = true;
    APP_LOG("First call to ndn_lite_random_hkdf_tinycrypt succeeded.\n");
    APP_LOG_HEX("First random number generated:", m_rng_result_1, sizeof(m_rng_result_1));
  }
  else {
    APP_LOG("First call to ndn_lite_random_hkdf_tinycrypt failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_lite_random_hkdf_tinycrypt(m_message, sizeof(m_message), 
                                 m_rng_result_2, sizeof(m_rng_result_2), 
                                 m_rng_seed_2, sizeof(m_rng_seed_2));
  if (ret_val == NDN_SUCCESS) {
    second_ndn_lite_random_hkdf_tinycrypt_call_succeeded = true;
    APP_LOG("Second call to ndn_lite_random_hkdf_tinycrypt succeeded.\n");
    APP_LOG_HEX("Second random number generated:", m_rng_result_2, sizeof(m_rng_result_2));
  }
  else {
    APP_LOG("Second call to ndn_lite_random_hkdf_tinycrypt failed, error code: %d\n", ret_val);
  }

  if (first_ndn_lite_random_hkdf_tinycrypt_call_succeeded &&
      second_ndn_lite_random_hkdf_tinycrypt_call_succeeded &&
      memcmp(m_rng_result_1, m_rng_result_2, RNG_TEST_BUFFER_SIZE) != 0) {
    APP_LOG("Both calls to ndn_lite_random_hkdf_tinycrypt succeeded, and their generated "
            "random numbers were different; considering this a success.\n");
    m_rng_hkdf_test_success = true;
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Rng hmacprng test
  ///////////////////////////////////////////////////////////////////////////////////

  bool first_ndn_lite_random_hmacprng_tinycrypt_call_succeeded = false;
  bool second_ndn_lite_random_hmacprng_tinycrypt_call_succeeded = false;

  ret_val = ndn_lite_random_hmacprng_tinycrypt(m_message, sizeof(m_message), 
                                               m_rng_result_1, sizeof(m_rng_result_1), 
                                               m_rng_seed_1, sizeof(m_rng_seed_1), 
                                               m_rng_additional_val_1, 
                                               sizeof(m_rng_additional_val_1));
  if (ret_val == NDN_SUCCESS) {
    first_ndn_lite_random_hmacprng_tinycrypt_call_succeeded = true;
    APP_LOG("First call to ndn_lite_random_hkdf_tinycrypt succeeded.\n");
    APP_LOG_HEX("First random number generated:", m_rng_result_1, sizeof(m_rng_result_1));
  }
  else {
    APP_LOG("First call to ndn_lite_random_hmacprng_tinycrypt failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_lite_random_hmacprng_tinycrypt(m_message, sizeof(m_message), 
                                               m_rng_result_2, sizeof(m_rng_result_2), 
                                               m_rng_seed_2, sizeof(m_rng_seed_2), 
                                               m_rng_additional_val_2, 
                                               sizeof(m_rng_additional_val_2));
  if (ret_val == NDN_SUCCESS) {
    second_ndn_lite_random_hmacprng_tinycrypt_call_succeeded = true;
    APP_LOG("Second call to ndn_lite_random_hkdf_tinycrypt succeeded.\n");
    APP_LOG_HEX("Second random number generated:", m_rng_result_2, sizeof(m_rng_result_2));
  }
  else {
    APP_LOG("Second call to ndn_lite_random_hmacprng_tinycrypt failed, error code: %d\n", ret_val);
  }

  if (first_ndn_lite_random_hmacprng_tinycrypt_call_succeeded &&
      second_ndn_lite_random_hmacprng_tinycrypt_call_succeeded &&
      memcmp(m_rng_result_1, m_rng_result_2, RNG_TEST_BUFFER_SIZE) != 0) {
    APP_LOG("Both calls to ndn_lite_random_hmacprng_tinycrypt succeeded, and their generated "
            "random numbers were different; considering this a success.\n");
    m_rng_hmacprng_test_success = true;
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Ecc test (tinycrypt backend)
  ///////////////////////////////////////////////////////////////////////////////////

  ndn_ecc_pub_t ndn_pub_key_1;
  ndn_ecc_prv_t ndn_prv_key_1;
  ndn_ecc_pub_t ndn_pub_key_2;
  ndn_ecc_prv_t ndn_prv_key_2;
  uint32_t random_key_id = 1;
  ret_val = ndn_lite_ecc_key_make_key_tinycrypt(&ndn_pub_key_1, &ndn_prv_key_1,
                                                NDN_ECDSA_CURVE_SECP256R1,
                                                random_key_id);
  if (ret_val == NDN_SUCCESS) {
    APP_LOG("First call to ndn_lite_ecc_key_make_key_tinycrypt succeeded.\n");
    APP_LOG_HEX("Value of generated public key:", ndn_pub_key_1.key_value, ndn_pub_key_1.key_size);
    APP_LOG_HEX("Value of generated private key:", ndn_prv_key_1.key_value, ndn_prv_key_1.key_size);
  }
  else {
    APP_LOG("First call to ndn_lite_ecc_key_make_key_tinycrypt failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_lite_ecc_key_make_key_tinycrypt(&ndn_pub_key_2, &ndn_prv_key_2,
                                                NDN_ECDSA_CURVE_SECP256R1,
                                                random_key_id);
  if (ret_val == NDN_SUCCESS) {
    APP_LOG("Second call to ndn_lite_ecc_key_make_key_tinycrypt succeeded.\n");
    APP_LOG_HEX("Value of generated public key:", ndn_pub_key_2.key_value, ndn_pub_key_2.key_size);
    APP_LOG_HEX("Value of generated private key:", ndn_prv_key_2.key_value, ndn_prv_key_2.key_size);
  }
  else {
    APP_LOG("Second call to ndn_lite_ecc_key_make_key_tinycrypt failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_lite_ecc_key_shared_secret_tinycrypt(
                                             &ndn_pub_key_1, &ndn_prv_key_2,
                                             NDN_ECDSA_CURVE_SECP256R1, 
                                             m_gen_shared_secret_1, 
                                             sizeof(m_gen_shared_secret_1));
  if (ret_val == NDN_SUCCESS) {
    APP_LOG("First call to ndn_lite_ecc_key_shared_secret_tinycrypt succeeded.\n");
    APP_LOG_HEX("First generated shared secret:", m_gen_shared_secret_1, 
                 sizeof(m_gen_shared_secret_1));
  }
  else {
    APP_LOG("First call to ndn_lite_ecc_key_shared_secret_tinycrypt "
            "failed, error code: %d\n", ret_val);
  }

    ret_val = ndn_lite_ecc_key_shared_secret_tinycrypt(
                                             &ndn_pub_key_2, &ndn_prv_key_1,
                                             NDN_ECDSA_CURVE_SECP256R1, 
                                             m_gen_shared_secret_2, 
                                             sizeof(m_gen_shared_secret_2));
  if (ret_val == NDN_SUCCESS) {
    APP_LOG("Second call to ndn_lite_ecc_key_shared_secret_tinycrypt succeeded.\n");
    APP_LOG_HEX("Second generated shared secret:", m_gen_shared_secret_2, 
                 sizeof(m_gen_shared_secret_2));
  }
  else {
    APP_LOG("Second call to ndn_lite_ecc_key_shared_secret_tinycrypt "
            "failed, error code: %d\n", ret_val);
  }

  if (memcmp(m_gen_shared_secret_1, m_gen_shared_secret_2, ECC_SHARED_SECRET_BUFFER_SIZE) == 0) {
    APP_LOG("Both generated shared secrets were equal; considering this a success.\n");
    m_ecc_tinycrypt_test_success = true;
  }                              

  ///////////////////////////////////////////////////////////////////////////////////

  // Ecc test (microecc backend)
  ///////////////////////////////////////////////////////////////////////////////////

  bool ndn_lite_ecdsa_sign_microecc_call_success = false;
  bool ndn_lite_ecdsa_verify_microecc_call_success = false;

  APP_LOG_HEX("Value of signature buffer before generating signature:", 
              m_signature, sizeof(m_signature));
  uint32_t ecdsa_sig_size;
  ret_val = ndn_lite_ecdsa_sign_microecc(m_message, sizeof(m_message), 
                                         m_signature, sizeof(m_signature),  
                                         m_raw_ecc_private_key_1, sizeof(m_raw_ecc_private_key_1), 
                                         NDN_ECDSA_CURVE_SECP256R1, &ecdsa_sig_size);
  if (ret_val == NDN_SUCCESS) {
    ndn_lite_ecdsa_sign_microecc_call_success = true;
    APP_LOG("Call to ndn_lite_ecdsa_sign_microecc succeeded.\n");
    APP_LOG("Size of signature generated: %d\n", ecdsa_sig_size);
    APP_LOG_HEX("Value of signature generated:", m_signature, ecdsa_sig_size);
  }
  else {
    APP_LOG("Call to ndn_lite_ecdsa_sign_microecc failed, error code: %d\n", ret_val);
  }

  ret_val = ndn_lite_ecdsa_verify_microecc(m_message, sizeof(m_message), 
                                           m_signature, sizeof(m_signature), 
                                           m_raw_ecc_public_key_1, sizeof(m_raw_ecc_public_key_1), 
                                           NDN_ECDSA_CURVE_SECP256R1);
  if (ret_val == NDN_SUCCESS) {
    ndn_lite_ecdsa_verify_microecc_call_success = true;
    APP_LOG("Call to ndn_lite_ecdsa_verify_microecc succeeded.\n");
  }
  else {
    APP_LOG("Call to ndn_lite_ecdsa_verify_microecc failed, error code: %d\n", ret_val);
  }

  if (ndn_lite_ecdsa_sign_microecc_call_success && ndn_lite_ecdsa_verify_microecc_call_success) {
    m_ecc_microecc_test_success = true;
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Check that all tests succeeded
  ///////////////////////////////////////////////////////////////////////////////////
  APP_LOG("Results of all security tests:\n");
  APP_LOG("AES test result: %d\n", m_aes_test_success);
  APP_LOG("Sha256 test result: %d\n", m_sha256_test_success);
  APP_LOG("Hmac test result: %d\n", m_hmac_test_success);
  APP_LOG("Rng hkdf test result: %d\n", m_rng_hkdf_test_success);
  APP_LOG("Rng hmacprng test result: %d\n", m_rng_hmacprng_test_success);
  APP_LOG("Ecc test (microecc backend) result: %d\n", m_ecc_microecc_test_success);
  APP_LOG("Ecc test (tinycrypt backend) result: %d\n", m_ecc_tinycrypt_test_success);

  if (m_aes_test_success && 
      m_sha256_test_success &&
      m_hmac_test_success &&
      m_rng_hkdf_test_success &&
      m_rng_hmacprng_test_success &&
      m_ecc_microecc_test_success &&
      m_ecc_tinycrypt_test_success) {
    APP_LOG("ALL TESTS SUCCEEDED.\n");
  }
  else {
    APP_LOG("ONE OR MORE TESTS FAILED.\n");
  }

  ///////////////////////////////////////////////////////////////////////////////////

  // Enter main loop.
  for (;;) {
    idle_state_handle();
  }
}

/**
 * @}
 */