


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
#include "ndn_standalone/security/detail/detail-aes/ndn-lite-aes-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-sha256/ndn-lite-sha256-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-hmac/ndn-lite-hmac-tinycrypt-impl.h"
#include "ndn_standalone/security/detail/detail-rng/ndn-lite-rng-tinycrypt-impl.h"
#include "ndn_standalone/ndn-enums.h"
#include "ndn_standalone/ndn-error-code.h"

#include "ndn_standalone/adaptation/ndn-nrf-ble-adaptation/logger.h"

bool m_aes_test_success = false;
bool m_sha256_test_success = false;
bool m_hmac_test_success = false;
bool m_rng_hkdf_test_success = false;
bool m_rng_hmacprng_test_success = false;

static const uint8_t m_raw_ecc_private_key[] =
{
  0xD8, 0x9A, 0x9E, 0xD9, 0xD4, 0x5A, 0xFD, 0xA1, 0xE5, 0xA4, 
  0x29, 0x73, 0x2B, 0x18, 0xE5, 0x51, 0xC4, 0xB0, 0x77, 0xEF, 
  0xA3, 0x5E, 0xB3, 0x55, 0x63, 0x73, 0xBC, 0x13, 0xBE, 0xE2, 
  0x5C, 0x2C,
};

static const uint8_t m_raw_ecc_public_key[] =
{
  0x41, 0xA0, 0x02, 0x0C, 0x65, 0xCA, 0x1B, 0xD0, 0xB4, 0x4B, 
  0x0B, 0xC9, 0xD3, 0x92, 0xE2, 0x14, 0xDB, 0x7A, 0x97, 0xC3, 
  0x22, 0xEA, 0xC7, 0xD7, 0xEA, 0x05, 0x77, 0xFB, 0x74, 0x4C, 
  0xC0, 0x86, 0x8F, 0xA6, 0xF9, 0x21, 0x72, 0x38, 0x92, 0xF3, 
  0x69, 0xA9, 0xAA, 0x82, 0xE0, 0xEC, 0x69, 0x77, 0x59, 0xA8, 
  0x6C, 0x5E, 0x7D, 0x74, 0x96, 0x1D, 0xB9, 0xCD, 0x9A, 0x3D, 
  0xC0, 0x2F, 0x86, 0x4A,
};

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

  ret_val = ndn_lite_hmac_sha256_tinycrypt(m_raw_sym_key, sizeof(m_raw_sym_key),
                                           m_message, sizeof(m_message), 
                                           m_hmac_result);
  if (ret_val == NDN_SUCCESS) {
    m_hmac_test_success = true;
    APP_LOG("Call to ndn_lite_hmac_sign_tinycrypt succeeded.\n");
    APP_LOG_HEX("Hmac signature of message:", m_hmac_result, NDN_SEC_SHA256_HASH_SIZE);
  }
  else {
    APP_LOG("Call to ndn_lite_hmac_sign_tinycrypt failed, error code: %d\n", ret_val);
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

  // Check that all tests succeeded
  ///////////////////////////////////////////////////////////////////////////////////
  APP_LOG("Results of all security tests:\n");
  APP_LOG("AES test result: %d\n", m_aes_test_success);
  APP_LOG("Sha256 test result: %d\n", m_sha256_test_success);
  APP_LOG("Hmac test result: %d\n", m_hmac_test_success);
  APP_LOG("Rng hkdf test result: %d\n", m_rng_hkdf_test_success);
  APP_LOG("Rng hmacprng test result: %d\n", m_rng_hmacprng_test_success);

  if (m_aes_test_success && 
      m_sha256_test_success &&
      m_hmac_test_success &&
      m_rng_hkdf_test_success &&
      m_rng_hmacprng_test_success) {
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