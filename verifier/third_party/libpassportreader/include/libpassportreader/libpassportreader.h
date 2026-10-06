#ifndef LIBPASSPORTREADER_H
#define LIBPASSPORTREADER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  PASSPORTREADER_FRAME_ORIENTATION_0 = 0,
  PASSPORTREADER_FRAME_ORIENTATION_90 = 1,
  PASSPORTREADER_FRAME_ORIENTATION_180 = 2,
  PASSPORTREADER_FRAME_ORIENTATION_270 = 3
} passportreader_frame_orientation_t;

typedef enum {
  // YCbCr conversion uses BT.709 coefficients. Specify the source range;
  // range is ignored for Y-only images.
  PASSPORTREADER_COLOR_RANGE_FULL = 1,
  PASSPORTREADER_COLOR_RANGE_LIMITED = 2
} passportreader_color_range_t;

typedef struct {
  const unsigned char *data;
  size_t length;
} passportreader_bytes_t;

typedef struct {
  unsigned int width;
  unsigned int height;
  passportreader_frame_orientation_t orientation;
  passportreader_bytes_t y;
  passportreader_bytes_t cb;
  passportreader_bytes_t cr;
  passportreader_color_range_t color_range;
} passportreader_frame_t;

typedef struct {
  const passportreader_frame_t *frames;
  size_t count;
} passportreader_frames_t;

typedef struct {
  const passportreader_bytes_t *certificates;
  size_t count;
} passportreader_csca_certificates_t;

typedef struct {
  unsigned char *data;
  size_t length;
} passportreader_bytes_result_t;

typedef struct {
  char *data;
  size_t length;
} passportreader_string_result_t;

typedef struct {
  const unsigned char *data;
  unsigned int row_stride;
  unsigned int pixel_stride;
} passportreader_image_plane_t;

typedef enum {
  PASSPORTREADER_IMAGE_FORMAT_Y = 0,
  PASSPORTREADER_IMAGE_FORMAT_YCBCR_420_BIPLANAR = 1,
  PASSPORTREADER_IMAGE_FORMAT_YCBCR_420_TRIPLANAR = 2
} passportreader_image_format_t;

typedef struct {
  passportreader_image_format_t format;
  passportreader_image_plane_t planes[3];
  size_t plane_count;
  unsigned int width;
  unsigned int height;
  passportreader_frame_orientation_t orientation;
  passportreader_color_range_t color_range;
} passportreader_image_t;

typedef enum {
  PASSPORTREADER_MRZ_SCANNER_INITIATED,
  PASSPORTREADER_MRZ_SCANNER_COMPLETED
} passportreader_mrz_scanner_state_t;

typedef enum {
  PASSPORTREADER_CHIP_READER_INITIATED,
  PASSPORTREADER_CHIP_READER_FAILED,
  PASSPORTREADER_CHIP_READER_COMPLETED
} passportreader_chip_reader_state_t;

typedef enum {
  PASSPORTREADER_FACE_VERIFICATION_INITIATED,
  PASSPORTREADER_FACE_VERIFICATION_COMPLETED
} passportreader_face_verification_state_t;

typedef enum {
  PASSPORTREADER_QR_CODE_SCANNER_INITIATED,
  PASSPORTREADER_QR_CODE_SCANNER_COMPLETED
} passportreader_qr_code_scanner_state_t;

typedef enum {
  PASSPORTREADER_SM_PROTOCOL_BAC_DES = 0,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_GM_DES = 1,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_GM_AES_128 = 2,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_GM_AES_192 = 3,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_GM_AES_256 = 4,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_IM_DES = 5,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_IM_AES_128 = 6,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_IM_AES_192 = 7,
  PASSPORTREADER_SM_PROTOCOL_PACE_DH_IM_AES_256 = 8,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_GM_DES = 9,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_GM_AES_128 = 10,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_GM_AES_192 = 11,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_GM_AES_256 = 12,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_IM_DES = 13,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_IM_AES_128 = 14,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_IM_AES_192 = 15,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_IM_AES_256 = 16,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_CAM_AES_128 = 17,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_CAM_AES_192 = 18,
  PASSPORTREADER_SM_PROTOCOL_PACE_ECDH_CAM_AES_256 = 19,
  PASSPORTREADER_SM_PROTOCOL_CA_DH_DES = 20,
  PASSPORTREADER_SM_PROTOCOL_CA_DH_AES_128 = 21,
  PASSPORTREADER_SM_PROTOCOL_CA_DH_AES_192 = 22,
  PASSPORTREADER_SM_PROTOCOL_CA_DH_AES_256 = 23,
  PASSPORTREADER_SM_PROTOCOL_CA_ECDH_DES = 24,
  PASSPORTREADER_SM_PROTOCOL_CA_ECDH_AES_128 = 25,
  PASSPORTREADER_SM_PROTOCOL_CA_ECDH_AES_192 = 26,
  PASSPORTREADER_SM_PROTOCOL_CA_ECDH_AES_256 = 27
} passportreader_sm_protocol_t;

typedef struct passportreader_mrz_scanner passportreader_mrz_scanner_t;
typedef struct passportreader_chip_reader passportreader_chip_reader_t;
typedef struct passportreader_face_verification
    passportreader_face_verification_t;
typedef struct passportreader_qr_code_scanner passportreader_qr_code_scanner_t;
typedef struct passportreader_face_index passportreader_face_index_t;
typedef struct passportreader_memory_storage passportreader_memory_storage_t;
typedef struct passportreader_file_storage passportreader_file_storage_t;

typedef struct passportreader_chip_reader_pending_operation
    passportreader_chip_reader_pending_operation_t;

typedef struct {
  passportreader_mrz_scanner_state_t state;
} passportreader_mrz_scanner_status_t;

typedef struct {
  passportreader_mrz_scanner_state_t state;
  const char *const *keys;
  size_t key_count;
} passportreader_mrz_scanner_result_t;

typedef struct {
  passportreader_face_verification_state_t state;
} passportreader_face_verification_status_t;

typedef struct {
  passportreader_face_verification_state_t state;
  passportreader_frames_t frames;
  // Match score in [0, 1]; higher is a stronger match.
  float score;
  // PNG image of the selected live face when verification is completed.
  passportreader_bytes_t face;
} passportreader_face_verification_result_t;

typedef struct {
  // Match score in [0, 1]; higher is a stronger match.
  float score;
  passportreader_bytes_t face;
} passportreader_face_verification_verify_result_t;

// Storage callbacks return 0 on success and 1 on failure.
typedef struct {
  int (*read)(void *context, uint64_t offset, void *buffer, size_t size);
  int (*write)(void *context, uint64_t offset, const void *buffer, size_t size);
  int (*resize)(void *context, uint64_t size);
  void *context;
} passportreader_storage_t;

typedef struct {
  uint64_t id;
  // Match score in [0, 1]; higher is a stronger match.
  float score;
} passportreader_face_index_search_result_t;

enum { PASSPORTREADER_FACE_INDEX_REBUILD_REQUIRED = 2 };

typedef struct {
  passportreader_qr_code_scanner_state_t state;
} passportreader_qr_code_scanner_status_t;

typedef struct {
  passportreader_qr_code_scanner_state_t state;
  const char *data;
} passportreader_qr_code_scanner_result_t;

typedef enum {
  PASSPORTREADER_CHIP_READER_OPERATION_NONE = 0,
  PASSPORTREADER_CHIP_READER_OPERATION_PACE_CAM_GENERATE_MAPPING_KEY = 1,
  PASSPORTREADER_CHIP_READER_OPERATION_PACE_CAM_GENERATE_EPHEMERAL_KEY = 2,
  PASSPORTREADER_CHIP_READER_OPERATION_PACE_CAM_DERIVE_KEYS = 3,
  PASSPORTREADER_CHIP_READER_OPERATION_CA_V1_GENERATE_EPHEMERAL_KEY = 4,
  PASSPORTREADER_CHIP_READER_OPERATION_CA_V2_GENERATE_EPHEMERAL_KEY = 5,
  PASSPORTREADER_CHIP_READER_OPERATION_AA_GENERATE_NONCE = 6
} passportreader_chip_reader_operation_t;

typedef struct {
  passportreader_sm_protocol_t sm_protocol;
  unsigned int parameter_id;
} passportreader_chip_reader_pace_cam_generate_mapping_key_request_t;

typedef struct {
  passportreader_bytes_t nonce;
  passportreader_bytes_t chip_mapping_public_key;
} passportreader_chip_reader_pace_cam_generate_ephemeral_key_request_t;

typedef struct {
  passportreader_bytes_t chip_key_agreement_public_key;
} passportreader_chip_reader_pace_cam_derive_keys_request_t;

typedef struct {
  passportreader_sm_protocol_t sm_protocol;
  passportreader_bytes_t chip_public_key;
} passportreader_chip_reader_ca_v1_generate_ephemeral_key_request_t;

typedef struct {
  passportreader_sm_protocol_t sm_protocol;
  passportreader_bytes_t chip_public_key;
} passportreader_chip_reader_ca_v2_generate_ephemeral_key_request_t;

typedef struct {
  unsigned char unused;
} passportreader_chip_reader_aa_generate_nonce_request_t;

typedef struct {
  passportreader_chip_reader_state_t state;
  float progress;
  const passportreader_chip_reader_pending_operation_t *pending_operation;
} passportreader_chip_reader_status_t;

typedef struct {
  passportreader_chip_reader_state_t state;
  unsigned int error;
  const char *message;
  const char *given_names;
  const char *surname;
  const char *nationality;
  const char *sex;
  const char *date_of_birth;
  const char *optional_data;
  const char *optional_data2;
  const char *issuing_country;
  const char *document_number;
  const char *expiry_date;
  const char *document_type;
  const char *issuer;
  const char *dsc;
  const char *personal_number;
  const char *place_of_birth;
  passportreader_bytes_t portrait;
  int document_integrity_verified;
  int active_authentication;
  int chip_authentication;
  passportreader_bytes_t ef_cardaccess;
  passportreader_bytes_t ef_cardsecurity;
  passportreader_bytes_t ef_sod;
  passportreader_bytes_t ef_dg1;
  passportreader_bytes_t ef_dg2;
  passportreader_bytes_t ef_dg11;
  passportreader_bytes_t ef_dg14;
  passportreader_bytes_t ef_dg15;
  passportreader_bytes_t pace_cam_encrypted_chip_authentication_data;
  passportreader_bytes_t ca_v1_probe_response_apdu;
  passportreader_bytes_t ca_v2_nonce;
  passportreader_bytes_t ca_v2_authentication_token;
  passportreader_bytes_t aa_signature;
  passportreader_sm_protocol_t sm_protocol;
} passportreader_chip_reader_result_t;

typedef union {
  const passportreader_chip_reader_pace_cam_generate_mapping_key_request_t
      *pace_cam_generate_mapping_key;
  const passportreader_chip_reader_pace_cam_generate_ephemeral_key_request_t
      *pace_cam_generate_ephemeral_key;
  const passportreader_chip_reader_pace_cam_derive_keys_request_t
      *pace_cam_derive_keys;
  const passportreader_chip_reader_ca_v1_generate_ephemeral_key_request_t
      *ca_v1_generate_ephemeral_key;
  const passportreader_chip_reader_ca_v2_generate_ephemeral_key_request_t
      *ca_v2_generate_ephemeral_key;
  const passportreader_chip_reader_aa_generate_nonce_request_t
      *aa_generate_nonce;
} passportreader_chip_reader_operation_request_t;

struct passportreader_chip_reader_pending_operation {
  passportreader_chip_reader_operation_t operation;
  uint64_t operation_id;
  passportreader_chip_reader_operation_request_t request;
};

typedef struct {
  passportreader_bytes_t terminal_mapping_public_key;
  passportreader_bytes_t mapping_private_key;
} passportreader_chip_reader_generate_pace_cam_mapping_key_result_t;

typedef struct {
  passportreader_bytes_t terminal_key_agreement_public_key;
  passportreader_bytes_t ephemeral_private_key;
} passportreader_chip_reader_generate_pace_cam_ephemeral_key_result_t;

typedef struct {
  passportreader_bytes_t terminal_authentication_token;
  passportreader_bytes_t encryption_key;
  passportreader_bytes_t mac_key;
} passportreader_chip_reader_derive_pace_cam_keys_result_t;

typedef struct {
  passportreader_bytes_t terminal_public_key;
  passportreader_bytes_t probe_command_apdu;
  passportreader_bytes_t private_key;
} passportreader_chip_reader_generate_ca_v1_ephemeral_key_result_t;

typedef struct {
  passportreader_bytes_t terminal_public_key;
  passportreader_bytes_t private_key;
} passportreader_chip_reader_generate_ca_v2_ephemeral_key_result_t;

typedef struct {
  passportreader_bytes_t nonce;
} passportreader_chip_reader_generate_aa_nonce_result_t;

typedef struct {
  const char *given_names;
  const char *surname;
  const char *nationality;
  const char *sex;
  const char *date_of_birth;
  const char *optional_data;
  const char *optional_data2;
  const char *issuing_country;
  const char *document_number;
  const char *expiry_date;
  const char *document_type;
  const char *issuer;
  const char *dsc;
  const char *personal_number;
  const char *place_of_birth;
  const char *csca_certificate_fingerprint;
  passportreader_bytes_t portrait;
  int document_integrity_verified;
  int active_authentication;
  int chip_authentication;
  passportreader_sm_protocol_t sm_protocol;
  passportreader_bytes_t ef_cardaccess;
  passportreader_bytes_t ef_cardsecurity;
  passportreader_bytes_t ef_sod;
  passportreader_bytes_t ef_dg1;
  passportreader_bytes_t ef_dg2;
  passportreader_bytes_t ef_dg11;
  passportreader_bytes_t ef_dg14;
  passportreader_bytes_t ef_dg15;
} passportreader_chip_reader_verify_result_t;

// All functions return 0 on success and 1 on failure. Output pointers must be
// non-null. A successful call can report a failed scan or failed verification
// in its status or result. Pointer inputs are borrowed for the call unless
// documented otherwise. Output data is caller-owned and remains valid until
// explicitly released. Release chip reader statuses with status_free and
// component results with their corresponding result_free function. Release
// an output before reusing its storage; shallow copies do not transfer
// ownership. Close and destroy functions accept null handles.
int passportreader_version(passportreader_string_result_t *result);

// Binary DER envelope v1. Keys use the same hex DER encoding as the tokenizer.
// Payloads and envelopes are limited to 64 MiB; RSA keys must be 2048–8192
// bits. Decrypt also accepts legacy ASCII base64url envelopes, using the
// supplied legacy key. Legacy envelopes have no key ID: envelope_key_id returns
// 1 and clears its result. key_id is an untrusted hint until successful
// decryption authenticates the envelope.
int passportreader_envelope_encrypt(passportreader_bytes_t payload,
                                    const char *public_key, uint32_t key_id,
                                    passportreader_bytes_result_t *result);
int passportreader_envelope_decrypt(passportreader_bytes_t envelope,
                                    const char *private_key,
                                    passportreader_bytes_result_t *result);
int passportreader_envelope_key_id(passportreader_bytes_t envelope,
                                   uint32_t *result);
int passportreader_bytes_result_free(passportreader_bytes_result_t *result);
int passportreader_bytes_free(passportreader_bytes_t *result);
int passportreader_string_result_free(passportreader_string_result_t *result);

int passportreader_mrz_scanner_result_free(
    passportreader_mrz_scanner_result_t *result);
int passportreader_mrz_scanner_create(passportreader_mrz_scanner_t **scanner);
int passportreader_mrz_scanner_initiate(passportreader_mrz_scanner_t *scanner,
                                        int passport_only);
int passportreader_mrz_scanner_process(
    passportreader_mrz_scanner_t *scanner, const passportreader_image_t *image,
    passportreader_mrz_scanner_status_t *status);
// Copies the current state and keys. Free the result with
// passportreader_mrz_scanner_result_free.
int passportreader_mrz_scanner_result(
    passportreader_mrz_scanner_t *scanner,
    passportreader_mrz_scanner_result_t *result);
int passportreader_mrz_scanner_destroy(passportreader_mrz_scanner_t *scanner);

int passportreader_chip_reader_result_free(
    passportreader_chip_reader_result_t *result);
// Releases the pending operation returned by next_command_apdu.
int passportreader_chip_reader_status_free(
    passportreader_chip_reader_status_t *status);
int passportreader_chip_reader_create(passportreader_chip_reader_t **reader);
int passportreader_chip_reader_initiate(passportreader_chip_reader_t *reader,
                                        const char *const *keys,
                                        size_t key_count);
// On insufficient capacity, returns 1, writes the required length, and leaves
// data untouched. The command is retained so the call can be retried with a
// larger buffer. A null data pointer is allowed when capacity is 0.
int passportreader_chip_reader_next_command_apdu(
    passportreader_chip_reader_t *reader, unsigned char *data, size_t capacity,
    size_t *length, passportreader_chip_reader_status_t *status);
// Copies the current state and document data, including after a platform NFC
// failure.
// Free the result with passportreader_chip_reader_result_free.
int passportreader_chip_reader_result(
    passportreader_chip_reader_t *reader,
    passportreader_chip_reader_result_t *result);
int passportreader_chip_reader_process_response_apdu(
    passportreader_chip_reader_t *reader, const unsigned char *data,
    size_t length, unsigned int sw1, unsigned int sw2);
int passportreader_chip_reader_retry(passportreader_chip_reader_t *reader);
int passportreader_chip_reader_complete_pace_cam_mapping_key(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t terminal_mapping_public_key);
int passportreader_chip_reader_complete_pace_cam_ephemeral_key(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t terminal_key_agreement_public_key);
int passportreader_chip_reader_complete_pace_cam_keys(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t terminal_authentication_token,
    passportreader_bytes_t encryption_key, passportreader_bytes_t mac_key);
int passportreader_chip_reader_complete_ca_v1_ephemeral_key(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t terminal_public_key,
    passportreader_bytes_t probe_command_apdu);
int passportreader_chip_reader_complete_ca_v2_ephemeral_key(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t terminal_public_key);
int passportreader_chip_reader_complete_aa_nonce(
    passportreader_chip_reader_t *reader, uint64_t operation_id,
    passportreader_bytes_t nonce);
int passportreader_chip_reader_destroy(passportreader_chip_reader_t *reader);

int passportreader_chip_reader_generate_pace_cam_mapping_key(
    passportreader_sm_protocol_t sm_protocol, unsigned int parameter_id,
    passportreader_chip_reader_generate_pace_cam_mapping_key_result_t *result);
int passportreader_chip_reader_generate_pace_cam_mapping_key_result_free(
    passportreader_chip_reader_generate_pace_cam_mapping_key_result_t *result);
int passportreader_chip_reader_generate_pace_cam_ephemeral_key(
    passportreader_sm_protocol_t sm_protocol, unsigned int parameter_id,
    passportreader_bytes_t mapping_private_key, passportreader_bytes_t nonce,
    passportreader_bytes_t chip_mapping_public_key,
    passportreader_chip_reader_generate_pace_cam_ephemeral_key_result_t
        *result);
int passportreader_chip_reader_generate_pace_cam_ephemeral_key_result_free(
    passportreader_chip_reader_generate_pace_cam_ephemeral_key_result_t
        *result);
int passportreader_chip_reader_derive_pace_cam_keys(
    passportreader_sm_protocol_t sm_protocol, unsigned int parameter_id,
    passportreader_bytes_t mapping_private_key, passportreader_bytes_t nonce,
    passportreader_bytes_t chip_mapping_public_key,
    passportreader_bytes_t ephemeral_private_key,
    passportreader_bytes_t chip_key_agreement_public_key,
    passportreader_chip_reader_derive_pace_cam_keys_result_t *result);
int passportreader_chip_reader_derive_pace_cam_keys_result_free(
    passportreader_chip_reader_derive_pace_cam_keys_result_t *result);
int passportreader_chip_reader_generate_ca_v1_ephemeral_key(
    passportreader_sm_protocol_t sm_protocol,
    passportreader_bytes_t chip_public_key,
    passportreader_chip_reader_generate_ca_v1_ephemeral_key_result_t *result);
int passportreader_chip_reader_generate_ca_v1_ephemeral_key_result_free(
    passportreader_chip_reader_generate_ca_v1_ephemeral_key_result_t *result);
int passportreader_chip_reader_generate_ca_v2_ephemeral_key(
    passportreader_sm_protocol_t sm_protocol,
    passportreader_bytes_t chip_public_key,
    passportreader_chip_reader_generate_ca_v2_ephemeral_key_result_t *result);
int passportreader_chip_reader_generate_ca_v2_ephemeral_key_result_free(
    passportreader_chip_reader_generate_ca_v2_ephemeral_key_result_t *result);
int passportreader_chip_reader_generate_aa_nonce(
    passportreader_chip_reader_generate_aa_nonce_result_t *result);
int passportreader_chip_reader_generate_aa_nonce_result_free(
    passportreader_chip_reader_generate_aa_nonce_result_t *result);
int passportreader_chip_reader_verify(
    passportreader_bytes_t ef_cardaccess,
    passportreader_bytes_t ef_cardsecurity, passportreader_bytes_t ef_sod,
    passportreader_bytes_t ef_dg1, passportreader_bytes_t ef_dg2,
    passportreader_bytes_t ef_dg11, passportreader_bytes_t ef_dg14,
    passportreader_bytes_t ef_dg15, passportreader_sm_protocol_t sm_protocol,
    passportreader_csca_certificates_t csca_certificates,
    passportreader_sm_protocol_t pace_cam_protocol,
    unsigned int pace_cam_parameter_id,
    passportreader_bytes_t pace_cam_mapping_private_key,
    passportreader_bytes_t pace_cam_nonce,
    passportreader_bytes_t pace_cam_chip_mapping_public_key,
    passportreader_bytes_t pace_cam_ephemeral_private_key,
    passportreader_bytes_t pace_cam_chip_key_agreement_public_key,
    passportreader_bytes_t pace_cam_encrypted_chip_authentication_data,
    passportreader_sm_protocol_t ca_v1_protocol,
    passportreader_bytes_t ca_v1_chip_public_key,
    passportreader_bytes_t ca_v1_private_key,
    passportreader_bytes_t ca_v1_probe_response_apdu,
    passportreader_sm_protocol_t ca_v2_protocol,
    passportreader_bytes_t ca_v2_chip_public_key,
    passportreader_bytes_t ca_v2_private_key,
    passportreader_bytes_t ca_v2_nonce,
    passportreader_bytes_t ca_v2_authentication_token,
    passportreader_bytes_t aa_nonce, passportreader_bytes_t aa_signature,
    passportreader_chip_reader_verify_result_t *result);
int passportreader_chip_reader_verify_result_free(
    passportreader_chip_reader_verify_result_t *result);

int passportreader_face_verification_result_free(
    passportreader_face_verification_result_t *result);
int passportreader_face_verification_create(
    passportreader_face_verification_t **verification);
int passportreader_face_verification_initiate(
    passportreader_face_verification_t *verification,
    passportreader_bytes_t portrait);
int passportreader_face_verification_process(
    passportreader_face_verification_t *verification,
    const passportreader_image_t *image,
    passportreader_face_verification_status_t *status);
// Copies the current state, retained frames, match score, and face image.
// Free the result with passportreader_face_verification_result_free.
int passportreader_face_verification_result(
    passportreader_face_verification_t *verification,
    passportreader_face_verification_result_t *result);
int passportreader_face_verification_destroy(
    passportreader_face_verification_t *verification);

int passportreader_face_verification_verify(
    passportreader_bytes_t portrait, passportreader_frames_t frames,
    passportreader_face_verification_verify_result_t *result);
int passportreader_face_verification_verify_result_free(
    passportreader_face_verification_verify_result_t *result);

int passportreader_qr_code_scanner_result_free(
    passportreader_qr_code_scanner_result_t *result);
int passportreader_qr_code_scanner_create(
    passportreader_qr_code_scanner_t **scanner);
int passportreader_qr_code_scanner_initiate(
    passportreader_qr_code_scanner_t *scanner);
int passportreader_qr_code_scanner_process(
    passportreader_qr_code_scanner_t *scanner,
    const passportreader_image_t *image,
    passportreader_qr_code_scanner_status_t *status);
// Copies the current state and data. Free the result with
// passportreader_qr_code_scanner_result_free.
int passportreader_qr_code_scanner_result(
    passportreader_qr_code_scanner_t *scanner,
    passportreader_qr_code_scanner_result_t *result);
int passportreader_qr_code_scanner_destroy(
    passportreader_qr_code_scanner_t *scanner);

int passportreader_face_index_create(const passportreader_storage_t *storage,
                                     passportreader_face_index_t **output);
// Returns PASSPORTREADER_FACE_INDEX_REBUILD_REQUIRED when the index was
// created with a different face embeddings model.
int passportreader_face_index_open(const passportreader_storage_t *storage,
                                   passportreader_face_index_t **output);
int passportreader_face_index_add(passportreader_face_index_t *index,
                                  uint64_t id, passportreader_bytes_t face);
int passportreader_face_index_remove(passportreader_face_index_t *index,
                                     uint64_t id);
int passportreader_face_index_search(
    passportreader_face_index_t *index, passportreader_bytes_t face,
    passportreader_face_index_search_result_t *result, size_t result_capacity,
    size_t *result_count);
int passportreader_face_index_close(passportreader_face_index_t *index);

// Built-in storage descriptors retain their resource until storage_free.
// Face indexes retain built-in storage; custom callback contexts must outlive
// the index.
int passportreader_storage_free(passportreader_storage_t *storage);
int passportreader_memory_storage_create(
    passportreader_memory_storage_t **output);
int passportreader_memory_storage_get(passportreader_memory_storage_t *storage,
                                      passportreader_storage_t *output);
int passportreader_memory_storage_destroy(
    passportreader_memory_storage_t *storage);

int passportreader_file_storage_open(const char *path,
                                     passportreader_file_storage_t **output);
int passportreader_file_storage_get(passportreader_file_storage_t *storage,
                                    passportreader_storage_t *output);
int passportreader_file_storage_close(passportreader_file_storage_t *storage);

#ifdef __cplusplus
}
#endif

#endif
