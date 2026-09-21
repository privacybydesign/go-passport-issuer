#ifndef LIBPASSPORTREADER_H
#define LIBPASSPORTREADER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PASSPORTREADER_ROTATED_0 = 0,
    PASSPORTREADER_ROTATED_90 = 1,
    PASSPORTREADER_ROTATED_180 = 2,
    PASSPORTREADER_ROTATED_270 = 3
} passportreader_image_orientation_t;

typedef enum {
    PASSPORTREADER_MRZ_SCANNER_INITIATED = 0,
    PASSPORTREADER_MRZ_SCANNER_FAILED = 1,
    PASSPORTREADER_MRZ_SCANNER_COMPLETED = 2
} passportreader_mrz_scanner_state_t;

typedef enum {
    PASSPORTREADER_CHIP_READER_INITIATED = 0,
    PASSPORTREADER_CHIP_READER_FAILED = 1,
    PASSPORTREADER_CHIP_READER_COMPLETED = 2
} passportreader_chip_reader_state_t;

typedef enum {
    PASSPORTREADER_FACE_VERIFIER_INITIATED = 0,
    PASSPORTREADER_FACE_VERIFIER_FAILED = 1,
    PASSPORTREADER_FACE_VERIFIER_COMPLETED = 2
} passportreader_face_verifier_state_t;

typedef enum {
    PASSPORTREADER_QR_CODE_SCANNER_INITIATED = 0,
    PASSPORTREADER_QR_CODE_SCANNER_COMPLETED = 1
} passportreader_qr_code_scanner_state_t;

int passportreader_mrz_scanner_run_Y(
    const unsigned char* plane,
    unsigned int row_stride,
    unsigned int pixel_stride,
    unsigned int width,
    unsigned int height,
    passportreader_image_orientation_t orientation,
    int passport_only
);
int passportreader_mrz_scanner_clear(void);
passportreader_mrz_scanner_state_t passportreader_mrz_scanner_state(void);
unsigned int passportreader_mrz_scanner_error(void);
size_t passportreader_mrz_scanner_key_count(void);
const char* passportreader_mrz_scanner_key(size_t index);

int passportreader_chip_reader_run_command(unsigned char* data, size_t* length);
int passportreader_chip_reader_run_response(
    const unsigned char* data,
    size_t length,
    unsigned int sw1,
    unsigned int sw2
);
int passportreader_chip_reader_set_keys(const char* const* keys, size_t length);
int passportreader_chip_reader_clear(void);
int passportreader_chip_reader_retry(void);
passportreader_chip_reader_state_t passportreader_chip_reader_state(void);
unsigned int passportreader_chip_reader_error(void);
float passportreader_chip_reader_progress(void);
const char* passportreader_chip_reader_message(void);
const char* passportreader_chip_reader_given_names(void);
const char* passportreader_chip_reader_surname(void);
const char* passportreader_chip_reader_nationality(void);
const char* passportreader_chip_reader_sex(void);
const char* passportreader_chip_reader_date_of_birth(void);
const char* passportreader_chip_reader_optional_data(void);
const char* passportreader_chip_reader_optional_data2(void);
const char* passportreader_chip_reader_issuing_country(void);
const char* passportreader_chip_reader_document_number(void);
const char* passportreader_chip_reader_expiry_date(void);
const char* passportreader_chip_reader_document_type(void);
const char* passportreader_chip_reader_issuer(void);
const char* passportreader_chip_reader_signer(void);
const char* passportreader_chip_reader_archive(void);
const char* passportreader_chip_reader_portrait(void);
const char* passportreader_chip_reader_personal_number(void);
const char* passportreader_chip_reader_place_of_birth(void);
int passportreader_chip_reader_passive_authentication(void);
int passportreader_chip_reader_active_authentication(void);
int passportreader_chip_reader_chip_authentication(void);
const char* passportreader_chip_reader_protocol(void);

int passportreader_face_verifier_run_YCbCr420FullRangeBiPlanar(
    const unsigned char* plane0,
    const unsigned char* plane1,
    unsigned int row_stride0,
    unsigned int pixel_stride0,
    unsigned int row_stride1,
    unsigned int pixel_stride1,
    unsigned int width,
    unsigned int height,
    passportreader_image_orientation_t orientation
);
int passportreader_face_verifier_run_YCbCr420FullRangeTriPlanar(
    const unsigned char* plane0,
    const unsigned char* plane1,
    const unsigned char* plane2,
    unsigned int row_stride0,
    unsigned int pixel_stride0,
    unsigned int row_stride1,
    unsigned int pixel_stride1,
    unsigned int row_stride2,
    unsigned int pixel_stride2,
    unsigned int width,
    unsigned int height,
    passportreader_image_orientation_t orientation
);
int passportreader_face_verifier_set_portrait(const char* portrait);
int passportreader_face_verifier_clear(void);
passportreader_face_verifier_state_t passportreader_face_verifier_state(void);
float passportreader_face_verifier_distance(void);
const char* passportreader_face_verifier_face(void);

int passportreader_qr_code_scanner_run_Y(
    const unsigned char* plane,
    unsigned int row_stride,
    unsigned int pixel_stride,
    unsigned int width,
    unsigned int height,
    passportreader_image_orientation_t orientation
);
int passportreader_qr_code_scanner_clear(void);
passportreader_qr_code_scanner_state_t passportreader_qr_code_scanner_state(void);
const char* passportreader_qr_code_scanner_data(void);

#ifdef __cplusplus
}
#endif

#endif
