#include <string>
#include <stdexcept>

// Limitations:
//   - Maximal supported integer width of 32 bits
//   - Maximal supported string length of 2**31 -1
//   - Only type tags up to 30 are supported

#define CER_MAX_PRIMITIVESTRING 1000 // defined in the standard

enum ASN1_Class {
  kAsn1Universal = 0x00,
};

enum ASN1_UniversalTag {
  kAsn1EndSequence = 0x00,
  kAsn1Sequence = 0x10,
  kAsn1Integer = 0x02,
  kAsn1OctetString = 0x04,
  kAsn1Enum = 0x0a,
  kAsn1Utf8String = 0x0c,
  kAsn1NumericString = 0x12,
  kAsn1PrintableString = 0x13,
  kAsn1TeletexString = 0x14,
  kAsn1VideotexString = 0x15,
  kAsn1UTCTime = 0x16,
  kAsn1GeneralizedTime = 0x17,
  kAsn1GraphicString = 0x18,
  kAsn1VisibleString = 0x19,
  kAsn1GeneralString = 0x1a,
  kAsn1UniversalString = 0x1b,
  kAsn1CharacterString = 0x1c,
  kAsn1BMPString = 0x1d,
};

enum ASN1_Token {
  kUnknown,
  kSequence,
  kInteger,
  kOctetString,
  kEndSequence,
};

class deserialization_error : public std::exception {
  const char * what () const throw ()
  {
    return "ASN.1 deserialization error";
  }
};

ASN1_Token cer_decode_token(const std::string& ber, int32_t* endpos, int32_t* int_param, std::string* string_param);

std::string cer_encode_endcons();
std::string cer_encode_sequence();
std::string cer_encode_length(int32_t len);
std::string cer_encode_integer(int32_t number, ASN1_UniversalTag subtype);
std::string cer_encode_string(const std::string& contents, ASN1_UniversalTag subtype);
