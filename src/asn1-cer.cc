#include "asn1-cer.h"

std::string cer_encode_sequence() {
  std::string res;

  res.push_back(0x30);
  res.push_back(0x80);
  return res;
}

std::string cer_encode_endcons() {
  std::string res;

  res.push_back(0x00);
  res.push_back(0x00);
  return res;
}

std::string cer_encode_length(int32_t len) {
  if (len < 0) {
    throw std::runtime_error("Can't serialize negative length in ASN.1");
  }

  std::string res;
  if (len <= 127) {
    res.push_back(len);
    return res;
  }

  res.push_back(0x00);

  bool ser_started = false;
  for (int i = 0; i < 4; i++) {
    uint8_t len_byte = (len >> (8 * (3 - i))) & 0xFF;
    if (!ser_started && len_byte) {
      ser_started = true;
      res[1] = 0x80 | (4 - i);
    }

    if (ser_started) res.push_back(len_byte);
  }

  return res;
}

static std::string int_to_bytes(int32_t data) {
  std::string res;

  for (int i = 0; i < 4; i++) res.push_back((data >> (8 * (3 - i))) & 0xFF);

  return res;
}

std::string cer_encode_integer(int32_t number, ASN1_UniversalTag subtype) {
  std::string res;

  res.push_back(subtype);
  res.push_back(0x00);  // stub

  std::string number_bytes = int_to_bytes(number);
  bool start_ser = false;
  uint8_t prev_byte = 0x00;

  for (int i = 0; i < number_bytes.length(); i++) {
    if (!start_ser) {
      if ((number_bytes[i] != 0x00) && ((uint8_t)number_bytes[i] != 0xFF)) {
        start_ser = true;
        if (i > 0) {
          if ((prev_byte & 0x80) != (number_bytes[i] & 0x80)) res.push_back(prev_byte);
        }
      } else {
        prev_byte = number_bytes[i];
      }
    } else {
      res.push_back(number_bytes[i]);
    }
  }
  res[1] = res.length() - 2;

  return res;
}

std::string cer_encode_string(const std::string& contents, ASN1_UniversalTag subtype) {
  size_t len = contents.length();

  std::string res;
  res.push_back(subtype);

  if (len <= CER_MAX_PRIMITIVESTRING) {
    res += cer_encode_length(len);
    res += contents;
    return res;
  }

  res.push_back(0x80);
  std::string contents_copy = contents;
  while (!contents_copy.empty()) {
    size_t chunk_size =
        (contents_copy.length() > CER_MAX_PRIMITIVESTRING) ? CER_MAX_PRIMITIVESTRING : contents.length();
    res += cer_encode_string(contents_copy.substr(0, chunk_size), subtype);
    contents_copy = contents_copy.substr(chunk_size);
  }
  res += cer_encode_endcons();
  return res;
}

static int32_t cer_decode_length(const std::string& content, int32_t* endpos) {
  if ((uint8_t)content[0] == 0x80) {
    *endpos = 1;
    return -1;
  }

  if (!((uint8_t)content[0] & 0x80)) {
    *endpos = 1;
    return content[0];
  }

  int len_len = content[0] & 0x7F;
  *endpos = len_len + 1;
  if (len_len > 4) return -2;

  int32_t res = 0;
  for (int i = 0; i < len_len; i++) {
    res <<= 8;
    res |= content[i];
  }

  // In case of overflow number can accidentially take a 'special' value (only -1 now). Make sure it is interpreted as
  // error.
  if (res < 0) res = -2;

  return res;
}

ASN1_Token cer_decode_token(const std::string& ber, int32_t* endpos, int32_t* int_param, std::string* string_param) {
  *endpos = 0;
  if (ber.length() < 2) return kUnknown;

  uint8_t type_class = (ber[0] >> 6) & 0x3;
  uint8_t tag = ber[0] & 0x1F;
  bool constructed = !!(ber[0] & 0x20);
  int32_t len_endpos;
  int32_t token_len = cer_decode_length(ber.substr(1), &len_endpos);

  // token_len of -1 is used as indefinite length marker
  if (token_len < -1) return kUnknown;

  std::string content;
  if (token_len == -1)  // indefinite form, take the whole tail
    content = ber.substr(2);
  else  // definite form
    content = ber.substr(1 + len_endpos, token_len);

  if (type_class == kAsn1Universal) {
    switch (tag) {
      case kAsn1Sequence:
        if (!constructed) return kUnknown;

        *int_param = token_len;
        *endpos = len_endpos + 1;
        return kSequence;

      case kAsn1EndSequence:
        if (token_len != 0)
          return kUnknown;
        else
          return kEndSequence;

      case kAsn1Integer: {
        if (constructed || token_len == -1) return kUnknown;

        // support max. 32 bit-wide integers
        if (content.length() > 4 || content.length() < 1) return kUnknown;

        int sign = !!(content[0] & 0x80);

        *int_param = 0;
        for (int i = 0; i < content.length(); i++) {
          *int_param <<= 8;
          *int_param |= content[i];
        }

        if (sign) {
          for (int i = token_len; i < 4; i++) *int_param |= (0xff << (i << 3));
        }

        *endpos = 1 + len_endpos + token_len;
        return kInteger;
      }
      case kAsn1OctetString:
      case kAsn1Utf8String:
      case kAsn1NumericString:
      case kAsn1PrintableString:
      case kAsn1TeletexString:
      case kAsn1VideotexString:
      case kAsn1UTCTime:
      case kAsn1GeneralizedTime:
      case kAsn1GraphicString:
      case kAsn1VisibleString:
      case kAsn1GeneralString:
      case kAsn1UniversalString:
      case kAsn1CharacterString:
      case kAsn1BMPString: {
        if (token_len >= 0) {  // Fixed length encoding
          *string_param = content;
          *endpos = 1 + len_endpos + token_len;
        } else {
          int32_t position = 1 + len_endpos;
          *string_param = std::string();
          for (;;) {
            int32_t internal_endpos;
            int32_t internal_int_param;
            std::string internal_string_param;
            ASN1_Token token =
                cer_decode_token(ber.substr(position), &internal_endpos, &internal_int_param, &internal_string_param);
            if (token == kEndSequence) {
              return kOctetString;
            } else if (token != kOctetString || internal_int_param != type_class) {
              return kUnknown;
            }

            // common case: a string segment
            *string_param += internal_string_param;
            position += internal_endpos;
          }
          *endpos = position;
        }
        *int_param = type_class;
        return kOctetString;
      }
      default:
        return kUnknown;
    }
  } else {
    return kUnknown;
  }
}
