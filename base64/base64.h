/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef BASE64_H
#define BASE64_H


int base64_encode(const uint8_t *in, uint16_t in_len, char *out);
int base64_decode(const char *in, uint8_t *out, uint16_t *out_len);

// 输入一个字符串，输出一个UTF-8格式的结果
void convert_to_utf8(char* input, int len);

#endif /* BASE64_H */
