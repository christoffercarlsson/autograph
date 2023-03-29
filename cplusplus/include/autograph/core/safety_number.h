#pragma once

constexpr unsigned int autograph_core_safety_number_SIZE = 60;
constexpr unsigned int autograph_core_safety_number_CHUNK_SIZE = 5;
constexpr unsigned int autograph_core_safety_number_DIVISOR = 100000;
constexpr unsigned int autograph_core_safety_number_FINGERPRINT_SIZE = 30;
constexpr unsigned int autograph_core_safety_number_ITERATIONS = 5200;

int autograph_core_safety_number(unsigned char *safety_number,
                                 const unsigned char *our_identity_key,
                                 const unsigned char *their_identity_key);
