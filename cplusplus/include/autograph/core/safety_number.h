#pragma once

const unsigned int autograph_core_safety_number_SIZE = 60;
const unsigned int autograph_core_safety_number_CHUNK_SIZE = 5;
const unsigned int autograph_core_safety_number_DIVISOR = 100000;
const unsigned int autograph_core_safety_number_FINGERPRINT_SIZE = 30;
const unsigned int autograph_core_safety_number_ITERATIONS = 5200;

int autograph_core_safety_number(unsigned char *safety_number,
                                 const unsigned char *our_identity_key,
                                 const unsigned char *their_identity_key);
