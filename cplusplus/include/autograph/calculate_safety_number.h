#pragma once

#include <string>

#include "crypto.h"

constexpr unsigned int SAFETY_NUMBER_DIVISOR = 100000;
constexpr unsigned int SAFETY_NUMBER_ITERATIONS = 5200;

Chunk calculate_safety_number(bool is_initiator, const Chunk &our_identity,
                              const Chunk &their_identity);
