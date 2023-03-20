#pragma once

#include <algorithm>
#include <string>

#include "crypto.h"

constexpr unsigned int SAFETY_NUMBER_DIVISOR = 100000;
constexpr unsigned int SAFETY_NUMBER_ITERATIONS = 5200;

CalculateSafetyNumberFunction create_calculate_safety_number(
    const Chunk &our_identity_key);
