#include <benchmark/benchmark.h>

#include "autograph.h"

int main(int argc, char** argv) {
  ::benchmark::Initialize(&argc, argv);

  autograph_init();

  ::benchmark::RunSpecifiedBenchmarks();
}
