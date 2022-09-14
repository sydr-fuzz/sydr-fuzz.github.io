---
title: Sydr
---

# About

**Sydr** is a dynamic symbolic execution tool that explores new paths and
enables [error detection](https://arxiv.org/abs/2111.05770). Sydr uses
[DynamoRIO](https://dynamorio.org) for concrete execution and
[Triton](https://triton-library.github.io) for symbolic execution.

**Sydr-fuzz** is a dynamic analysis tool for security development lifecycle. It
combines fuzzing ([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html),
[AFL++](https://aflplus.plus)) with the power of dynamic symbolic execution
([Sydr](https://arxiv.org/abs/2011.09269)). Sydr-fuzz implements the following
fuzzing pipeline:

* Hybrid fuzzing with Sydr and libFuzzer/AFL++: `sydr-fuzz run`
* Corpus minimization: `sydr-fuzz cmin`
* Error detection (out of bounds, integer overflow, division by zero, etc.) via
  [symbolic security predicates](https://arxiv.org/abs/2111.05770):
  `sydr-fuzz security`
* Collecting coverage: `sydr-fuzz cov-report`
* Crash triaging, deduplication, and clustering with
  [Casr](https://arxiv.org/abs/2112.13719): `sydr-fuzz casr`

Our mission is discovering new bugs in open source projects via hybrid fuzzing
([OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz)). We already found a
significant number of
[trophies](https://github.com/ispras/oss-sydr-fuzz/blob/master/TROPHIES.md).
Moreover, we [compare](fuzzbench) Sydr-fuzz with existing fuzzers.

# Guides

* Fuzzing xlnt project with sydr-fuzz for fun and profit (libFuzzer)
  \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-xlnt-project-with-sydr-fuzz-for-fun-and-profit)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-xlnt-project-with-sydr-fuzz-for-fun-and-profit-%28rus%29)\]
* Fuzzzing FreeImage project with Sydr and AFLplusplus \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzzing-FreeImage-project-with-Sydr-and-AFLplusplus)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzzing-FreeImage-project-with-Sydr-and-AFLplusplus-%28rus%29)\]

# Publications and Talks

# Open Source Projects

* [OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz): Hybrid Fuzzing for
  Open Source Software
* [gdb-command](https://github.com/anfedotoff/gdb-command): Rust Library for
  Manipulating GDB in Batch Mode
* [Juliet C/C++ Dynamic Test Suite](https://github.com/ispras/juliet-dynamic):
  Evaluating Dynamic Analysis Tools on Juliet
* [sydr-benchmark](https://github.com/ispras/sydr-benchmark): Benchmarking
  Dynamic Symbolic Execution
