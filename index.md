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

* Vishnyakov A., Fedotov A., Kuts D., Novikov A., Parygina D., Kobrin E.,
  Logunova V., Belecky P., Kurmangaleev Sh. Sydr: Cutting Edge Dynamic Symbolic
  Execution. 2020 Ivannikov ISPRAS Open Conference.
  \[[paper](https://arxiv.org/abs/2011.09269)\]
  \[[slides](https://vishnya.xyz/vishnyakov-isprasopen2020.pdf)\]
  \[[video](https://www.ispras.ru/conf/2020/video/compiler-technology-11-december.mp4#t=6021)\]
* Fedotov A.N., Kurmangaleev Sh.F. CASR: core dump analysis and severity
  reporter tool. Proceedings of ISP RAS, 2020.
  \[[russian&nbsp;paper](https://www.researchgate.net/publication/346176971)\]
* Kuts D. Towards Symbolic Pointers Reasoning in Dynamic Symbolic Execution.
  2021 Ivannikov Memorial Workshop.
  \[[paper](https://arxiv.org/abs/2109.03698)\]
  \[[slides](/papers/kuts-ivmem2021.pdf)\]
* Vishnyakov A., Logunova V., Kobrin E., Kuts D., Parygina D., Fedotov A.
  Symbolic Security Predicates: Hunt Program Weaknesses. 2021 Ivannikov ISPRAS
  Open Conference.
  \[[paper](https://arxiv.org/abs/2111.05770)\]
  \[[slides](https://vishnya.xyz/vishnyakov-isprasopen2021.pdf)\]
  \[[video](https://youtu.be/CI-Zioq5G84?t=6583)\]
* Savidov G., Fedotov A. Casr-Cluster: Crash Clustering for Linux Applications.
  2021 Ivannikov ISPRAS Open Conference.
  \[[paper](https://arxiv.org/abs/2112.13719)\]
  \[[slides](/papers/casr-cluster.pdf)\]
* Kobrin E., Vishnyakov A., Fedotov A. Hybrid Fuzzing of TensorFlow Machine
  Learning Framework. MITSOBI 2022.
  \[[russian&nbsp;slides](https://vishnya.xyz/kobrin-mitsobi2022.pdf)\]
* Vishnyakov A.V., Kobrin E.A., Fedotov A.N. Error detection in binary code with
  dynamic symbolic execution. Proceedings of ISP RAS, 2022.
  \[[russian&nbsp;paper](https://ispranproceedings.elpub.ru/jour/article/view/1512/1346)\]
  \[[russian&nbsp;slides](https://vishnya.xyz/vishnyakov-mitsobi2022.pdf)\]
* Parygina D., Vishnyakov A., Fedotov A. Strong Optimistic Solving for Dynamic
  Symbolic Execution. 2022 Ivannikov Memorial Workshop.
  \[[paper](https://arxiv.org/abs/2209.03710)\]
  \[[slides](/papers/parygina-ivmem2022.pdf)\]

# Open Source Projects

* [OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz): Hybrid Fuzzing for
  Open Source Software
* [gdb-command](https://github.com/anfedotoff/gdb-command): Rust Library for
  Manipulating GDB in Batch Mode
* [Juliet C/C++ Dynamic Test Suite](https://github.com/ispras/juliet-dynamic):
  Evaluating Dynamic Analysis Tools on Juliet
* [sydr-benchmark](https://github.com/ispras/sydr-benchmark): Benchmarking
  Dynamic Symbolic Execution
