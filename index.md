---
title: Sydr
---

# About

<div style="float: right; margin-left: 1em; width: 20%">
<img src="sydr-bold.svg">
</div>

**Sydr** is a dynamic symbolic execution tool that explores new paths and
enables [error detection](https://arxiv.org/abs/2111.05770). Sydr uses
[DynamoRIO](https://dynamorio.org) for concrete execution and
[Triton](https://triton-library.github.io) for symbolic execution.

**Sydr-Fuzz** is a dynamic analysis tool for security development lifecycle. It
combines fuzzing ([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html),
[AFL++](https://aflplus.plus)) with the power of dynamic symbolic execution
([Sydr](https://arxiv.org/abs/2011.09269)). Sydr-Fuzz implements the following
fuzzing pipeline:

* Hybrid fuzzing with Sydr and libFuzzer/AFL++; coverage-guided Python (Atheris)
  and Java (Jazzer) fuzzing: `sydr-fuzz run`
* Corpus minimization: `sydr-fuzz cmin`
* Error detection (out of bounds, integer overflow, numeric truncation, division
  by zero, etc.) via
  [symbolic security predicates](https://arxiv.org/abs/2111.05770):
  `sydr-fuzz security`
* Collecting coverage: `sydr-fuzz cov-html`
* Triaging, deduplication, and clustering of crashes and Undefined Behavior
  Sanitizer errors with
  [Casr](https://github.com/ispras/casr), and later upload of new and unique
  reports to [DefectDojo](https://github.com/DefectDojo/django-DefectDojo): `sydr-fuzz casr --ubsan --url <URL>`

Our mission is discovering new bugs in open source projects via hybrid fuzzing
([OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz)). We already found a
significant number of
[trophies](https://github.com/ispras/oss-sydr-fuzz/blob/master/TROPHIES.md).
Moreover, we [compare](fuzzbench) Sydr-Fuzz with existing fuzzers.

Sydr-Fuzz supports multiple programming languages including C/C++
([libFuzzer](https://www.llvm.org/docs/LibFuzzer.html)/[AFL++](https://aflplus.plus)),
Rust
([cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz)/[afl.rs](https://github.com/rust-fuzz/afl.rs)),
Go ([go-fuzz](https://github.com/dvyukov/go-fuzz)), Python
([Atheris](https://github.com/google/atheris)), and Java
([Jazzer](https://github.com/CodeIntelligenceTesting/jazzer)). All languages
except Python and Java
support symbolic execution with Sydr.

# Guides

* Fuzzing xlnt project with sydr-fuzz for fun and profit (libFuzzer)
  \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-xlnt-project-with-sydr-fuzz-for-fun-and-profit)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-xlnt-project-with-sydr-fuzz-for-fun-and-profit-%28rus%29)\]
* Fuzzzing FreeImage project with Sydr and AFLplusplus \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzzing-FreeImage-project-with-Sydr-and-AFLplusplus)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzzing-FreeImage-project-with-Sydr-and-AFLplusplus-%28rus%29)\]
* Fuzzing goblin (Rust) project with Sydr and AFLplusplus \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-goblin-%28Rust%3Acrab%3A%21%29-project-with-Sydr-and-AFLplusplus)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-goblin-%28Rust%3Acrab%3A%21%29-project-with-Sydr-and-AFLplusplus-%28rus%29)\]
* Fuzzing ruamel-yaml (Python) project with  sydr-fuzz (Atheris backend) \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-ruamel-yaml-%28Python%29-project-with--sydr-fuzz-%28Atheris-backend%29)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-ruamel-yaml-%28Python%29-project-with--sydr-fuzz-%28Atheris-backend%29-%28rus%29)\]
* Fuzzing golang/image (Go) project with sydr-fuzz (go-fuzz backend) \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-golang-image-%28Go%29-project-with--sydr-fuzz-%28go-fuzz-backend%29)\] \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-golang-image-%28Go%29-project-with--sydr-fuzz-%28go-fuzz-backend%29-%28rus%29)\]
* Fuzzing json‐sanitizer (Java) project with sydr‐fuzz (Jazzer backend)
  \[[english](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-json%E2%80%90sanitizer-%28Java%29-project-with-sydr%E2%80%90fuzz-%28Jazzer-backend%29)\]
  \[[russian](https://github.com/ispras/oss-sydr-fuzz/wiki/Fuzzing-json%E2%80%90sanitizer-%28Java%29-project-with-sydr%E2%80%90fuzz-%28Jazzer-backend%29-%28rus%29)\]

# Open Source Projects

* [OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz): Hybrid Fuzzing for
  Open Source Software
* [CASR](https://github.com/ispras/casr): Crash Analysis and Severity Report
* [gdb-command](https://github.com/anfedotoff/gdb-command): Rust Library for
  Manipulating GDB in Batch Mode
* [Juliet C/C++ Dynamic Test Suite](https://github.com/ispras/juliet-dynamic):
  Evaluating Dynamic Analysis Tools on Juliet
* [sydr-benchmark](https://github.com/ispras/sydr-benchmark): Benchmarking
  Dynamic Symbolic Execution

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
  \[[russian&nbsp;video](https://youtu.be/CI-Zioq5G84?t=6583)\]
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
* Fedotov A. Sydr: Dynamic Analysis Technology. IVMEM 2022 Plenum.
  \[[russian&nbsp;slides](/papers/fedotov-plenum-sydr-ivmem2022.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/L7ZRV2Voee4?t=5652)\]
* Fedotov A. Sydr: SDL for Artificial Intelligence. IVMEM 2022 Plenum.
  \[[russian&nbsp;slides](/papers/fedotov-plenum-sdlai-ivmem2022.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/L7ZRV2Voee4?t=7658)\]
* Parygina D., Vishnyakov A., Fedotov A. Strong Optimistic Solving for Dynamic
  Symbolic Execution. 2022 Ivannikov Memorial Workshop.
  \[[paper](https://arxiv.org/abs/2209.03710)\]
  \[[slides](/papers/parygina-ivmem2022.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/L7ZRV2Voee4?t=14710)\]
* Fedotov A. Sydr: Hybrid Fuzzing. IVMEM 2022 Cybersecurity Round Table.
  \[[russian&nbsp;slides](/papers/fedotov-cybersec-ivmem2022.pdf)\]
* Fedotov A. Sydr & CASR: Dynamic Analysis for SDL. ISPRAS Open 2022 Trusted
  Software Development.
  \[[russian&nbsp;slides](/papers/fedotov-cybersec-isprasopen2022.pdf)\]
* Fedotov A. Development of Trusted Machine Learning Frameworks. ISPRAS Open 2022 Trusted AI.
  \[[russian&nbsp;slides](/papers/fedotov-sdlai-isprasopen2022.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/4SglZ8f4R5k?t=7684)\]
* Vishnyakov A., Kuts D., Logunova V., Parygina D., Kobrin E., Savidov G.,
  Fedotov A. Sydr-Fuzz: Continuous Hybrid Fuzzing and Dynamic Analysis for
  Security Development Lifecycle. 2022 Ivannikov ISPRAS Open Conference.
  \[[paper](https://arxiv.org/abs/2211.11595)\]
  \[[slides](https://vishnya.xyz/vishnyakov-isprasopen2022.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/qw_tzzgX04E?t=16813)\]
* Vishnyakov A. Error detection in binary code with dynamic symbolic execution.
  PhD thesis.
  \[[russian&nbsp;thesis](https://vishnya.xyz/vishnyakov-phd-thesis2022.pdf)\]
  \[[russian&nbsp;synopsis](https://vishnya.xyz/vishnyakov-phd-synopsis2022.pdf)\]
  \[[russian&nbsp;slides](https://vishnya.xyz/vishnyakov-phd-thesis2022-presentation.pdf)\]
* Fedotov A., Vishnyakov A. CASR: Your Life Vest in a Sea of Crashes. OFFZONE 2023.
  \[[slides](/papers/fedotov-casr-offzone2023.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/EgEeICZQD9M?si=hiFEwPmDqnh0cEq6)\]
* Padaryan V., Stepanov V., Vishnyakov A. Fuzzing for SDL: Select, Cover, Reveal. OFFZONE 2023.
  \[[slides](/papers/vishnyakov-sydr-offzone2023.pdf)\]
  \[[russian&nbsp;video](https://youtu.be/ASZMRp8AoTQ?si=HW0q_TxtbMWCkuoH&t=1067)\]
* Mezhuev T., Kobrin I., Vishnyakov A., Kuts D. Numeric Truncation Security Predicate.
  2023 Ivannikov ISPRAS Open Conference.
  \[[paper](https://arxiv.org/abs/2312.06425)\]
  \[[slides](https://vishnya.xyz/mirror/mezhuev-ispopen2023.pdf)\]
  \[[russian&nbsp;video](https://www.youtube.com/watch?v=oMpSgMFFiXc&t=18608s)\]
