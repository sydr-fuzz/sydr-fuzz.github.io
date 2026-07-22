# LibAFL-DiFuzz: направленный фаззинг на основе LibAFL

* TOC
{:toc}

LibAFL-DiFuzz - это инструмент направленного фаззинга, основанный на модульной архитектуре библиотеки фаззинга LibAFL и инструмента
статической предобработки DiFuzz. Инструмента позволяет выполнять фаззинг с фокусом на заданных участках программного кода и задавать
"направление" анализа с использованием одной или нескольких целевых точек в коде. Для запуска направленного фаззинга требуется провести
предварительный статический анализ программы, в ходе которого будут сформированы специальные метрики, используемые в дальнейшем анализе.
В процессе фаззинга LibAFL-DiFuzz отслеживает текущее состояние выполнения программы и управляет распределением вычислительных ресурсов
(энергии) между входными данными, повышая вероятность достижения заданных целевых точек.

Основные идеи и функциональные возможности, реализованные в LibAFL-DiFuzz, включают:

* Планирование распределения энергии в процессе фаззинга на основе алгоритма имитации отжига
* Метрику близости к целевым участкам кода, основанную на доминаторах графа и расширенных целевых
последовательностях (Enhanced Target Sequences, ETS)
* Эвристические алгоритмы для разрешения неявных вызовов на этапе статической предобработки программы
* Использование контекстных весов для повышения точности метрики близости

Ключевые аспекты внутренней архитектуры LibAFL-DiFuzz подробно изложены в следующей научной статье:
[LibAFL-DiFuzz: Advanced Architecture Enabling Directed Fuzzing](https://arxiv.org/abs/2412.19143).

LibAFL-DiFuzz работает по следующей схеме:

* **Предобработка**: инструмент DiFuzz выполняет статический анализ целевой программы: строит графовые представления, конструирует ETS, вычисляет контекстные веса
и создает файл `ets.toml` со всей необходимой информацией для фаззинга.
* **Инструментация**: специальные компиляторы (`libafl_cc`/`libafl_cxx`) выполняют сборку целевой программы со специфичной для LibAFL инструментацией, используя
информацию из файла `ets.toml`.
* **Фаззинг**: фаззер LibAFL-DiFuzz запускает форксервер для инструментированной программы и выполняет анализ. В ходе фаззинга механизм планирования энергии выделяет
больше ресурсов наиболее перспективным входным данным, повышая вероятность достижения целевых участков кода.

## Зависимости

Для запуска LibAFL-DiFuzz и сборки проектов, необходимы следующие зависимости:

* Ubuntu20.04 (libc2.31) или новее;
* **Boost 1.71**: `apt-get update && apt-get -y install libboost1.71-all-dev`;
* **libTBB2**: `apt-get update && apt-get -y install libtbb-dev` (`libtbb2-dev` для Ubuntu22.04 и новее);
* **LLVM-18**: `wget https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 18 all`;
* **Rust** toolchain >= 1.84;
* **cargo make**: `cargo install cargo-make`;
* **Python** >= 3.10;
* **wllvm** (для C/C++): `pip3 install wllvm`;
* **Go** (для проектов на Go).


# Использование LibAFL-DiFuzz

В данном разделе описывается порядок использования инструмента LibAFL-DiFuzz.

## Опции LibAFL-DiFuzz

    $ ./libafl_difuzz --help

    LibAFL-DiFuzz fuzzer instance.

    Usage: libafl_difuzz [OPTIONS] -- <ARGS>...

    Arguments:
      <ARGS>...  Add "-- /path/to/target_bin <arguments>" to set binary path and its
                arguments.

    Options:
      -i <INPUT_DIR>                   Input corpus directory. [default: ./corpus]
      -x <CRASH_DIR>                   Output directory with crashes. [default: ./crashes]
      -e <ETS_PATH>                    Path to ets.toml. [default: ./ets.toml]
          --dict <dict>                A dictionary file to read tokens from, to be used
                                       during fuzzing
      -j <jobs>                        Number of cpu cores to be used by fuzzer. [default: 1]
      -l <limit>                       Stack limit size in gigabytes. [default: 8]
          --rss-limit <rss-limit>      Memory limit size in gigabytes for target. [default: 0]
      -p <port>                        Broker port. [default: 1337]
          --exit-on-all                Exit fuzzing when all target points are reached.
          --iters <iters>              Number of fuzzer iterations. [default: 1000000]
          --panic-analysis <LANGUAGE>  Enable error handling from "panic()" function for Rust
                                       or Go targets. [possible values: rust, go]
          --crash-exitcode <EXITCODE>  Enable error handling when target exits with
                                       <EXITCODE>.
          --cool-time <cool-time>      Time (in seconds) for exploration stage. [default:
                                       7200]
          --beta <beta>                Beta parameter for gMaxCov metric. [default: 0.5]
      -s <SYNC_DIR>                    Sync input directory.
          --sync-jobs <sync-jobs>      Number of cpu cores to be used for synchronization.
                                       [default: 1]
          --sync-limit <sync-limit>    Limit for number of inputs imported at one
                                       synchronization iteration. [default: 100]
          --forced                     All files from sync directory are force-added to
                                       corpus.
      --skip-bin-check                 Skip binary instrumentation checks.
      -h, --help                       Print help
      -V, --version                    Print version

## Опции для указания директорий

Опция **-i [--input] <INPUT_DIR>** задает путь до директории корпуса входных данных, который используется в процессе фаззинга для получения и сохранения данных.

Опция **-x [--crashes] <CRASH_DIR>** задает путь до выходной директории. Все целевые файлы (входные данные, приводящие к достижению целевой точки, аварийному завершению или зависанию программы) сохраняются в данном каталоге.

Опция **-e [--ets] <ETS_PATH>** задает путь до конфигурационного файла `ets.toml`, созданного инструментом DiFuzz во время статической предобработки и обновленного во время компиляции программы.

Опция **--dict \<dict\>** задает путь до словаря. Токены из словаря используются в мутациях в процессе фаззинга.

## Настройки процесса фаззинга

Опция **-j [--jobs] \<jobs\>** задает число процессов (ядер CPU), используемых во время фаззинга. Каждый процесс соответсвует отдельному клиенту фаззера.

Опция **-l [--limit] \<limit\>** задает ограничение размера стека (в мегабайтах).

Опция **--rss-limit \<rss-limit\>** задает ограничение размера потребляемой памяти (в мегабайтах).

Опция **-p [--port] \<port\>** задает порт для брокера LibAFL-DiFuzz. Данный порт используется для коммуникации между всеми процессами фаззера. Значение порта должно быть уникальным для каждой фаззинг-кампании. Если на машине одновременно запускается LibAFL-DiFuzz для фаззинга нескольких проектов, необходимо использовать данную опцию для указания разных портов для брокера.

Опция **--exit-on-all** завершает анализ при достижению всех целевых точек.

Опция **--iters \<iters\>** задает число итераций фаззинга. Каждая итерация соответствует получению набора входных данных из корпуса, его мутированию и оценке результатов.

Опция **--panic-analysis \<LANGUAGE\>** включает обработку ошибок для функции `panic` в программах на Rust или Go. В качестве значения указывается соответствующий язык: "rust" или "go".

Опция **--crash-exitcode \<EXITCODE\>** включает обработку ошибок когда программа завершается с кодом <EXITCODE>.

Опция **--skip-bin-check** позволяет пропустить проверку анализируемого бинарного файла на наличие символов, необходимых для фаззинга.

## Настройки направленного фаззинга

Опция **--cool-time \<cool-time\>** задает время (в секундах), которое будет затрачено на стадию _exploration_, целью которой является увеличение покрытия программы. После **cool-time** процесс фаззиннга переходит на стадию _exploitation_, целью которой является достижение целевых точек.

Опция **--beta \<beta\>** задает пороговое значение для планирования энергии. Глобальная метрика покрытия ETS учитывается при вычислении энергии только в том случае, если есть достаточное количество ETS, у которых степень исследования превышает заданный порог. Чем меньше значение параметра **beta**, тем раньше в процессе фаззинга начинает учитываться глобальная метрика покрытия ETS, и наоборот.

## Режим синхронизации

Опция **-s [--sync] \<SYNC_DIR\>** используется для запуска LibAFL-DiFuzz в гибридном режиме параллельно с другими инструментами анализа. В опции указывается путь до директории, используемой LibAFL-DiFuzz ждя импорта входных данных от других инструментов.

Опция **--sync-jobs \<sync-jobs\>** задает число процессов (ядер CPU), используемых для синхронизации.

Опция **--sync-limit \<sync-limit\>** задает ограничение числа входных данных, импортируемых за одну итерацию синхронизации.

Опция **--forced** позволяет добавлять все файлы из синхронизационной директории в корпус фаззинга без их оценки.

## Аргументы фаззинг цели

**-- \<ARGS\>...** (**-- /path/to/target_bin \<arguments\>**) добавляется в конце командной строки и задает путь до исполняемого файла целевой программы с ее аргументами.

## Переменные окружения

Следующие переменные окружения позволяют изменить размеры битовой карты покрытия и массива ETS:

* Установите **DIFUZZ_MAP_SIZE=\<number\>** чтобы задать размеры битовой карты покрытия (по умолчанию 65536);
* Установите **ETS_ARRAY_SIZE=\<number\>** чтобы задать размеры массива ETS (по умолчанию 65536).


# Набор инструментов LibAFL-DiFuzz

Набор инструментов LibAFL-DiFuzz включает средства статической предобработки, инструментации и фаззинга. Кроме того, в его состав входят вспомогательные скрипты и шаблоны, упрощающие подготовку фаззинг целей. Все компоненты поставляются в виде единого архива с определённой структурой. В данном разделе приводится описание входящих в состав инструментов и рассматривается структура архива.

Основным компонентом системы является инструмент фаззинга LibAFL-DiFuzz, представленный исполняемым файлом `libafl_difuzz`. Средства статической предобработки DiFuzz и инструментации являются языково-зависимыми и представлены набором исполняемых файлов, библиотек и сценариев.

## Статический анализ с помощью DiFuzz

DiFuzz представляет собой отдельный инструмент для статического анализа фаззинг целей и сбора информации, необходимой для последующей инструментации и фаззинга. В состав DiFuzz входят три специализированные версии: difuzz — для программ на C/C++, difuzz-rust — для Rust и difuzz-go — для Go. Инструмент принимает на вход путь до исполняемого файла (C/C++), путь до скомпилированого ".bc" файла с биткодом LLVM (C/C++/Rust), либо до директории с исходным кодом проекта (Go), а также конфигурационный файл с описанием целевых точек.

### Опции DiFuzz (C/C++)

    $ ./difuzz -h
    Build ETS for CG and CFG domtrees.

    Usage: difuzz [OPTIONS] --config <CONFIG.toml> --binary <BINARY>

    Options:
    -j, --jobs <jobs>
            Number of cpu cores to be used by the program. [default: half of cpu cores]
    -l, --log-level <LOG_LEVEL>
            Logging level. [default: info] [possible values: info, debug, trace]
    -c, --config <CONFIG.toml>
            Config file with target points.
    -b, --binary <BINARY>
            Target binary or linked LLVM bytecode (.bc) file.
    -r, --root <ROOT_FN_NAME>
            Root function name. [default: main]
    -o, --output <OUTPUT_DIR>
            Output directory with .dot files. [default: difuzz]
    -e, --ets-file </path/to/ets.toml>
            Path to output ets.toml file. If path is not provided, it is put in
            OUTPUT_DIR/BIN_NAME-out/ets.toml.
        --disasm-bc
            Disassemble LLVM bytecode (.bc) into .ll format.
        --target-check-mode <MODE>
            Mode for checking source code and target points correctness. Mode "tp" checks
            only target points in target debug info, "source" checks only for source code
            existance, "all" checks all of them. [default: all] [possible values: all, tp,
            source, disabled]
        --analyse-icalls <ICALLS_STRATEGY>
            Analyse all indirect calls with specific strategy and try to resolve them
            (sometimes it takes a long time). [default: disabled] [possible values: strong,
            weak, disabled]
    -w, --weights <WEIGHTS_STRATEGY>
            Choose context weights strategy for accurate proximity metrics calculation.
            [default: reverse] [possible values: reverse, direct, disabled]
    -h, --help
            Print help
    -V, --version
            Print version

### Опции DiFuzz-Rust

    $ difuzz-rust -h
    Build ETS for CG and CFG domtrees for Rust code.

    Usage: difuzz-rust [OPTIONS] --config <CONFIG.toml> --binary <BINARY>

    Options:
    -j, --jobs <jobs>
            Number of cpu cores to be used by the program. [default: half of cpu cores]
    -l, --log-level <LOG_LEVEL>
            Logging level. [default: info] [possible values: info, debug, trace]
    -c, --config <CONFIG.toml>
            Config file with target points.
    -b, --binary <BINARY>
            Linked LLVM bytecode (.bc) file.
    -r, --root <ROOT_FN_NAME>
            Root function name. [default: main]
    -o, --output <OUTPUT_DIR>
            Output directory with .dot files. [default: difuzz]
    -e, --ets-file </path/to/ets.toml>
            Path to output ets.toml file. If path is not provided, it is put in
            OUTPUT_DIR/BIN_NAME-out/ets.toml.
        --disasm-bc
            Disassemble LLVM bytecode (.bc) into .ll format.
        --target-check-mode <MODE>
            Mode for checking source code and target points correctness. Mode "tp" checks
            only target points in target debug info, "source" checks only for source code
            existance, "all" checks all of them. [default: all] [possible values: all, tp,
            source, disabled]
        --analyse-icalls <ICALLS_STRATEGY>
            Analyse all indirect calls with specific strategy and try to resolve them
            (sometimes it takes a long time). [default: disabled] [possible values: strong,
            weak, disabled]
    -w, --weights <WEIGHTS_STRATEGY>
            Choose context weights strategy for accurate proximity metrics calculation.
            [default: reverse] [possible values: reverse, direct, disabled]
    -h, --help
            Print help
    -V, --version
            Print version

### Опции DiFuzz-Go

    $ ./difuzz-go -h
    Build ETS for CG and CFG domtrees for Go code.

    Usage: difuzz-go [OPTIONS] --config <CONFIG.toml> --project-dir <PROJECT>

    Options:
    -j, --jobs <jobs>
            Number of cpu cores to be used by the program. [default: half of cpu cores]
    -l, --log-level <LOG_LEVEL>
            Logging level. [default: info] [possible values: info, debug, trace]
    -c, --config <CONFIG.toml>
            Config file with target points.
    -p, --main-path <MAIN_PATH>
            Path to ".go" file with "main" function. File directory must not contain any
            other files with "main" function.
    -r, --root <ROOT_FN_NAME>
            Root function name. [default: main]
    -o, --output <OUTPUT_DIR>
            Output directory with .dot files. [default: difuzz]
    -e, --ets-file </path/to/ets.toml>
            Path to output ets.toml file. If path is not provided, it is put in
            OUTPUT_DIR/BIN_NAME-out/ets.toml.
        --target-check-mode <MODE>
            Mode for checking source code and target points correctness. Mode "tp" checks
            only target points in target debug info, "source" checks only for source code
            existance, "all" checks all of them. [default: all] [possible values: all, tp,
            source, disabled]
        --ignore-tp
            Ignore target point if it doesn't exist.
    -w, --weights <WEIGHTS_STRATEGY>
            Choose context weights strategy for accurate proximity metrics calculation.
            [default: reverse] [possible values: reverse, direct, disabled]
    -h, --help
            Print help
    -V, --version
            Print version

## Инструментация C/C++

Инструментация программ на C/C++ выполняется с помощью обёрток над компилятором Clang — `libafl_cc` и `libafl_cxx`. Инструментация осуществляется посредством специализированного LLVM-прохода difuzz-ets-pass.so, который автоматически подключается обёртками компилятора в процессе сборки. Для инструментации также требуется статическая библиотека liblibforkserver.a, которая обеспечивает взаимодействие исследуемой программы с фаззером. Данная библиотека автоматически подключается к фаззинг цели обёртками компилятора.

При параллельной компиляции используется вспомогательная утилита `ETSSharedManager`. Скрипт `insert_forkserver.py` предназначен для автоматической вставки в исходный код программы вызовов функций инициализации и обработчиков сигналов, необходимых для работы forkserver.

## Инструментация Rust

Инструментация программ на Rust выполняется с помощью обёртки `libafl_rustc` над компилятором rustc. Как и в случае C/C++, используются специализированные под Rust версии LLVM-прохода difuzz-ets-pass.so и статической библиотеки liblibforkserver-rs.a. Но в отличие от C/C++, для корректной работы `libafl_rustc` требуются дополнительные библиотеки, которые входят в состав каталога rust-difuzz/ архива инструментария.
Так же как и для C/C++, используются утилита ETSSharedManager и скрипт `insert_forkserver.py`.

## Инструментация Go

Инструментация программ на Go осуществляется с помощью набора утилит, реализованных на языке Go. В отличие от C/C++ и Rust, где инструментация выполняется на уровне промежуточного представления LLVM (LLVM IR), инструменты для Go модифицируют непосредственно исходный код программы. Утилита `goinstr_difuzz` выполняет инструментацию для DiFuzz (на основе ETS), а `goinstr_sancov` выполняет инструментацию для отслеживания покрытия кода. Каталог goinstr-difuzz/ содержит исходный код на языке Go, который используется для инструментации.

Утилита `goinstr_coverage` предназначена для корректного сбора информации о покрытии после завершения процесса фаззинга. В отличие от стандартного механизма, она обеспечивает сбор покрытия не только для входных данных из корпуса, но и для входных данных, приводящих к аварийному завершению программы.

## Структура архива

Архив инструментов LibAFL-DiFuzz имеет следующую структуру:

    difuzz/
    │ # Fuzzer
    ├── libafl_difuzz
    │ # Static analysis
    ├── difuzz
    ├── difuzz-rust
    ├── difuzz-go
    │ # Assistive tools
    ├── ETSSharedManager
    ├── insert_forkserver.py
    ├── tp_validate.py
    │ # C/C++ instrumentation
    ├── libafl_cc
    ├── libafl_cxx
    ├── difuzz-ets-pass.so
    ├── liblibforkserver.a
    │ # Rust instrumentation
    ├── rust-difuzz/
    │   ├── bin/
    │   │   └── libafl_rustc
    │   ├── difuzz-ets-pass.so
    │   ├── liblibforkserver-rs.a
    │   └── lib/
    │ # Go instrumentation
    ├── goinstr_difuzz
    ├── goinstr_sancov
    ├── goinstr_coverage
    ├── goinstr-difuzz/
    │ # Target template
    ├── template/
    │ # Documentation
    └── DOCUMENTATION.md

Директория `template/` содержит шаблоны файлов для сборки проектов, а также вспомогательный скрипт `gen_target.py` для автоматического реконфигурирования фаззинг-цели.


# Конфигурирование фаззинг-целей для LibAFL-DiFuzz

При добавлении новой фаззинг-цели необходимо подготовить ряд обязательных файлов. Каталог `template/` содержит шаблоны этих файлов, а также специальный скрипт для их автоматической генерации. Структура каталога `template/` имеет следующий вид:

    template/
    ├── gen_target.py
    ├── config.toml
    ├── Makefile_release.toml
    ├── Makefile_release_rust.toml
    └── Makefile_release_go.toml

Полная конфигурация фаззинг-цели для LibAFL-DiFuzz должна включать следующие файлы:
* `config.toml` содержит перечень целевых точек и информацию об их расположении в исходном коде
* `Makefile.toml` описывает все этапы сборки, включая этап статической предобработки
* Исходный код фаззинг-цели
* Скрипт сборки для исполняемого файла анализируемой программы

Скрипт `gen_target.py` предназначен для автоматической генерации файлов `config.toml` и `Makefile.toml` на основе параметров фаззинг-цели и имеющихся шаблонов. Скрипт имеет следующие аргументы:

* **-p [--project] \<name\>**: имя проекта
* **-s [--script] \<script-path\>**: путь до скрипта сборки фаззинг-цели
* **-t [--target-dir] \<target-dir\>**: путь до директоири с исходным кодом проекта
* **-m [--main-path] \<main-path\>**: путь до файла с реализацией функции _main_ относительно _target-dir_ (либо абсолютный путь)
* **-b [--bin-path] \<bin-path\>**: путь до исполняемого файла, построенного в результате сборки, относительно _target-dir_
* **-a [--bin-args] \<bin-args\>**: аргументы запуска исполняемого файла (с “_@@_” вместо имени входного файла)
* **-c [--config-dir] \<config-dir\>** (optional): путь до директории со сгенерированными файлами (по умолчанию ".")
* **-r [--rep-clone] \<clone-cmd\>**: (optional) bash-команда для клонирования репозитория проекта
* **-v [--version] \<version-cmd\>**: (optional) bash-команда для перехода на определенный коммпит в репозитории проекта
* **--mode \<mode\>**: режим сборки (_debug_/_release_), по умолчанию _release_
* **--root \<root-name\>**: имя функции, являющейся входной точкой в программе
* **-l [--lang] \<lang\>**: язык целевой программы (_c/rust/go_)

## Руководство для LibAFL-DiFuzz

Подробные примеры подготовки фаззинг-целей для LibAFL-DiFuzz приведены в гайдах:

* **C/C++**: Directed fuzzing for xlnt project with sydr‐fuzz (LibAFL‐DiFuzz backend) [[eng](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-xlnt-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29)] [[rus](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-xlnt-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29-%28rus%29)]
* **Rust**: Directed fuzzing for goblin project with sydr‐fuzz (LibAFL‐DiFuzz backend) [[eng](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-goblin-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29)] [[rus](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-goblin-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29-%28rus%29)]
* **Go**: Directed fuzzing for golang image (Go) project with sydr‐fuzz (LibAFL‐DiFuzz backend) [[eng](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-golang-image-%28Go%29-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29)] [[rus](https://github.com/ispras/oss-sydr-fuzz/wiki/Directed-fuzzing-for-golang-image-%28Go%29-project-with-sydr%E2%80%90fuzz-%28LibAFL%E2%80%90DiFuzz-backend%29-%28rus%29)]


# Интеграция со статическим анализатором Svace

Для проверки потенциальной достижимости точек, размеченных Svace, на существующих фаззинг-целях используется скрипт `tp_validate.py`. В качестве входных данных он принимает
отчет Svace в формате .csv, каталог с исходным кодом проекта, а также путь до:
* исполняемых файлов фаззинг-целей, собранных `wllvm/wllvm++` компилятором, для C/C++;
* файлов с LLVM биткодом для Rust;
* исходного кода фаззинг-цели с `main` функциоей для Go.

Полный список аргументов:

* **--csv <csv-path>**: путь до CSV файла с отчетом Svace со столбцами *file*, *line*, and *status*
* **--out <output-dir>**: выходная директория; обязательна, если не указана *--dry-run*
* **--project-dir <project-dir>**: путь до каталога с исходным кодом проекта
* **--bins <bins>**: разделенные запятой пути до исполняемых файлов (или LLVM биткод для Rust, или исходный файл с *main* для Go)
* **--difuzz <difuzz-path>**: путь для исполняемого файла *difuzz*/*difuzz-rust*/*difuzz-go*
* **--filter-status <mode>**: статус ошибки (*confirmed/unclear/confirmed-unclear/paths*)
* **--filter-severity <level>**: критичность ошибки (*critical/major/normal/keep-all*)
* **--difuzz-jobs <jobs>**: число параллельных процессов для *difuzz*/*difuzz-rust*/*difuzz-go*
* **--clean-artifacts**: удалить промежуточные артефакты и оставить только результаты
* **--dry-run**: запуск анализе без генерации выходных данных
* **--difuzz-analyse-icalls <mode>**: анализ неявных вызовов (*strong/weak/disabled*)
* **--difuzz-analyse-icalls-cache <cache>**: включение кэша неявных вызовов
* **--log-level <level>**: уровень логгирования (*info/debug/trace*)

## Примеры запуска скрипта

Для C/C++:

```bash
$ /sydr/difuzz/tp_validate.py --csv markers_23.csv --project-dir /giflib --out . --bins '/giflib/build/bin1,/giflib/build/bin2' --difuzz /sydr/difuzz/difuzz --clean-artifacts --log-level debug
```

Для Go:

```bash
$ /sydr/difuzz/tp_validate.py --csv markers_34.csv --project-dir /image --out . --bins '/image/cmd/**/main.go' --difuzz /sydr/difuzz/difuzz-go --dry-run --log-level trace
```
