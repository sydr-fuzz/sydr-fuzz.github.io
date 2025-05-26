# Гибридный фаззер Sydr-fuzz

* TOC
{:toc}

[Sydr-fuzz](https://sydr-fuzz.github.io) - это инструмент динамического анализа для безопасного
цикла разработки ПО. Sydr-fuzz сочетает в себе мощь инструмента динамического
символьного выполнения Sydr и современных фаззеров. Sydr позволяет увеличивать
покрытие кода и обнаруживать ошибки. На данный момент sydr-fuzz позволяет
запускать Sydr вместе с [libFuzzer](https://www.llvm.org/docs/LibFuzzer.html),
[AFL++](https://aflplus.plus/) и [Honggfuzz](https://honggfuzz.dev/), а также поддерживает
фаззинг Python/CPython с помощью [Atheris](https://github.com/google/atheris),
фаззинг Java с помощью [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer),
фаззинг JavaScript c помощью [Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js),
фаззинг Lua с помощью [luzer](https://github.com/ligurio/luzer) и
фаззинг C# с помощью [Sharpfuzz](https://github.com/Metalnem/sharpfuzz) для
инструментации кода и [AFL++](https://aflplus.plus/) для фаззинга.
Примеры уже настроенных фаззинг целей для sydr-fuzz можно найти в репозитории
[OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz). По сути sydr-fuzz
реализует пайплайн фаззинга:

- Гибридный фаззинг с помощью Sydr и одного из фаззеров (libFuzzer, AFL++, Honggfuzz),
  фаззинг Python (Atheris), Java (Jazzer), JavaScript (Jazzer.js), Lua (luzer)
  и C# (Sharpfuzz): `sydr-fuzz run`
- Минимизация корпуса: `sydr-fuzz cmin` (шаг обязателен для AFL++)
- Поиск ошибок (выхода за границы буфера, целочисленного переполнения, деления
  на нуль и др.) символьными предикатами безопасности Sydr: `sydr-fuzz security`
- Сбор покрытия: `sydr-fuzz cov-html`
- Дедупликация, кластеризация и оценка критичности аварийных завершений и ошибок
  неопределенного поведения с использованием Casr, а также выгрузка новых
  уникальных отчетов в систему [DefectDojo](https://github.com/DefectDojo/django-DefectDojo):
  `sydr-fuzz casr --ubsan --url <URL>`

Гайды, публикации, презентации, трофеи, бенчмарки и другую полезную информацию
можно найти на [сайте](https://sydr-fuzz.github.io).

# Трофеи

Список трофеев можно найти в репозитории
[OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz/blob/master/TROPHIES.md).

## Опции

Доступные опции:

    $ sydr-fuzz -h
    ISP RAS
    Continuous hybrid fuzzing and dynamic analysis for security development lifecycle

    Usage: sydr-fuzz [OPTIONS] <COMMAND>

    Commands:
      run         Run hybrid fuzzing with Sydr and libFuzzer/AFL++/Honggfuzz, Python
                      fuzzing with Atheris, Java fuzzing with Jazzer, JavaScript fuzzing with
                      Jazzer.js, or C# fuzzing wiht Sharpfuzz
      cmin        Minimize corpus
      security    Check security predicates (out of bounds, integer overflow, division by
                      zero, etc.) for corpus seeds
      casr        Triage, deduplicate, cluster, and create reports for crashes and UBSAN
                      runtime errors
      rm-crashes  Remove crashes from corpus
      cov-html    Generate HTML coverage report
      cov-export  Collect and export corpus coverage in JSON or lcov trace file format
      cov-report  Collect corpus coverage and display summary
      cov-show    Collect and show line by line corpus coverage
      pycov       Collect and export corpus coverage in specified format for Python
                      targets
      jacov       Collect and export corpus coverage in specified format for Java targets
      jscov       Collect and export corpus coverage in specified format for JavaScript
                      targets
      sharpcov    Collect and export corpus coverage in specified format for C# targets
      luacov      Collect and export corpus coverage for Lua targets
      init        Create basic TOML config file template
      help        Print this message or the help of the given subcommand(s)

    Options:
      -l, --log-level <LEVEL>  Logging level [default: info] [possible values: minimal, info,
                               debug, trace]
      -c, --config <FILE>      Configuration file [default: sydr-fuzz.toml]
      -o, --output <OUT_DIR>   Output project directory with artifacts [default: <CONFIG>-out]
      -h, --help               Print help
      -V, --version            Print version


Опция **-c, \--config \<FILE\>** указывает путь к конфигурационному файлу в TOML
формате для запуска фаззинга (по умолчанию `sydr-fuzz.toml`).

Опция **-l, \--log-level \<LEVEL\>** указывает уровень логирования (`info` по
умолчанию) для сообщений от sydr-fuzz (`sydr-fuzz.log`). Уровни логирования:
`minimal|info|debug|trace`. Уровень логирования `minimal`
позволяет печатать только самые информативные сообщения уровня
логирования `info`.

Опция **-o, \--output \<OUT_DIR\>** указывает путь до выходной директории с
проектом, где содержатся артефакты и результаты работы фаззинга. Если не
указывать эту опцию, то проект создастся в текущей директории с именем
`<CONFIG>-out`.

### Опции для создания шаблона конфигурационного TOML файла

    $ sydr-fuzz-init
    Create basic TOML config file template

    Usage: sydr-fuzz init [OPTIONS]

    Options:
          --libfuzzer [<RUN_TARGET_LINE>...]  Add libFuzzer table to TOML config template
          --afl [<RUN_TARGET_LINE>...]        Add AFL++ table to TOML config template
          --honggfuzz [<RUN_TARGET_LINE>...]  Add Honggfuzz table to TOML config template
          --sydr [<RUN_TARGET_LINE>...]       Add Sydr table to TOML config template
          --cov [<RUN_TARGET_LINE>...]        Add coverage table to TOML config template
      -c, --corpus <corpus>                   Path to corpus directory
          --atheris [<RUN_TARGET_LINE>...]    Add Atheris table to TOML config template
          --jazzer <TARGET_CLASS>             Add Jazzer table to TOML config template
          --jazzer-js [<RUN_TARGET_LINE>...]  Add Jazzer.js table to TOML config template
          --sharpfuzz [<RUN_TARGET_LINE>...]  Add Sharpfuzz table to TOML config template
          --luzer [<TARGET_PATH>...]          Add luzer table to TOML config template
      -h, --help                              Print help

Опция **--libfuzzer** добавляет таблицу libFuzzer.

Опция **--afl** добавляет таблицу AFL++.

Опция **--honggfuzz** добавляет таблицу Honggfuzz.

Опция **--sydr** добавляет таблицу Sydr.

Опция **--cov**  добавляет таблицу для сбора покрытия (для компилируемых языков или C#)
Может быть указана только вместе с одной из таблиц AFL++, libFuzzer, Sydr, Sharpfuzz.

Опция **-c, --corpus** указывает путь до директории с корпусом.

Опция **--atheris** добавляет таблицу Atheris (несовместима с другими таблицами).

Опция **--jazzer** добавляет таблицу Jazzer (несовместима с другими таблицами).

Опция **--jazzer-js** добавляет таблицу Jazzer.js (несовместима с другими таблицами).

Опция **--sharpfuzz** добавляет таблицу Sharpfuzz (несовместима с другими таблицами, кроме [cov]).

Опция **--luzer** добавляет таблицу luzer.

### Опции запуска фаззинга

    $ sydr-fuzz run -h
    Run hybrid fuzzing with Sydr and libFuzzer/AFL++/Honggfuzz, Python fuzzing with Atheris,
    Java fuzzing with Jazzer, JavaScript fuzzing with Jazzer.js, or C# fuzzing wiht Sharpfuzz

    Usage: sydr-fuzz run [OPTIONS]

    Options:
          --use-sydr-inputs      Use files generated by Sydr as new inputs for Sydr (relevant
                                 only for libFuzzer random and file-info strategies)
          --attach               Attach Sydr to existing fuzzing process
      -f, --force-remove         Remove output project directory if it exists
      -s, --strategy <STRATEGY>  Strategy for scheduling Sydr input seeds [default: coverage]
                                 [possible values: coverage, random, file-info]
          --runs <N>             Stop sydr-fuzz after N Sydr runs
      -h, --help                 Print help

Опция **-f, \--force-remove** перезаписывает всю выходную директорию с проектом.

Нижеперечисленные опции для фаззинга Python-кода не поддерживаются.

Опция **\--runs \<N\>** задает число запусков Sydr, после которого работа
sydr-fuzz будет завершена.

Опция **-s, \--strategy \<STRATEGY\>** указывает стратегию для выбора входных
файлов из очереди для запуска на них Sydr при гибридном фаззинге. Стратегия
`coverage` используется по умолчанию. В данной стратегии входные данные из
корпуса фаззера, которые принесли больше покрытия, позже созданы и имеют
меньший размер, имеют больший приоритет. Стратегия `file-info` учитывает только
время создания файла и размер (файлы созданные позже и меньшего размера имеют
приоритет выше). Стратегия `random` выбирает входные данные случайным образом.

Опция **\--use-sydr-inputs** позволяет запускать Sydr на своих же входных данных
при гибридном фаззинге. Имеет эффект только вместе со стратегиями libFuzzer
`file-info` и `random`.

Опция **\--attach** позволяет запускать Sydr в режиме присоединения к внешнему
фаззеру. Для этого в toml-конфиге должны быть заданы соответствующие
директории: директория фаззера (`fuzzer_dir`) и выходная директория для Sydr
(`output_dir`). В случае фаззера AFL++ ожидается, что в `fuzzer_dir` существует
файл `fuzzer_setup` и директория `queue`, откуда будут выбираться входные данные
для Sydr. В качестве стратегии выбора входных файлов используется `coverage`.
Для остальных фаззеров, совместимых с Sydr, входные данные непосредственно
извлекаются из `fuzzer_dir`, стратегия выбора - `file-info`.
Сгенерированные инструментом Sydr файлы будут подкладываться в директорию `output_dir`.
При работе с фаззерами, отличными от AFL++, через соответствующий параметр в
конфигурационном файле можно указать, необходимо ли производить минимизацию
сгенерированных инструментом Sydr входных файлов.

### Опции генерации HTML отчета о покрытии (C/C++/Rust/Python/Go/Java/JavaScript/C#/Lua)

    $ sydr-fuzz cov-html -h
    Generate HTML coverage report

    Usage: sydr-fuzz cov-html [OPTIONS]

    Options:
      -j, --jobs <N>  Number of parallel jobs to collect and merge raw LLVM coverage [default:
                      half of cpu cores]
      -h, --help      Print help

Опция **-j, \--jobs \<N\>** позволяет задать количество потоков для сбора данных
LLVM покрытия (не применяется для Python).
По умолчанию данное значение равно половине ядер процессора.

При сборе покрытия Java-кода через переменную окружения `CASR_SOURCE_DIRS`
можно указать пути до исходного кода (список путей, разделенных через ':').
Тогда информация о нем будет отражена в html отчете:

    $ export CASR_SOURCE_DIRS=/dir/with/sources/1:/dir/with/sources/2
    $ sydr-fuzz cov-html

### Продвинутые опции сбора покрытия (C/C++/Rust)

**sydr-fuzz cov-export** собирает покрытие и экспортирует его в JSON или lcov
формат

**sydr-fuzz cov-report** собирает покрытие и выводит краткий отчет о покрытии в
процентах

**sydr-fuzz cov-show** собирает и выводит покрытие по строкам

Все три команды имеют одинаковый интерфейс задания дополнительных аргументов
после `--`:

    $ sydr-fuzz cov-report -h
    Collect corpus coverage and display summary

    Usage: sydr-fuzz cov-report [OPTIONS] [-- [ARGS]...]

    Arguments:
      [ARGS]...  llvm-cov report extra options after --

    Options:
      -j, --jobs <N>  Number of parallel jobs to collect and merge raw coverage [default: half
                      of cpu cores]
      -h, --help      Print help

Опция **-j, \--jobs \<N\>** позволяет задать количество потоков для сбора данных покрытия.
По умолчанию данное значение равно половине ядер процессора.

**cov-COMMAND** заимствованы от команд
[llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html). Дополнительные
аргументы **ARGS**, которые можно перечислить после `--`, представляют собой
соответствующие опции и аргументы для команд llvm-cov за тем исключением, что
целевой бинарный файл и опция **-instr-profile** заранее заданы. Например:

    $ sydr-fuzz cov-report -j 4 -- -use-color=true

По умолчанию `llvm-cov` ищется в `PATH`. Однако можно указать свой путь до
`llvm-cov` в переменной среды `SYDR_LLVM_COV`. Тогда путь до `llvm-profdata`
составится автоматически на основе пути до `llvm-cov`.

### Продвинутые опции сбора покрытия (Python)

    $ sydr-fuzz pycov -h
    Collect and export corpus coverage in specified format for Python targets

    Usage: sydr-fuzz pycov <FORMAT> [-- [ARGS]...]

    Arguments:
      <FORMAT>   Coverage format (report, html, xml, json, lcov, etc.)
      [ARGS]...  coverage FORMAT extra options after --

    Options:
      -h, --help  Print help

Дополнительные аргументы **<ARGS>**, которые можно перечислить после `--`,
представляют собой соответствующие опции и аргументы
[Coverage](https://coverage.readthedocs.io/en/latest/cmd.html).

### Продвинутые опции сбора покрытия (Java)

    $ sydr-fuzz jacov -h
    Collect and export corpus coverage in specified format for Java targets

    Usage: sydr-fuzz jacov <FORMAT> [-- [ARGS]...]

    Arguments:
      <FORMAT>   Coverage format (html, xml, csv) [possible values: html, xml, csv]
      [ARGS]...  Extra jacococli options after --

    Options:
      -h, --help  Print help

Дополнительные аргументы **<ARGS>**, которые можно перечислить после `--`,
представляют собой соответствующие опции и аргументы
[jacococli report](https://www.eclemma.org/jacoco/trunk/doc/cli.html).

Например, можно указать путь до исходного кода. Тогда информация о нем будет
отражена в html отчете:

    $ sydr-fuzz jacov html -- --sourcefiles <path>

Можно использовать переменную окружения `CASR_SOURCE_DIRS` для указания путей к
директориям, содержащим файлы исходного кода (список путей, разделенных через ':').

### Продвинутые опции сбора покрытия (JavaScript)

    $ sydr-fuzz jscov -h
    Collect and export corpus coverage in specified format for JavaScript targets

    Usage: sydr-fuzz jscov <FORMAT> [-- [ARGS]...]

    Arguments:
      <FORMAT>   Coverage format (clover, cobertura, html-spa, html, json-summary, json, lcov,
                 lcovonly, teamcity, text-lcov, text-summary, text) [possible values: clover,
                 cobertura, html-spa, html, json-summary, json, lcov, lcovonly, teamcity,
                 text-lcov, text-summary, text]
      [ARGS]...  Extra coverage options after --

    Options:
      -h, --help  Print help

Дополнительные аргументы **<ARGS>**, которые можно перечислить после `--`,
представляют собой соответствующие опции и аргументы
[Jazzer.js](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/docs/fuzz-targets.md#coverage-report-generation).

### Продвинутые опции сбора покрытия (C#)

    $ sydr-fuzz sharpcov -h
    Collect and export corpus coverage in specified format for C# targets

    Usage: sydr-fuzz sharpcov <FORMAT> [-- [ARGS]...]

    Arguments:
      <FORMAT>   Coverage format (html, lcov, clover, coveralls, xml, opencover, cobertura,
                 text) [possible values: html, lcov, clover, coveralls, xml, opencover,
                 cobertura, text]
      [ARGS]...  Extra minicover/altcover instrument options after --

    Options:
      -h, --help  Print help

Дополнительные аргументы **<ARGS>**, которые можно перечислить после `--`,
представляют собой соответствующие опции и аргументы
[AltCover](https://stevegilham.com/altcover/Usage) (для форматов lcov и html) или
[minicover instrument](https://github.com/lucaslorentz/minicover?tab=readme-ov-file#instrument)
(для форматов html, clover, coveralls, xml, opencover, cobertura, text).
Для `AltCover` можно добавлять опции `--fileFilter`, `--pathFilter`, `--assemblyFilter`, `--assemblyExcludeFilter`,
`--typeFilter`, `--methodFilter`, `--attributeFilter`, `--attributetoplevel`, `--typetoplevel`, `--methodtoplevel`,
`--localSource`, `--callContext`, `--methodpoint`, `--single`, `--linecover`, `--branchcover`.
Как дополнительные аргументы `minicover instrument` можно добавлять опции `--sources`, `--assemblies`, `--tests`,
`--exclude-sources`, `exclude-assemblies` и `exclude-tests`.

### Продвинутые опции сбора покрытия (Lua)
Сбор покрытия после фаззинга с помощью [luzer](https://github.com/ligurio/luzer) и движка
libFuzzer (данный способ фаззинга поддерживается через sydr-fuzz) осуществляется посредством утилиты LuaCov:

    # sydr-fuzz -c name.toml luacov
    Collect and export corpus coverage for Lua targets

    Usage: sydr-fuzz luacov

    Options:
      -h, --help  Print help

### Сбор покрытия (Go)

Сбор покрытия после фаззинга с помощью
[go-fuzz](https://github.com/dvyukov/go-fuzz) и движка libFuzzer (данный способ
фаззинга поддерживается через sydr-fuzz) осуществляется следующим образом:

Переходим в директорию, содержащую исходный код проекта, для которого
осуществлялся фаззинг. Пример:

    # cd /image

Копируем полученный после фаззинга корпус в директорию `corpus`, созданную в
корне репозитория с проектом. Пример:

    # cp -r /fuzz/webp-out/corpus /image/corpus

Собираем цель для go-fuzz без поддержки libFuzzer:

    # go-fuzz-build -func=FuzzWebp -o fuzz_webp.zip

Запускаем фаззинг с опцией сбора покрытия, ждём пока импортируется корпус. После
этого завершаем фаззинг. Можно нажать Ctrl+C, когда более 10 секунд не растет
покрытие `cover` и `corpus` не меньше размера корпуса в сообщениях вида
`2023/03/03 17:09:40 workers: 12, corpus: 834 (34s ago), crashers: 2, restarts:
1/5587, execs: 1033722 (21528/sec), cover: 1309, uptime: 48s`

    # go-fuzz -bin=fuzz_webp.zip -dumpcover

Исправляем файл с покрытием с помощью sed:

    # sed -i '/0.0,1.1/d' coverprofile

Генерируем отчёт о покрытии:

```
# go tool cover -html=coverprofile
HTML output written to /tmp/cover2240572277/coverage.html
```

### Опции проверки предикатов безопасности (C/C++/Rust/Go)

    $ sydr-fuzz security -h
    Check security predicates (out of bounds, integer overflow, division by zero, etc.) for
    corpus seeds

    Usage: sydr-fuzz security [OPTIONS]

    Options:
      -f, --force-remove       Remove output project directory if it exists
      -j, --jobs <N>           Number of Sydr jobs
      -t, --timeout <SECONDS>  Timeout (in seconds) for target execution [default: 30]
          --runs <runs>        Check security predicates for N seeds from corpus
      -h, --help               Print help

Опция **-f, \--force-remove** перезаписывает всю выходную директорию с проектом.

Опция **-j, \--jobs \<N\>** позволяет изменить количество запускаемых Sydr.

Опция **\--runs \<N\>** задает число файлов из корпуса, на которых будет
запущена проверка предикатов безопасности. После заданного числа запусков
sydr-fuzz прекратит работу.

Опция **-t, \--timeout \<SECONDS\>** устанавливает время выполнения фаззинг цели в секундах, которое
будет считаться тайм-аутом (по умолчанию 30 секунд).

### Опции запуска анализа аварийных завершений и ошибок неопределенного поведения с помощью Casr

    $ sydr-fuzz casr -h
    Triage, deduplicate, cluster, and create reports for crashes and UBSAN runtime errors

    Usage: sydr-fuzz casr [OPTIONS]

    Options:
          --no-cluster               Do not cluster reports
          --ubsan                    Create and triage UndefinedBehaviorSanitizer reports
      -p                             Use PATH environment variable to find casr tools
          --ignore <FILE>            File with regular expressions for functions and file
                                     paths to filter in call stacks
      -j, --jobs <N>                 Number of parallel jobs for crash triaging [default: half
                                     of cpu cores]
      -t, --timeout <SECONDS>        Timeout (in seconds) for target execution [set 0 to
                                     disable] [default: 30]
          --no-casr-gdb              Do not collect crash reports via casr-gdb
          --san-force                Force casr-san run without sanitizers symbols check
          --url <URL>                Upload new and unique CASR reports to DefectDojo at base
                                     URL
          --token <TOKEN>            DefectDojo API key (required when DefectDojo URL is
                                     provided)
          --product <PRODUCT>        DefectDojo product name (required when DefectDojo URL is
                                     provided)
          --engagement <ENGAGEMENT>  DefectDojo engagement name [default: TOML config name +
                                     datetime]
      -h, --help                     Print help

Опция **\--ignore \<FILE\>** - позволяет задать файл с регулярными выражениями для функций и путей,
которые будут отфильтрованы в стекax вызовов.

Опция **-j, \--jobs \<N\>** - позволяет задать число потоков для параллельного
анализа аварийных завершений.
По умолчанию данное значение равно половине ядер процессора.

Опция **\--no-casr-gdb** - осуществление анализа без запуска casr-gdb.

Опция **\--no-cluster** - осуществление анализа без запуска кластеризации отчетов об аварийных завершениях.

Опция **-p** - поиск путей до casr инструментов с помощью переменной окружения PATH.

Опция **\--san-force** отключает проверку наличия символов ASAN в фаззинг цели и
принудительно запускает `casr-san`.

Опция **-t, \--timeout \<SECONDS\>** - позволяет установить тайм-аут на выполнение фаззинг
цели под casr-san/casr-gdb (по умолчанию 30 секунд). Чтобы отключить тайм-аут,
нужно значение опции равное 0.

Опция **\--ubsan** включает анализ ошибок неопреденного поведения (UBSAN).

При анализе аварийных завершений Java программ можно использовать переменную среды
`CASR_SOURCE_DIRS` (список путей, разделенных через ':') для указания путей к директориям,
содержащим файлы исходного кода.

С помощью опции **\--url \<URL\>** можно указать ссылку для экспорта полученных
CASR отчетов в DefectDojo. Использование данной опции инициирует процесс
экспорта.

Опция **\--token \<TOKEN\>** позволяет задать DefectDojo API key.

Опция **\--product \<PRODUCT\>** позволяет указать название анализируемого продукта.

Опция **\--engagement \<ENGAGEMENT\>** позволяет задать название очередной серии
анализа в рамках продукта (по умолчанию складывается из имени
конфигурационного файла и даты).

Для аккумуляции отчетов с найденными ранее ошибками можно использовать
переменную среды `CASR_PREV_CLUSTERS_DIR`, указав путь к предыдущей кластерной
структуре (например `CASR_PREV_CLUSTERS_DIR=<previous_output_dir>/casr`).
Указанная директория будет скопирована в выходную директорию проекта, а новые
аварийные завершения и их отчёты будут в ней накапливаться.

### Опции удаления аварийных завершений из корпуса

    $ sydr-fuzz rm-crashes -h
    Remove crashes from corpus

    Usage: sydr-fuzz rm-crashes [OPTIONS] <PATH>

    Arguments:
      <PATH>  Path to corpus directory.

    Options:
      -j, --jobs <N>           Number of parallel jobs to run target on inputs [default: half
                               of cpu cores]
      -t, --timeout <SECONDS>  Timeout (in seconds) for target execution [default: 30]
      -h, --help               Print help

Аргумент **<PATH>** позволяет указать путь к корпусу.

Опция **-j, --jobs <N>** - позволяет задавать число потоков для запуска фаззинг
цели на входных данных из корпуса.
По умолчанию данное значение равно половине ядер процессора.

Опция **-t, \--timeout \<SECONDS\>** - позволяет установить тайм-аут на выполнение фаззинг
цели (по умолчанию 30 секунд).


### Результаты фаззинга

Результаты фаззинга и промежуточные артефакты сохраняются в директории проекта.
Путь до директории с выходным проектом может быть задан пользователем с помощью
опции `-o` перед командой запуска (`run`, `security`). Если опцию `-o` не задавать,
то директория с проектом автоматически создаcтся в текущей директории со
следующим именем: `<config-name>-out`. Директория с проектом имеет следующий вид:

    sydr-fuzz-out/
    ├── <fuzzer>
    │   └── ...
    ├── crashes
    │   ├── crash-deadbeaf
    │   ├── oom-cafebabe
    │   └── timeout-cafecafe
    ├── corpus
    │   └── seed
    ├── corpus-old
    │   └── seed
    ├── sydr
    │   ├── cache
    │   ├── logs
    │   │   └── log_seed.txt
    │   ├── stats
    │   │   └── stats_seed.json
    │   ├── annotated-logs
    │   │   └── log_seed.txt
    │   └── seeds
    │       └── seed
    ├── coverage
    │   └── cov.profdata
    ├── casr
    │   ├── cl1
    │   │   ├── crash-deadbeaf1
    │   │   ├── crash-deadbeaf1.casrep
    │   │   └── crash-deadbeaf1.gdb.casrep
    │   ├── cl2
    │   │   ├── crash-deadbeaf2
    │   │   ├── crash-deadbeaf2.casrep
    │   │   └── crash-deadbeaf2.gdb.casrep
    │   ├── oom
    │   │   └── oom-deadbeaf3
    │   ├── timeout
    │   │   └── timeout-deadbeaf4
    │   └── ubsan
    │       ├── corus_seed
    │       ├── corus_seed_src_1_1.casrep
    │       └── corus_seed_src_2_1.casrep
    ├── security
    │   └── sydr_file0_out_of_bounds_0
    ├── security-verified
    │   └── sydr_file0_out_of_bounds_0
    ├── security-unique
    │   └── sydr_file0_out_of_bounds_0
    ├── sydr-fuzz.log
    ├── sydr-fuzz-cmin.log
    ├── sydr-fuzz-security.log
    └── sydr-fuzz-coverage.log


Директория <fuzzer> является рабочей директорией фаззера. В зависимости от
конфигурации анализа и выбранного инструмента фаззинга, директория проекта
может содержать `libfuzzer`, `aflplusplus` (в т.ч. при использовании Sharpfuzz),
`honggfuzz`, `atheris`, `jazzer` или `jazzer.js`. В случае ensemble-фаззинга могут
присутствовать сразу несколько из перечисленных директорий. Директории `libFuzzer`,
`atheris`, `jazzer` и `jazzer.js` содержат логи для каждого запущенного процесса
фаззера (cmin.log, fuzz-0.log, fuzz-1.log и т.д.).

    libfuzzer(athris,jazzer,jazzer.js)/
    ├── cmin.log
    └── fuzz-1.log

Директория `aflplusplus` является общей выходной директорией для AFL++ и содержит
директории `aflplusplus/*-worker` для каждого запущенного процесса AFL++ и Sydr
(`sydr-worker` требуется для синхронизации между AFL++ и Sydr). В случае Sharpfuzz
`sydr-worker` отсутствует. Каждая worker-директория содержит директории с рабочим
корпусом (`queue`), найденными аварийными завершениями (`crashes`) и зависаниями
(`hangs`). В директории `aflplusplus/logs` хранятся логи AFL++.

    aflplusplus/
    ├── afl_main-worker
    │   ├── crashes
    │   ├── hangs
    │   └── queue
    ├── afl_s01-worker
    │   ├── crashes
    │   ├── hangs
    │   └── queue
    ├── sydr-worker
    │   ├── crashes
    │   └── queue
    └── logs
        ├── afl_main.log
        └── afl_s01.log

Директория `honggfuzz` является рабочей директорией для Honggfuzz и содержит логи
запуска фаззера (`cmin-0.log`, `fuzz-0.log`), общий лог с отчетами санитайзеров
о найденных ошибках `HONGGFUZZ.REPORT.TXT`, файл со статистикой фаззинга `stats.txt`,
директорию с найденными аварийными завершениями и зависаниями `crashes`, а также
директорию для синхронизации с Sydr-ом `sydr-worker`.

    honggfuzz/
    ├── cmin-0.log
    ├── fuzz-0.log
    ├── HONGGFUZZ.REPORT.TXT
    ├── stats.txt
    ├── crashes/
    └── sydr-worker/

В директории `crashes` будут помещены все найденные c помощью фаззера и Sydr ошибки
(crash-\*, oom-\*, timeout-\*, leak-\*). При фаззинге с AFL++ ошибки также сохраняются в
выходных директориях фаззеров (`sydr-fuzz-out/aflplusplus/*-worker/(crashes|hangs)`).

Директория `corpus` содержит стартовый корпус фаззинга. В начале анализа все
указанные в опциях фаззера исходные корпуса минимизируются (можно отключить
параметром `cmin` в таблице фаззера) и сохраняются в `corpus`. Для libFuzzer
эта директория является рабочей, и по окончании фаззинга она содержит полный
корпус фаззинга. Для AFL++ `corpus` является только стартовым набором файлов и
по окончании фаззинга не содержит новых файлов. Рабочие директории AFL++ расположены
в `aflplusplus/*-worker/queue`, чтобы собрать все корпуса вместе, требуется
запустить команду `sydr-fuzz cmin`. После запуска команды минимизации корпуса,
директория `corpus` содержит выходной минимизированный корпус, достигнутый
в процессе фаззинга. Полный не минимизированный корпус сохраняется в директории
`corpus-old`.

`sydr` является рабочей директорией для всего пула Sydr'ов. В этой директории
хранятся логи (`sydr/logs/log_<input-name>.txt`), аннотированные логи
(`sydr/annotated-logs/log_<input-name>.txt`), которые были проаннотированы
во время верификации результатов режима проверки предикатов безопасности,
исходные входные данные для Sydr (`sydr/seeds/`) и файлы со статистикой Sydr
(`sydr/stats/stats_<input-name>.json`). Также хранится общий кэш (`cache`).

В директории `coverage` хранятся данные о покрытии на сгенерированном корпусе.

В директории `casr` хранятся размеченные по кластерам аварийные завершения, обнаруженные
в процессе фаззинга. В директории каждого кластера `cl<i>` находятся входной файл
для воспроизведения и \*.casrep файлы с подробной информацией об ошибке. Т.к.
AFL++ не отличает аварийное завершение от out of memory, приводящие к oom файлы
обнаруживаются с помощью Casr и сохраняются в директорию `casr/oom`. При достижении
тайм-аута во время работы casr-san соответствующий входной файл будет помещен
в директорию `casr/timeout`. В директории `casr/ubsan` хранятся отчёты об
ошибках неопределенного поведения.

В директории `security` хранятся результаты работы Sydr в режиме проверки предикатов
безопасности. В директории `security-verified` хранятся верифицированные результаты работы
Sydr в режиме проверки предикатов безопасности. В директории `security-unique`
хранятся уникальные верифицированные результаты работы Sydr в режиме проверки
предикатов безопасности.

Логи запусков sydr-fuzz в режиме `run`, `cmin`, `security` и `cov-*` лежат в корне проекта
(`sydr-fuzz.log`, `sydr-fuzz-cmin.log`, `sydr-fuzz-security.log`, `sydr-fuzz-coverage.log`).

## Гибридный фаззинг с помощью sydr-fuzz

Распакуйте Sydr в директории с конфигурационным файлом sydr-fuzz:

    $ unzip sydr.zip

Запустите подготовленный докер и примонтируйте директорию с конфигурационным
файлом sydr-fuzz в директорию `/fuzz` внутри докера:

    $ sudo docker run --cap-add=SYS_PTRACE  --security-opt seccomp=unconfined \
        --network host -v /etc/localtime:/etc/localtime:ro \
        -v /var/hasplm:/var/hasplm -v /etc/hasplm:/etc/hasplm \
        --rm -it -v $PWD:/fuzz sydr-fuzz-target /bin/bash

Опции `--cap-add=SYS_PTRACE` и `--security-opt seccomp=unconfined` (либо просто
`--privileged`) нужны для работы Casr. Опция `--network host` нужна для подключения
сетевого USB-ключа Sentinel.

Зайдите в директорию `/fuzz`:

    # cd /fuzz

Запустите фаззинг:

    # sydr-fuzz run

Если конфигурационный файл называется иначе чем `sydr-fuzz.toml`, то его можно
явно указать:

    # sydr-fuzz -c name.toml run

В случае фаззинга с libFuzzer, можно дополнительно проверить, что обертка собрана
корректно. Для этого следует по логу убедиться, что покрытие (cov) растет. Если оно
не растет, то, возможно, либо входные данные не попадают в целевую функцию, либо
целевая библиотека собрана без инструментации libFuzzer.

При фаззинге с AFL++ имеется возможность
[отслеживать]((https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#e-the-status-of-the-fuzz-campaign))
состояние AFL++ с помощью утилит `afl-whatsup` и `afl-plot`. Утилита `afl-whatsup`
показывает подробную статистику фаззинга для каждого запущенного процесса AFL++,
для этого достаточно указать общую директорию `aflplusplus`:

    $ afl-whatsup name-out/aflplusplus

Утилита `afl-plot` позволяет строить графики для статистики работы AFL++, для этого
следует указать директорию конкретного процесса AFL++ и директорию для сохранения
построенных графиков:

    $ afl-plot name-out/aflplusplus/afl_main-worker plot_dir

Число входных данных от Sydr, которые принесли покрытие фаззеру, печатается в
логе как "[SYDR] Files reloaded by libFuzzer: {}, unique {}" для libFuzzer,
"[SYDR] Files imported by AFL++: {}" для AFL++,
"[SYDR] Files reloaded by Honggfuzz: {}" для Honggfuzz. Для libFuzzer
дополнительно печатается число уникальных полезных файлов, поскольку
каждый запущенный инстанс libFuzzer'а анализирует файлы независимо и один и
тот же файл Sydr'а может учитываться несколько раз.

Сами полезные файлы можно найти следующим образом.

Для libFuzzer:

    $ find name-out/libfuzzer -name "fuzz-*.log" | xargs -I {} grep -H --color "Reloaded.*sydr_" {}

Для AFL++:

    $ ls name-out/aflplusplus/afl_main-worker/queue | grep "sync:sydr-worker"

Для Honggfuzz:

    $ find name-out/honggfuzz -name "fuzz-*.log" | xargs -I {} grep "File imported" {}

По завершении фаззинга результаты работы будут сохранены в `name-out/crashes`.
Рекомендуется воспользоваться комнандой `cmin` (см. следующий раздел)
для агрегации и минимизации фаззинг-корпуса в `name-out/corpus`.
В противном случае для AFL++ корпус будет содержаться либо в
`name-out/aflplusplus/afl_main-worker/queue` (после финальной синхронизации
AFL\_FINAL\_SYNC в afl++ v4.09c и выше), либо разбит по директориям
`name-out/aflplusplus/*-worker/queue`.

При гибридном фаззинге с AFL++ или Honggfuzz дополнительно выполняется минимизация
всех входных данных, генерируемых символьным исполнителем Sydr. Это делается с целью
уменьшить нагрузку на фаззер при синхронизации и сократить размеры корпусов данных,
поскольку число таких инпутов может быть очень велико. В случае гибридного фаззинга
с libFuzzer минимизация не требуется, поскольку фаззер каждую секунду сканирует
корпус и сохраняет себе только полезные инпуты. В случае AFL++ и Honggfuzz все инпуты
от Sydr cначала накапливаются в директории `output/sydr/sydr-bucket`, раз в минуту
запускается минимизация, по результатам сохраняются только интересные инпуты
(в `output/aflplusplus/sydr-worker/queue` или `output/honggfuzz/sydr-worker`).

Для AFL++ минимизация выполняется с помощью утилиты afl-showmap и глобальной битовой карты,
объединяемой между всеми запусками Sydr. Для Honggfuzz - с помощью запуска фаззера
в режиме минимизации (--minimize) только на текущем наборе данных в `sydr-bucket`.
Если Honggfuzz на каких-то целях работает слишком медленно, как альтернативу можно
использовать libFuzzer-merge: путь для libFuzzer-обертки нужно указать в параметре
"ilbfuzzer\_merge\_target" таблицы [honggfuzz] конфигурационного файла.

Минимизация инпутов Sydr для AFL++ и Honggfuzz может быть полностью выключена
с помощью параметра "minimize\_sydr\_inputs" таблицы [sydr] конфигурационного файла.

### Ensemble-фаззинг

Поддерживается возможность одновременного запуска libFuzzer, AFL++ и
Sydr (ensemble фаззинг). Для этого в конфигурационном файле должны присутствовать
таблицы для всех вышеперечисленных инструментов. Никаких дополнительных
опций/настроек задавать не нужно. При указании всех трех таблиц будет
произведен запуск фаззеров и символьного исполнителя. Следующий инпут для запуска
Sydr выбирается в соответствии с выбранной стратегией (по умолчанию - прирост
покрытия) поочередно из каждого фаззера.

Синхронизация между инструментами во время ensemble-фаззинга устроена
следующим образом:

- AFL++/Sydr: в общей для AFL директории `name-out/aflplusplus`
создается директория `sydr-worker/queue`, куда сохраняются сгенерированные
Sydr инпуты. Поскольку число таких инпутов может быть очень велико,
производится дополнительная минимизация с помощью afl-showmap.
- libFuzzer/Sydr: Sydr генерирует новые инпуты напрямую в директорию
корпуса libFuzzer'а `name-out/corpus` (в случае ensemble фаззинга --
`name-out/libfuzzer/queue`). Все непригодившиеся инпуты Sydr'а (которые
не были импортированы фаззером) удаляются из корпуса через 1 минуту.
- AFL++/libFuzzer: директория корпуса libFuzzer передается в AFL++
через опцию -F (внешний фаззер).
- libFuzzer/AFL++: новые инпуты из корпуса основного инстанса AFL++
периодически копируются в корпус libFuzzer'а. Через 1 минуту после этого,
все скопированные файлы из корпуса удаляются.

## Минимизация корпуса

Чтобы минимизировать корпус, надо запустить команду `cmin`:

    $ sydr-fuzz -c name.toml cmin

После этого содержимое оригинального корпуса будет помещено в директорию
`name-out/corpus-old`, минимизированный корпус будет в директории `name/corpus`.
Минимизация корпуса может быть запущена в несколько параллельных потоков, при
условии что утилита `afl-cmin` поддерживает такую функцию. Число параллельных
потоков указывается с помощью параметра `cmin` в конфигурационном
файле. По умолчанию используется половина всех доступных ядер на машине.

## Сбор покрытия (C/C++/Rust)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого приложения
и выполнять его обработку с помощью комманд llvm-cov. Для этого можно добавить
секцию `[cov]` в конфигурационный файл. Для AFL++ перед сбором
покрытия обязательно нужно провести минимизацию корпуса `sydr-fuzz cmin`, чтобы
собрать рабочие корпуса от всех процессов фаззера в одном месте.

```toml
[sydr]
target = "/target_sydr @@"

[libfuzzer]
path = "/target_fuzzer"

[cov]
target = "/instrumented_target @@"
```

**target** - строка запуска инструментированного для сбора покрытия целевого исполняемого
файла. При сборке исполняемого файла следует использовать флаги:
`-fprofile-instr-generate -fcoverage-mapping`. Если `@@` отсутствует в строке запуска, то
входные данные принимаются из стандартного потока ввода.

Для генерации HTML отчета о покрытии можно воспользоваться следующей командой:

    $ sydr-fuzz -c name.toml cov-html

Для запуска сбора покрытия на корпусе проекта и вывода краткого отчёта с цветной разметкой
можно выполнить следующую команду:

    $ sydr-fuzz -c name.toml cov-report -- -use-color=true

Для получения отчёта о покрытии в одном файле html (не рекомендуется для больших
проектов) можно воспользоваться следующей командой:

    $ sydr-fuzz -c name.toml cov-show -- -format=html > index.html

Более того, можно получить покрытие в формате LCOV с его дальнейшей конвертацией
в html, что позволяет более гибко задавать опции:

    $ sydr-fuzz -c name.toml cov-export -- -format=lcov > name.lcov
    $ genhtml -o name-cov-html name.lcov

Если `genhtml` выдает ошибку `ERROR: cannot read /path/to/file`, то можно
запустить его с опцией `--ignore-errors source`.

## Сбор покрытия (Python/Java/JavaScript)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого Python-, Java- или JavaScript-кода,
выполнять его обработку и получать отчет в формате html. Для этого достаточно
использовать команду

    $ sydr-fuzz -c name.toml cov-html

При сборе покрытия Java-кода через переменную окружения `CASR_SOURCE_DIRS`
можно указать пути до исходного кода (список путей, разделенных через ':').
Тогда информация о нем будет отражена в html отчете:

    $ export CASR_SOURCE_DIRS=/dir/with/sources/1:/dir/with/sources/2
    $ sydr-fuzz cov-html

## Сбор покрытия (C#)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого C#-кода.
Для этого нужно добавить секцию `[cov]` в конфигурационный файл.
В зависимости от требуемого формата покрытия нужно указать разные варианты `[cov]`:

Для форматов html, clover, coveralls, xml, opencover, cobertura, text используется
инструмент [minicover](https://github.com/lucaslorentz/minicover):
```toml
[cov]
target = "/fuzz/Program.cs"
source = "/source"
build_dir = "/fuzz"
tool_path = "/usr/bin/minicover"
use_minicover = true
```

Для формата lcov и html используется инструмент [AltCover](https://github.com/SteveGilham/altcover):
```toml
[cov]
build_dir = "/fuzz"
tool_path = "/usr/bin/altcover"
use_minicover = false
```

Чтобы собрать покрытие через `sydr-fuzz`, необходимо создать сборку в отдельной директории:

    $ mkdir build_cov && cd build_cov
    $ dotnet new console

Затем аналогично сборке для фаззинга можно в файле `Program.cs` написать обертку и
в `build_cov.csproj` файл добавить путь до модуля собранного проекта, либо можно
указать путь до .csproj файла проекта:

```xml
<ItemGroup>
    <Reference Include="target_name">
      <HintPath>/path/to/bin/target_name.dll</HintPath>
    </Reference>
</ItemGroup>
```
либо
```xml
<ItemGroup>
    <ProjectReference Include="/path/to/csproj/target_name.csproj" />
</ItemGroup>
```

Перед сбором покрытия сам проект собирать не нужно (в `sydr-fuzz` проект собирается
автоматически через `dotnet build`), но если требуется собрать его с определенными настройками,
то в директории `build_cov` после сборки проекта должна быть директория `bin/Debug` с файлами .dll,
а сам проект должен быть собран в конфигурации `Debug` (так как сбор покрытия осуществляется через
`dotnet run`, где по умолчанию указана конфигурация `Debug`). Также в директории `build_cov`
не должно быть артефактов и инструментированных файлов после работы `AltCover` и `minicover`.

Для сбора покрытия в форматах `html` или `lcov` нужно запустить сбор покрытия
через `sydr-fuzz`, указав в конфигурационном файле путь для модулей .dll `bin_dir`,
путь до директории `build_dir`, откуда собиралось приложение, путь до инструмента AltCover в
`tool_path` (если этого инструмента нет в $PATH):

    $ sydr-fuzz sharpcov <название_формата>
    или
    $ sydr-fuzz cov-html (для формата html)

Для сбора покрытия в форматах `html`, `clover`, `coveralls`, `xml`, `opencover`, `cobertura`,
`text` нужно запустить сбор покрытия через `sydr-fuzz`, указав в конфигурационном файле
путь для обертки `target`, путь для исходного кода `source`, путь до директории `build_dir`, откуда
собиралось приложение, путь до инструмента minicover в `tool_path` (если этого инструмента нет в $PATH):

    $ sydr-fuzz sharpcov <название_формата>
    или
    $ sydr-fuzz cov-html (для формата html)

Покрытие в формате HTML может быть собрано как с помощью `AltCover`, так и с помощью `minicover`.
Инструмент `AltCover` используется по умолчанию, так как поддерживает возможность сбора покрытия
в параллельном режиме.

## Сбор покрытия (Lua)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого Lua-приложения.
Для этого можно добавить секцию `[cov]` в конфигурационный файл:

```toml
[luzer]
target = "target.lua"

[cov]
target = "target_cov.lua"
```

**target** - путь до инструментируемой для сбора покрытия фаззинг-цели.

Для генерации HTML отчета о покрытии можно воспользоваться следующей командой:

    $ sydr-fuzz -c name.toml cov-html

## Сбор покрытия (Go)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого Go-приложения.
Для этого можно добавить секцию `[cov]` в конфигурационный файл:

```toml
[sydr]
target = "/target_sydr @@"

[libfuzzer]
path = "/target_fuzzer"

[cov]
target = "/target_cov.zip"
```

**target** - путь до инструментированной для сбора покрытия фаззинг-цели. Для
сборки следует использовать команду:

    $ go-fuzz-build -func=FuzzTest -o target_cov.zip

Для генерации HTML отчета о покрытии можно воспользоваться следующей командой:

    $ sydr-fuzz -c name.toml cov-html

## Чтение символьных данных в Sydr из стандартного потока ввода (C/C++/Rust/Go)

Иногда может потребоваться написать обертку для Sydr, которая принимает входные
данные из стандартного потока ввода. Для этого необходимо указать `--sym-stdin`
в аргументах Sydr и не использовать `@@` в командной строке запуска обертки для
Sydr:

```toml
[sydr]
args = "--sym-stdin"
target = "/target_sydr"
```

## Отдельный запуск фаззера (C/C++/Rust/Go)

Sydr-fuzz поддерживает запуск фаззера без Sydr. Для этого необходимо заполнить
только секцию выбранного инструмента (без таблицы `[sydr]`).

## Итеративный анализ Sydr (C/C++/Rust/Go)

Sydr-fuzz поддерживает итеративный запуск Sydr без фаззера. Таким образом, Sydr
будет запускаться на файлах из корпуса и на сгенерированных новых входных данных
от предыдущих запусков Sydr. Для этого необходимо указать корпус в параметре
таблицы `[sydr]` **corpus**:

```toml
[sydr]
args = "-n 2048 -j 4"
target = "/target_sydr @@"
corpus = "/corpus"
jobs = 3
```

Файлы из директории, указанной в таблице `[sydr]` **corpus**, также будут
скопированы в директорию `corpus` внутри проекта.

## Проверка предикатов безопасности (C/C++/Rust/Go)

Sydr-fuzz позволяет запускать предикаты безопасности на корпусе из директории
проекта (`name-out/corpus`).

Перед запуском проверки предикатов безопасности стоит минимизировать корпус (для
AFL++ этот шаг является обязательным):

    $ sydr-fuzz -c name.toml cmin

Для запуска проверки предикатов безопасности можно выполнить следующую команду:

    $ sydr-fuzz -c name.toml security

Sydr-fuzz самостоятельно изменит опции запуска Sydr для проверки предикатов
безопасности.

Результаты запуска будут сохранены в директорию `/fuzz/name-out/security`.
Результаты, верифицированные санитайзерами, будут сохранены в директорию
`/fuzz/name-out/security-verified`. Уникальные верифицированные результаты будут
сохранены в директорию `/fuzz/name-out/security-unique`. Если результат, полученный с помощью
проверки предикатов безопасности, приводит к аварийному завершению программы,
результат будет сохранен в `/fuzz/name-out/crashes`. Логи, которые были проаннотированы во время
верификации, будут сохранены в директорию `/fuzz/name-out/sydr/annotated-logs`.

Для запуска на произвольном входном корпусе можно использовать следующий
конфигурационный файл:

```toml
[sydr]
args = "--security --no-invert"
target = "/target_sydr @@"
corpus = "/corpus"
jobs = 3
```

**corpus** - директория с корпусом.

Файлы из директории, указанной в таблице `[sydr]` **corpus**, также будут
скопированы в директорию `corpus` внутри проекта.

## Анализ аварийных завершений и ошибок неопределенного поведения с помощью Casr

Sydr-fuzz дает возможность осуществлять анализ аварийных завершений после фаззинга:
создание отчетов об аварийных завершениях, их дедупликация и кластеризация, а
также создание отчётов об ошибках неопределенного поведения.
Для этого должна существовать непустая директория `name-out/crashes` с входными данными.
Конфигурационный файл может выглядеть следующим образом (может быть использован
тот же конфиг, на основе которого производился фаззинг, возможно и с `[aflplusplus]`):

```toml
[sydr]
target = "./target_sydr @@"

[libfuzzer]
path = "./target_fuzzer"

[sharpfuzz]
target = "/target_sharpfuzz.dll"
casr_bin = "/casr_target_sharpfuzz.dll"
```

В случае анализа аварийных завершений C#-кода необходимо дополнительно добавить запись
`casr_bin = "/path/to/bin.dll"` в `[sharpfuzz]`, причем указанный .dll модуль не должен
быть проинструментирован инструментом Sharpfuzz.

Для запуска анализа Casr следует выполнить:

    $ sydr-fuzz -c name.toml casr

В результате работы инструмента будет создана директория `name-out/casr`, в которой
по умолчанию будут находится кластеры, содержащие схожие отчеты об авариных завершениях `target_fuzzer`
после срабатывания санитайзера и отчеты об авариных завершениях `target_sydr` (если не указана опция `--no-casr-gdb`).
Также вместе с каждым отчетом будут лежать входные данные, вызвавшие соотвествующее аварийное завершение.
Создание кластеров или запуск `casr-gdb` можно пропустить, задав необходимые опции.

AFL++ не отличает аварийное завершение от out of memory, поэтому приводящие к
oom файлы обнаруживаются с помощью Casr и сохраняются в директорию `casr/oom`.
Файлы, на которых произошел тайм-аут, сохраняются в директорию `casr/timeout`.

Для того чтобы также производился анализ ошибок неопределенного поведения следует выполнить:

    $ sydr-fuzz -c name.toml casr --ubsan

Отчёты будут составлены для всех срабатываний UBSAN на файлах из `name-out/casr`
(т.е. дедуплицированные и кластеризованные аварийные завершения),
`name-out/corpus` и `name-out/security-unique`. Поэтому перед использованием
данной команды рекомендуется провести минимизацию корпуса, т.е. запустить
`cmin`, а также `security` для получения отчётов для срабатываний предикатов
безопасности. При этом отчёты будут дедуплицироваться по строчке аварийного
завершения, т.е. в случае когда несколько ошибок произошло в одной и той же
строке, отчёт будет составлен только для первой из них со следующим приоритетом
(в порядке убывания): `name-out/security-unique`, `name-out/casr`,
`name-out/corpus`. Все ошибки неопределенного поведения имеют класс критичности
**NOT_EXPLIOTABLE**

Для удобного просмотра отчетов можно воспользоваться специальным инструментом `casr-cli`:

    $ casr-cli name-out/casr/cl1/crash-deadbeef.casrep

Можно выбрать другой вид отчета с помощью аргумента **--view**:

    $ casr-cli --view slider name-out/casr/cl1/crash-deadbeef.casrep

Вывод отчета в stdout:

    $ casr-cli --view stdout name-out/casr/cl1/crash-deadbeef.casrep

Также инструментом можно воспользоваться для просмотра общей статистики Casr директории,
содержащей отчеты или кластеры:

    $ casr-cli name-out/casr

## DefectDojo

Sydr-fuzz дает возможность выгружать уникальные CASR отчеты в систему DefectDojo.
[DefectDojo](https://github.com/DefectDojo/django-DefectDojo)
— это платформа для организации безопасности и управления уязвимостями.
Уникальность отчетов (за исключением UBSAN) определяется на основе стеков вызовов
в соответствии с алгоритмом дедупликации, представленным в CASR.
Дедупликация UBSAN отчетов производится по строчке исходного кода, в которой
произошло аварийное завершение (путь до файла с исходным кодом + номер строки).
Анализ выполняется в соответствии со следующими этапами:

1. Указываются необходимые [API параметры](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/)
   DefectDojo (url, токен и имя продукта).
2. Для данного продукта будут получены все уже имеющие в
   системе аварийные завершения, будет произведена дедупликация новых аварийных
   завершений (из директории `out/casr`) и только уникальные
   (с точки зрения наших алгоритмов) будут загружены в систему.
3. Каждый загружаемый элемент будет иметь описание с полями из CASR отчета
   такими как строчка исходного кода, в которой произошло аварийное завершение,
   критичность, описание ошибки, стек вызовов и проч. Также вместе с каждым CASR
   отчетом в DefectDojo будет загружен отчет GDB CASR (если он есть) и файл
   с входными данными, которые привели к рассматриваемому аварийному завершению.

Подробные инструкции по установке DefectDojo могут быть найдены
[тут](https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/DOCKER.md).
Для начала работы можно выполнить следующие команды:

    # git clone https://github.com/DefectDojo/django-DefectDojo.git
    # cd django-DefectDojo
    # ./dc-build.sh
    # ./dc-up.sh
    # # Wait for complete initialization: django-defectdojo_initializer_1 exited with code 0
    # # Get password for user "admin":
    # docker-compose logs initializer | grep "Admin password:"

Пример запуска `sydr-fuzz casr` с экспортом аварийных завершений в DefectDojo:

    # sydr-fuzz casr --url http://localhost:8080 --token 382f5dfdf2a339f7c3bb35442f9deb9b788a98d5 --product xlnt

## Классы критичности

В этой секции описаны классы критичности аварийных завершений. Классы аварийных завершений собраны в три группы: *критичные, потенциально критичные, отказ в обслуживании*. Некоторые прототипы классов взяты из библиотеки с открытым исходный кодом [gdb-exploitable](https://github.com/jfoote/exploitable.git).

**Критичные (EXPLOITABLE)**

Критичные аварийные завершения являются самыми опасными, исправлять такие аварийные завершения рекомендуется в первую очередь. Такие аварийные завершения могут легко привести к перехвату потока управления.

Список классов:

1. **SegFaultOnPc**. Попытка выполнить инструкцию по адресу, который не доступен для выполнения. Это может указывать на то, что атакующий уже контролирует счётчик команд.
2. **ReturnAv**. Аварийное завершение при выполнении инструкции возврата. Указывает на то, что произошла перезапись адреса возврата на стеке.
3. **BranchAv**. Аварийное завершение при выполнении инструкции ветвления. Указывает на то, что атакующий контролирует целевой адрес перехода.
4. **CallAv**. Аварийное завершение при выполнении инструкции вызова. Указывает на то, что атакующий контролирует целевой адрес вызова.
5. **DestAv**. Аварийное завершение при попытке записи в память машинного слова. Указывает на то, что вероятно атакующий контролирует адрес записи в память и потенциально записываемое значение (CWE-123).
6. **heap-buffer-overflow(write)**. Аварийное завершение при попытке записи за границами выделенного на куче буфера.
7. **global-buffer-overflow(write)**. Аварийное завершение при попытке записи за границами глобального буфера.
8. **stack-use-after-scope(write)**. Аварийное завершение при при записи по адресу стека за пределами лексической области времени существования переменной.
9. **stack-use-after-return(write)**. Аварийное завершение при записи в объект стека после возврата функции, в которой этот объект был определен.
10. **stack-buffer-overflow(write)**. Аварийное завершение при попытке записи за верхней границей выделенного на стеке буфера.
11. **stack-buffer-underflow(write)**. Аварийное завершение при попытке записи за нижней границей выделенного на стеке буфера.
12. **heap-use-after-free(write)**. Аварийное завершение при попытке записи в освобожденную память.
13. **container-overflow(write)**. Аварийное завершение при попытке записи в память внутри выделенного региона, но за текущими границами контейнера.
14. **param-overlap**. Вызов функции, запрещающей перекрывающиеся диапазоны памяти.

**Потенциально критичные (PROBABLY_EXPLOITABLE)**

Потенциально критичные аварийные классы требуют некоторого дополнительного (часто ручного) анализа, чтобы определить критичные они или нет.

Список классов:

1. **SourceAv**. Аварийное завершение при попытке чтения из памяти машинного слова.
2. **BadInstruction**. Невозомжно декодировать команду или выполнить привилегированную инструкцию. Это может указывать на то, что нарушитель перехватил управление, или же такую ситуацию создают искуственно программисты (аналог вызов функции `abort()`).
3. **SegFaultOnPcNearNull**. Попытка выполнить инструкцию по адресу, который не доступен для выполнения. Это может указывать на то, что атакующий уже контролирует счётчик команд, или же это происходит разыменование нулевого указателя.
4. **BranchAvNull**. Аварийное завершение при выполнении инструкции ветвления. Указывает на то, что атакующий контролирует целевой адрес перехода, или же это просто разыменование нулевого указателя.
5. **CallAvNearNull**. Аварийное завершение при выполнении инструкции вызова. Указывает на то, что атакующий контролирует целевой адрес вызова, или же это просто разыменование нулевого указателя.
6. **HeapError**. Аварийное завершение, порождённое вызывом функции `abort()` из кода менедежера динамической памяти. Частой причиной является переполнение буфера.
7. **StackGuard**. Произошла перезапись "канарейки" на стеке.
8. **DestAvNearNull**. Аварийное завершение при попытке записи в память машинного слова. Указывает на то, что вероятно атакующий контролирует адрес записи, или же это просто разыменование нулевого указателя.
9. **heap-buffer-overflow**. Аварийное завершение при попытке чтения или записи за границами выделенного на куче буфера.
10. **global-buffer-overflow**. Аварийное завершение при попытке чтения или записи за границами глобального буфера.
11. **stack-use-after-scope**. Аварийное завершение при использовании адреса стека за пределами лексической области времени существования переменной.
12. **use-after-poison**. Аварийное завершение при попытке использования памяти, которая была помечена с помощью специальных функций, как недоступная (poisoned memory).
13. **stack-use-after-return**. Аварийное завершение при попытке использования объекта стека после возврата функции, в которой этот объект был определен.
14. **stack-buffer-overflow**. Аварийное завершение при попытке чтения или записи за верхней границей выделенного на стеке буфера.
15. **stack-buffer-underflow**. Аварийное завершение при попытке чтения или записи за нижней границей выделенного на стеке буфера.
16. **heap-use-after-free**. Аварийное завершение при попытке использования освобожденной памяти.
17. **container-overflow**. Аварийное завершение при попытке использования памяти внутри выделенного региона, но за текущими границами контейнера.
18. **negaotive-size-param**. Использование отрицательного значения размера при доступе в память.
19. **calloc-overflow**. Переполение параметров функции `calloc`.
20. **readllocarray-overflow**. Переполение параметров функции `recalloc`.
21. **pvalloc-overflow**. Переполение параметров функции `pvalloc`.
22. **overwrites-const-input**. Аварийное завершение при попытке перезаписи неизменяемых входных данных.

**Отказ в обслуживании (NOT_EXPLOITABLE)**

Для классов отказов в обслуживании требуется дополнительный ручной анализ, для того чтобы установить, является ли аврийное завершение критичным или нет.
Также в эту группу входят аварийные завершения, которые с большой вероятностью не являются критичными с точки зрения перехвата потока управления.

Список классов:

1. **AbortSignal**. Программа получила сигнал SIGABRT. SIGABRTы часто генерируются библиотекой libc и встроенными защитами от переполнения буфера и т.д.
2. **AccessViolation**. Аварийное завершение при доступе к памяти. Требуется дополнительный анализ от разработчика для уточнения степени критичности.
3. **SourceAvNearNull**. Аварийное завершение при попытке чтения из памяти машинного слова, или же это просто разыменование нулевого указателя.
4. **SafeFunctionCheck**. Получение сигнала SIGABRT из-за срабатывания защиты внутри безопасной функции: `_chk()`.
5. **FPE**. Аварийное завершение при обработке арифметической инструкции с плавающей точкой.
6. **StackOverflow**. Аварийное завершение при попытке доступа в память. Последняя инструкция и указатель стека сигнализируют о возможной ошибке переполнения стека.
7. **double-free**. Аварийное завершение при попытке освободить уже освобожденную память.
8. **bad-free**. Аварийное завершение при попытке освободить невыделенную память.
9. **alloc-dealloc-mismatch**. Несоответствие API выеделения и освобождения.
10. **heap-buffer-overflow(read)**. Аварийное завершение при попытке чтения за границами выделенного на куче буфера.
11. **global-buffer-overflow(read)**. Аварийное завершение при попытке чтения за границами глобального буфера.
12. **stack-use-after-scope(read)**. Аварийное завершение при чтении с адреса стека за пределами лексической области времени существования переменной.
13. **stack-use-after-return(read)**. Аварийное завершение при попытке чтения объекта стека после возврата функции, в которой этот объект был определен.
14. **stack-buffer-overflow(read)**. Аварийное завершение при попытке чтения за верхней границей выделенного на стеке буфера.
15. **stack-buffer-underflow(read)**. Аварийное завершение при попытке чтения за нижней границей выделенного на стеке буфера.
16. **heap-use-after-free(read)**. Аварийное завершение при попытке чтения из освобожденной памяти.
17. **container-overflow(read)**. Аварийное завершение при попытке чтения из памяти внутри выделенного региона, но за текущими границами контейнера.
18. **initialization-order-fiasco**. Инициализатор для глобальной переменной обращается к динамически инициализируемой глобальной переменной из другой единицы трансляции, которая еще не инициализирована.
19. **new-delete-type-mismatch**. Размер выделенной памяти отличаестя от размера освобождаемой.
20. **bad-malloc_usable_size**. Неверный аргумент для функции `bad-malloc_usable_size`.
21. **odr-violation**. Определение одного и того же символа в различных модулях.
22. **memory-leaks**. Возникновение утечек памяти вследствие недостаточного отслеживания и освобождения выделенной памяти после ее использования.
23. **invalid-allocation-alignment**. Неверное выравнивание при выделении памяти.
24. **invalid-aligned-alloc-alignment**. Неверное выравнивание при вызове `aligned_alloc`.
25. **invalid-posix-memalign-alignment**. Неверное выравнивание при вызове `posix_memalign`.
26. **allocation-size-too-big**. Запрашиваемый размер памяти превышает максимально поддерживаемый.
27. **out-of-memory**. Аварийное завершение при превышении лимита памяти.
28. **fuzz target exited**. Завершение работы целевой программы.
29. **timeout**. Аварийное завершение при превышении лимита времени выполнения.
