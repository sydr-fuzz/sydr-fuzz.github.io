# Sydr-fuzz

[Sydr-fuzz](https://sydr-fuzz.github.io) - это инструмент динамического анализа для безопасного
цикла разработки ПО. Sydr-fuzz сочетает в себе мощь инструмента динамического
символьного выполнения Sydr и современных фаззеров. Sydr позволяет увеличивать
покрытие кода и обнаруживать ошибки. На данный момент sydr-fuzz позволяет
запускать Sydr вместе с [libFuzzer](https://www.llvm.org/docs/LibFuzzer.html) и
[AFL++](https://aflplus.plus/), а также поддерживает фаззинг Python/CPython с
помощью [Atheris](https://github.com/google/atheris). Примеры уже настроенных
фаззинг целей для sydr-fuzz можно найти в репозитории
[OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz). По сути sydr-fuzz
реализует пайплайн фаззинга:

- Гибридный фаззинг с помощью Sydr и одного из фаззеров (libFuzzer, AFL++) или
  фаззинг Python (Atheris):
  `sydr-fuzz run`
- Минимизация корпуса: `sydr-fuzz cmin` (шаг обязателен для AFL++)
- Поиск ошибок (выхода за границы буфера, целочисленного переполнения, деления
  на нуль и др.) символьными предикатами безопасности Sydr: `sydr-fuzz security`
- Сбор покрытия: `sydr-fuzz cov-report`
- Сбор покрытия для Python-кода: `sydr-fuzz pycov html`
- Дедупликация, кластеризация и оценка критичности аварийных завершений с
  использованием Casr: `sydr-fuzz casr`

Гайды, публикации, презентации, трофеи, бенчмарки и другую полезную информацию
можно найти на [сайте](https://sydr-fuzz.github.io).

# Трофеи

Список трофеев можно найти в репозитории
[OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz/blob/master/TROPHIES.md).

# Минимальные системные требования

- Операционная система: Ubuntu 18.04/20.04, Astra 1.7, ALT Workstation 10.0 и
  аналоги - 64-bit.
- Процессор (CPU): Intel Core i3 или аналогичный AMD.
- Оперативная память (RAM): 4 ГБ.

DynamoRIO имеет известную
[проблему](https://github.com/DynamoRIO/dynamorio/issues/5437) запуска 32-битных
программ с glibc версии 2.34+. Поэтому Sydr не сможет проанализировать 32-битные
программы на Ubuntu 22.04. Для решения данной проблемы можно запускать Sydr
внутри Docker. Анализ 64-битных программ на Ubuntu 22.04 работает без ошибок.

# Рекомендуемые системные требования

- Операционная система: Ubuntu 18.04/20.04 - 64-bit.
- Процессор (CPU): Intel Core i7 (Desktop) или аналогичный AMD.
- Оперативная память (RAM): 32 ГБ и больше.

# Зависимости

Перед установкой инструмента установите следующие зависимости.

    $ sudo apt install gcc-multilib binutils lsb-release gdb python3 python3-pip \
                       liblapack-dev gfortran
    $ sudo -H python3 -m pip install numpy scipy

Для корректной работы лицензионного USB ключа требуется установить последнюю
версию
[Sentinel HASP/LDK Run-time Environment](https://supportportal.thalesgroup.com/csm?sys_kb_id=29364265db9ea78cfe0aff3dbf96192c&id=kb_article_view&sysparm_rank=6&sysparm_tsqueryId=4cd5f5484722cd10128dca72e36d43e7&sysparm_article=KB0018315)
(перед установкой желательно вынуть USB ключ, и вставить его назад по завершению
установки):

    $ tar xf aksusbd*.tar.gz
    $ rm aksusbd*.tar.gz
    $ cd aksusbd*
    $ sudo ./dinst

Для работы лицензионного ключа на Astra Linux требуется разрешить трассировку
ptrace: Пуск -> Панель управления -> Безопасность -> Политика безопасности ->
Настройка безопасности -> Системные параметры -> Снять галочку с "Блокировать
трассировку ptrace для всех пользователей".

# Установка

Для установки достаточно распаковать zip-архив.

    $ unzip sydr.zip

# Использование sydr-fuzz

Рекомендуется воспользоваться нашим докером `sydr/ubuntu20.04-sydr-fuzz`
(который можно найти в

`docker/ubuntu20.04-sydr-fuzz/Dockerfile`) и запускать
гибридный фаззинг внутри него. Дальнейшая документация основывается на
использовании нашего докера. Далее перечислены зависимости, которые нужно
установить, если запуск производится на другой системе.

## Зависимости libFuzzer

Sydr-fuzz можно запускать просто на системе (требуется LLVM 13+). Однако
настоятельно рекомендуем установить
[Docker](https://docs.docker.com/engine/install/) для сборки и запуска фаззинга
целей в изолированном окружении.

Для корректного ранжирования входных данных, подающихся от libFuzzer к Sydr,
требуется сборка LLVM, содержащая добавленный нами
[коммит](https://github.com/llvm/llvm-project/commit/827ccc93b8f378c36a356a3025db65bbd1f031e8#diff-0bc43509353a4f382ac6e3d2847f195de7a51d44c74a7baa4f0f33da17451cc6).
Данные изменения добавляют печать входных данных от Sydr, которые увеличивают
покрытие кода с точки зрения фаззера. Эта функциональность присутствует с релиза
[LLVM 13.0.0](https://github.com/llvm/llvm-project/releases/tag/llvmorg-13.0.0).
Более ранние версии LLVM также поддерживаются, но ранжирование не будет
эффективным.

## Зависимости AFL++

Фаззер AFL++ и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется
скачать и установить AFL++ (можно из [репозитория](https://github.com/AFLplusplus/AFLplusplus)).
AFL++ активно разрабатывается, поэтому желательно использовать наиболее новую версию.
Для запуска Sydr-fuzz с AFL++ также необходимы утилиты минимизации корпуса `afl-cmin`
и построения битовой карты `afl-showmap`. Вместе с фаззером afl-fuzz они должны находиться
в одной директории, путь до которой либо есть в `$PATH`, либо указан в конфигурационном файле.

## Зависимости Atheris

Библиотека фаззинга Atheris и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
и установить Atheris (можно из [репозитория](https://github.com/google/atheris)).
Для работы sydr-fuzz с Atheris также необходима библиотека сбора покрытия
[Coverage](https://coverage.readthedocs.io/en/latest/install.html).

## Опции

Доступные опции:

    $ sydr-fuzz -h
    ISP RAS
    Continuous hybrid fuzzing and dynamic analysis for security development lifecycle

    USAGE:
        sydr-fuzz [OPTIONS] <SUBCOMMAND>

    OPTIONS:
        -c, --config <FILE>        Configuration file [default: sydr-fuzz.toml]
        -h, --help                 Print help information
        -l, --log-level <LEVEL>    Logging level [default: info] [possible values: minimal,
                                   info, debug, trace]
        -o, --output <OUT_DIR>     Output project directory with artifacts [default:
                                   <CONFIG>-out]
        -V, --version              Print version information

    SUBCOMMANDS:
        casr          Triage, deduplicate, cluster crashes and create reports
        cmin          Minimize corpus
        cov-export    Collect and export corpus coverage in JSON or lcov trace file format
        cov-report    Collect corpus coverage and display summary
        cov-show      Collect and show line by line corpus coverage
        help          Print this message or the help of the given subcommand(s)
        pycov         Collect and export corpus coverage in specified format for Python
                      targets
        run           Run hybrid fuzzing with Sydr and libFuzzer/AFL++ or Python fuzzing
                      with Atheris
        security      Check security predicates (out of bounds, integer overflow, division
                      by zero, etc.) for corpus seeds

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

### Опции запуска фаззинга

    $ sydr-fuzz run -h
    sydr-fuzz-run
    Run hybrid fuzzing with Sydr and libFuzzer/AFL++ or Python fuzzing with Atheris

    USAGE:
        sydr-fuzz run [OPTIONS]

    OPTIONS:
        -f, --force-remove           Remove output project directory if it exists
        -h, --help                   Print help information
            --runs <N>               Stop sydr-fuzz after N Sydr runs
        -s, --strategy <STRATEGY>    Strategy for scheduling Sydr input seeds [default:
                                     coverage] [possible values: coverage, random, file-info]
            --use-sydr-inputs        Use files generated by Sydr as new inputs for Sydr
                                     (relevant only for libFuzzer random and file-info
                                     strategies)

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

### Опции сбора покрытия (C/C++/Rust)

**sydr-fuzz cov-export** собирает покрытие и экспортирует его в JSON или lcov
формат

**sydr-fuzz cov-report** собирает покрытие и выводит краткий отчет о покрытии в
процентах

**sydr-fuzz cov-show** собирает и выводит покрытие по строкам

Все три команды имеют одинаковый интерфейс задания дополнительных аргументов
после `--`:

    $ sydr-fuzz cov-report -h
    sydr-fuzz-cov-report
    Collect corpus coverage and display summary

    USAGE:
        sydr-fuzz cov-report [OPTIONS] [-- <ARGS>...]

    ARGS:
        <ARGS>...    llvm-cov report extra options after --

    OPTIONS:
        -h, --help        Print help information
        -j, --jobs <N>    Number of parallel jobs to collect and merge raw coverage [default:
                          half of cpu cores]

Опция **-j, \--jobs \<N\>** позволяет задать количество потоков для сбора данных покрытия.
По умолчанию данное значение равно половине ядер процессора.

**cov-COMMAND** заимствованы от команд
[llvm-cov](https://llvm.org/docs/CommandGuide/llvm-cov.html). Дополнительные
аргументы **ARGS**, которые можно перечислить после `--`, представляют собой
соответствующие опции и аргументы для команд llvm-cov за тем исключением, что
целевой бинарный файл и опция **-instr-profile** заранее заданы. Например:

    $ sydr-fuzz cov-report -j 4 -- -use-color=true

### Опции сбора покрытия (Python)

    Collect and export corpus coverage in specified format for Python targets

    USAGE:
        sydr-fuzz pycov <FORMAT> [-- <ARGS>...]

    ARGS:
        <FORMAT>     Coverage format (report, html, xml, json, lcov, etc.)
        <ARGS>...    coverage FORMAT extra options after --

    OPTIONS:
        -h, --help    Print help information

Дополнительные аргументы **<ARGS>**, которые можно перечислить после `--`,
представляют собой соответствующие опции и аргументы
[Coverage](https://coverage.readthedocs.io/en/latest/cmd.html).

### Опции проверки предикатов безопасности (C/C++/Rust/Go)

    $ sydr-fuzz security -h
    sydr-fuzz-security
    Check security predicates (out of bounds, integer overflow, division by zero, etc.) for
    corpus seeds

    USAGE:
        sydr-fuzz security [OPTIONS]

    OPTIONS:
        -f, --force-remove         Remove output project directory if it exists
        -h, --help                 Print help information
        -j, --jobs <N>             Number of Sydr jobs
            --runs <N>             Check security predicates for N seeds from corpus
        -t, --timeout <SECONDS>    Timeout (in seconds) for target execution [default: 30]

Опция **-f, \--force-remove** перезаписывает всю выходную директорию с проектом.

Опция **-j, \--jobs \<N\>** позволяет изменить количество запускаемых Sydr.

Опция **\--runs \<N\>** задает число файлов из корпуса, на которых будет
запущена проверка предикатов безопасности. После заданного числа запусков
sydr-fuzz прекратит работу.

Опция **-t, \--timeout \<SECONDS\>** устанавливает время выполнения фаззинг цели в секундах, которое
будет считаться тайм-аутом (по умолчанию 30 секунд).

### Опции запуска анализа аварийных завершений с помощью Casr

    $ sydr-fuzz casr
    sydr-fuzz-casr
    Triage, deduplicate, cluster crashes and create reports

    USAGE:
        sydr-fuzz casr [OPTIONS]

    OPTIONS:
        -h, --help                 Print help information
            --ignore <FILE>        File with regular expressions for functions and file paths
                                   to filter in call stacks
        -j, --jobs <N>             Number of parallel jobs for crash triaging [default: half
                                   of cpu cores]
            --no-casr-gdb          Do not collect crash reports via casr-gdb
            --no-cluster           Do not cluster reports
        -p                         Use PATH environment variable to find casr tools
            --san-force            Force casr-san run without sanitizers symbols check
        -t, --timeout <SECONDS>    Timeout (in seconds) for target execution [default: 30]

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
цели под casr-san/casr-gdb (по умолчанию 30 секунд).

## Создание фаззинг целей

Для осуществления гибридного фаззинга требуется подготовить отдельные обертки
для Sydr и фаззера. Все цели рекомендуется собирать с отладочной информацией
(`-g`), чтобы потом проще было анализировать аварийные завершения и срабатывания
предикатов безопасности.

Фаззинг необходимо проводить в том же окружении (Docker), в котором
производилась сборка фаззинг целей. В противном случае возможны проблемы с
символами в выводе санитайзеров и поиском файлов с исходным кодом.

### Обертка Sydr

Обертка для Sydr представляет собой небольшую программу, которая читает входные данные (файл
либо стандартный поток ввода) и передает их в функцию, являющуюся целью фаззинга. Данную
обертку требуется собирать без каких либо санитайзеров (но оставить `-g`). Рекомендуется
запустить обертку под Sydr на каком-нибудь файле из очереди и убедиться, что Sydr генерирует
новые входные данные. Таким образом, можно проверить, что обертка написана верно.
Чтение входных данных в обертке должно происходить непосредственно перед их использованием.
Все остальные вычисления (инициализация глобального контекста и т.д.), которые не зависят от
входных данных, должны быть расположены до их чтения. В противном случае скорость интерпретации
программы может замедляться в разы.

### Обертка libFuzzer

Для подготовки libFuzzer обертки можно воспользоваться его
[документацией](https://www.llvm.org/docs/LibFuzzer.html). По сути требуется
реализовать функцию `LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)`,
которая принимает на вход мутированный буфер и передает его в функцию,
являющуюся целью фаззинга. Проект [OSS-Fuzz](https://github.com/google/oss-fuzz)
уже содержит libFuzzer обертки для большого числа проектов с открытым исходным
кодом. Обертку для фаззера следует собирать с санитайзерами и libFuzzer (который
тоже является санитайзером):

`-g -fsanitize=fuzzer,address,integer,bounds,null,undefined,float-divide-by-zero`

Важно не забыть собрать не только код обертки с санитайзерами, но и целевую
библиотеку, которую он использует. Для сборки библиотеки флаг `-fsanitize=fuzzer`
нужно заменить на `-fsanitize=fuzzer-no-link`. Если обертка требует инициализации
глобального контекста, то требуется добавить вызов `LLVMFuzzerInitialize`.

Для облегчения работы, libFuzzer обертка может быть использована для создания
обертки Sydr. Достаточно добавить функцию `main`, которая читает входные данные
и передает их в `LLVMFuzzerInitialize` в виде буфера. Для этого можно слинковать
обертку libFuzzer с `main` следующего содержания:

```cpp
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main(int argc, char** argv)
{
    // LLVMFuzzerInitialize(&argc, &argv);

    FILE* fd = fopen(argv[1], "rb");
    if (!fd) return 1;
    fseek(fd, 0, SEEK_END);
    long fsize = ftell(fd);
    fseek(fd, 0, SEEK_SET);

    char* buffer = (char*)malloc(fsize);
    fread(buffer, 1, fsize, fd);
    fclose(fd);

    return LLVMFuzzerTestOneInput((const uint8_t*)buffer, fsize);
}
```

Примеры кода `main` находятся
[здесь](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/standalone/StandaloneFuzzTargetMain.c)
и
[здесь](https://github.com/vanhauser-thc/qemu_driver/blob/master/qemu_driver.c).
Докер `sydr/ubuntu20.04-sydr-fuzz` уже содержит исходный код `main` в
файлах `/opt/StandaloneFuzzTargetMain.c` или `/opt/qemu_driver.c`. С их помощью
можно получить обертку для Sydr, например:

    $ clang -g fuzz_target.c /opt/StandaloneFuzzTargetMain.c -o sydr_target

Таким же образом, из libFuzzer обертки можно получить обертки для AFL++.

### Обертка AFL++

Для AFL++ написание отдельной обертки не требуется, можно полностью использовать
код обертки Sydr или libFuzzer. Отличие заключается только в сборке с другой инструментацией.

Стоит отметить, что существует возможность вообще не производить никаких
дополнительных действий и просто взять собранную под Sydr обертку. В аргументах
AFL++ в таком случае необходимо указать использование бинарной инструментации
(`-Q` для режима QEMU и `-O` для FRIDA). Фаззинг с бинарной инструментацией
выполняется медленно и неэффективно, а отсутствие санитайзеров в сборке сводит
вероятность нахождения ошибок к минимуму. Настоятельно не рекомендутся использовать
этот вариант. Подробнее о фаззинге бинарных целей можно почитать
[здесь](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_binary-only_targets.md).

Чтобы собрать обертку с инструментацией фаззера, при сборке цели нужно
использовать компиляторы, поставляемые вместе с AFL++: `afl-clang`/`afl-clang++`,
`afl-clang-fast`/`afl-clang-fast++`, `afl-gcc`/`afl-g++`. Также при сборке нужно указать
санитайзеры и опцию для дебаг-информации:

`-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero`

Поробнее об инструментации фаззинг целей AFL++ написано
[здесь](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#1-instrumenting-the-target).

Также можно использовать компиляторы `afl-clang-lto`/`afl-clang-lto++`. При
использовании этих компиляторов битовая карта, используемая при гибридном
фаззинге с AFL++, будет содержать меньше коллизий.

Подробнее об LTO mode можно прочитать [здесь](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md).

Рекомендуется собирать обертку для работы AFL++ в Persistent mode. В этом режиме
AFL++ будет фаззить цель много раз в одном процессе, вместо того чтобы создавать
каждый раз процесс заново, что ускоряет фаззинг в несколько раз.

Для сборки оберток AFL++ в Persistent mode можно воспользоваться оберткой
для libFuzzer. Для этого стоит собирать библиотеку и обертку вышеупомянутыми
компиляторами, при этом помимо санитайзеров указав `-fsanitize=fuzzer` во
флагах компиляции. В таком случае компиляторы от AFL++ самостоятельно создадут
функцию `main` с инструментацией для Persistent mode, вызвав оттуда
LLVMFuzzerTestOneInput из обертки для libFuzzer. При использовании флага
`-fsanitize=fuzzer` стоит использовать `@@` в поле `target` в таблице
`aflplusplus` в конфигурационном файле.

Также можно собрать обертки AFL++ без `-fsanitize=fuzzer`, написав `main`
самостоятельно. Для этого нужно слинковать обертку для libFuzzer с `main` следующего содержания:

```cpp
#include <stdint.h>
#include <unistd.h>
#include <string.h>

__AFL_FUZZ_INIT();

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
// extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);

int
main(int argc, char **argv)
{

    // LLVMFuzzerInitialize(&argc, &argv);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    uint8_t *data = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(1000))
    {
        size_t size = __AFL_FUZZ_TESTCASE_LEN;

        LLVMFuzzerTestOneInput(data, size);
    }

    return 0;
}
```

При использовании такой функции `main` `@@` в конфигурационном файле
использовать не надо, т.к. данные будут читаться из стандартного потока ввода.

Подробнее о Persistent mode можно почитать [здесь](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md).

**Фаззинг аргументов командной строки**

Гибридный фаззинг с AFL++ позволяет фаззить аргументы командной строки. Для
компиляции оберток для фаззинга аргументов командной строки необходимо
воспользоваться заголовочным файлом
[argv-fuzz-inl.h](https://github.com/AFLplusplus/AFLplusplus/blob/stable/utils/argv_fuzzing/argv-fuzz-inl.h).
Нужно добавить `#include "/path/to/argv-fuzz-inl.h"` в обертки для Sydr и AFL++.
Затем вызвать или макрос `AFL_INIT_ARGV();`, или макрос
`AFL_INIT_SET0("prog_name");` в самом начале функции `main`. Тогда данные со
стандартного потока ввода будут преобразованы в `argc` и `argv` соответственно.

В случае использования `AFL_INIT_SET0` `argv[0]` всегда будет равен переданной в макрос
строке.

Для фаззинга аргументов командной строки необходимо подавать на стандартный
поток ввода данные, разделенные нуль-терминатором. Например, данные `AAAA\0BBBB\0CCCC\0`
будут преобразованы в `argv[0] = "AAAA\0"`, `argv[1] = "BBBB\0"`, `argv[2] = "CCCC\0"`.

При фаззинге аргументов командной строки цели Sydr и AFL++ принимают входные
данные со стандартного потока ввода, поэтому в аргументах Sydr стоит указать
аргумент `--sym-stdin`; `@@` для AFL++ указывать не надо.

Пример конфигурации:

```toml
[sydr]
args = "--sym-stdin"
target = "/target_sydr"

[aflplusplus]
args = "-i /corpus -t 2000"
target = "/target_afl"
```

Стоит отметить, что использование [Persistent mode](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md)
и фаззинга аргументов командной строки несовместимо.

### Обертка Atheris

Для подготовки Atheris обертки можно воспользоваться его
[документацией](https://github.com/google/atheris/blob/master/README.md). По
сути, требуется реализовать функцию `TestOneInput(data)`, которая принимает на
вход мутированный буфер и передает его в функцию, являющуюся целью фаззинга.
Проект [OSS-Fuzz](https://github.com/google/oss-fuzz) уже содержит Atheris
обертки для большого числа проектов с открытым исходным кодом.

Также в начале обертки требуется использовать инструментацию целевой
библиотеки с помощью функции `atheris.instrument_imports()` (рекомендуется
инструментировать все используемые библиотеки).

Для корректной работы обертки требуется выдать ей права на выполнение с помощью
утилиты `chmod +x` и указать путь до интрепретатора Python в начале обертки,
используя `#!`, например `#!/usr/bin/env python3`.

Если целевая библиотека содержит расширения на языках C/C++, рекомендуется
инструментация исходных файлов при сборкe библиотеки. Для этого требуется
использовать флаг `-fsanitize=address,fuzzer-no-link` при сборке. Более подробно
об этом можно прочитать в
[документации](https://github.com/google/atheris/blob/master/native_extension_fuzzing.md)
Atheris.

```py
#!/usr/bin/env python3

import atheris

with atheris.instrument_imports():
    from ruamel import yaml as ryaml
    import sys

@atheris.instrument_func
def TestOneInput(data):
    ryaml.load_all(data)

if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
```

## Подготовка докера для гибридного фаззинга

Докер файл отвечает за установку зависимостей для сборки цели, сборку целей под
фаззер и Sydr, создание начального корпуса для фаззинга и т.д.
В начальный корпус рекомендуется добавлять файлы размером меньше 1 Мб. В
противном случае фаззинг будет неэффективным, а Sydr будет использовать большой
объем оперативной памяти.
Ниже приводится пример возможного Dockerfile с комментариями:

```docker
# Подготовленный нами докер с собранным LLVM
FROM sydr/ubuntu20.04-sydr-fuzz

# Автор
MAINTAINER John Doe

# Установка зависимостей для сборки
RUN apt-get update && apt-get install -y libssl-dev

# Клонирование целевого репозитория
RUN git clone https://github.com/target/project

# Сборка фаззинг целей
## Копирование оберток для libFuzzer/AFL++, Sydr и скрипта сборки
COPY target_fuzzer.c target_sydr.c build.sh /
## Сборка целей для libFuzzer/AFL++ и Sydr
RUN ./build.sh

# Создание начального корпуса
RUN mkdir corpus && find /project -name "*.json" -exec cp {} /corpus \;
```

Сборка докера:

    $ sudo docker build -t sydr-fuzz-target .

## Конфигурационный файл и структура выходного проекта

Конфигурационный файл (`sydr-fuzz.toml`) используется для задания опций
фаззера и Sydr. Все пути задаются либо абсолютно, либо относительно
директории, в которой расположен конфигурационный файл. Для настройки запуска
различных инструментов в этом файле указываются таблицы `[sydr]`, `[libfuzzer]`,
`[aflplusplus]` (или список таблиц `[[aflplusplus]]`), `[atheris]` и `[cov]`. Конфигурационный файл не может
одновременно содержать таблицы `[libfuzzer]` и `[aflplusplus]`, а также
`[atheris]` с какой-либо другой таблицей (на примере ниже приведены все таблицы
для краткости).

```toml
exit-on-time = 7200

[sydr]
args = "-j 4"
target = "/target_sydr @@"
jobs = 3

[libfuzzer]
path = "/target_fuzzer"
args = "-dict=/json.dict -jobs=6 /corpus"

[atheris]
path = "/target.py"
args = "/corpus -jobs=4 -workers=4"

[aflplusplus]
args = "-t 5000 -i /corpus"
target = "/target_afl @@"
jobs = 6

[cov]
target = "/instrumented_target @@"
```

**exit-on-time** - опциональный параметр указывает время в секундах. Если в
течение этого времени покрытие не растет, фаззинг автоматически завершается.

**out** - опциональный параметр указывает путь до выходной директории с
проектом, где содержатся артефакты и результаты работы фаззинга. Если не
указывать эту опцию, то проект создастся в текущей директории с именем
`<CONFIG>-out`. Данный параметр дублирует аргумент командной строки `--output`,
который считается более приоритетным, чем значение из конфигурационного файла.

### Sydr

```toml
[sydr]
args = "-j 4"
target = "/target_sydr @@"
jobs = 3
timeout = 1000
cache = true
optimistic = true
fuzzmem = false
wait_jobs = false
solving_limit = false
symaddr = 20
[sydr.env]
    CLASSIC_ENVVAR = "XXX"
```

Таблица `[sydr]` может содержать следующие параметры:

**args** - аргументы Sydr. Опции `--sym-file` и `--log-file` задаются
автоматически, их указывать не надо.

**target** - строка запуска обертки для Sydr. Вместо имени символьного входного
файла следует использовать `@@`.

**jobs** - число процессов Sydr для запуска (по умолчанию 1). Всего запускается
**jobs** процессов Sydr в `-j` (задается в **args**) потоков каждый.

**timeout** - тайм-аут в секундах, по истечении которого процесс Sydr будет
остановлен. Если параметр не указан, выставляется 20 минут (1200 секунд).

**cache** - булевый параметр (по умолчанию включен), который включает кэш
инвертированных переходов.

**optimistic** - булевый параметр (по умолчанию включен), который включает
оптимистичные решения.

**fuzzmem** - булевый параметр (по умолчанию включен), который включает режим
фаззинга символьных адресов.

**wait_jobs** - булевый параметр (по умолчанию включен), который включает
приостановление построения предиката пути, когда набрано достаточно
необработанных запросов к математическому решателю.

**solving_limit** - булевый параметр (по умолчанию включен), который включает 60
секундный тайм-аут на суммарное время, проведенное в решателе.

**symaddr** - целочисленный параметр, который включает режим обработки символьных
адресов раз в N запусков Sydr (по умолчанию N = 25). Чтобы выключить этот режим,
необходимо указать N = 0.

**[sydr.env]** - таблица, содержащая значения переменных окружения, которые будут
выставлены для каждого запускаемого процесса Sydr. Каждая строка таблицы задаёт
строковую переменную, имя которой совпадает с именем соответствующей переменной окружения.
Значения переменных окружения можно задавать также в системных переменных окружения.
При этом значения, заданные в файле конфигурации, более приоритетны, чем
значения, заданные в системных переменных окружения.

### libFuzzer

```toml
[libfuzzer]
path = "/target_fuzzer"
args = "-dict=/json.dict -jobs=6 /corpus"
cmin = true
set_cover_merge = true
[libfuzzer.env]
    ASAN_OPTIONS = "allocator_may_return_null=0"
```

Таблица `[libfuzzer]` может содержать следующие параметры:

**path** - путь до libFuzzer обертки.

**args** - аргументы libFuzzer. В аргументах могут быть указаны входные
директории с корпусами. Выходная директория с корпусом автоматически создается в
каталоге с проектом (и подставляется в аргументы libFuzzer). В выходной корпус
будут минимизированы все входные корпуса. Число процессов libFuzzer можно
контролировать через опцию `-jobs=N`,
которая указывает на то, что должно быть выполнено N запусков фаззинга до конца
(пока не найден баг или исчерпан лимит времени/числа итераций). Запуски фаззинга
распределяются между несколькими процессами libFuzzer (по умолчанию используется
не больше половины доступных ядер), число которых можно задать через
`-workers=N`. Если цель для фаззинга аварийно завершается, имеет смысл
использовать опции `-jobs=M -workers=N`, где N - число процессов libFuzzer, а
M - число аварийных завершений, зависаний и oom, по достижению которого фаззинг
будет завершен. Подробное описание опций libFuzzer можно найти в его
[документации](https://www.llvm.org/docs/LibFuzzer.html).

**cmin** - булевый параметр (по умолчанию включен), который включает
минимизацию входных корпусов в выходной корпус проекта. Если параметр выключен,
то происходит просто копирование входных корпусов в выходной корпус проекта.
Минимизацию корпуса, например, можно выключить, когда libFuzzer не справляется
минимизировать корпус.

**set_cover_merge** - булевый параметр (по умолчанию выключен), который
позволяет использовать для минимизации опцию libFuzzer `set_cover_merge`. Если
параметр выключен, для минимизации используется опция `merge`.

**[libfuzzer.env]** - таблица, содержащая значения переменных окружения, которые будут
выставлены для каждого запускаемого процесса libFuzzer. Каждая строка таблицы задаёт
строковую переменную, имя которой совпадает с именем соответствующей переменной окружения.

По умолчанию задаётся переменная среды `ASAN_OPTIONS="allocator_may_return_null=1"`.

Значения по умолчанию можно менять путем переопределения их в таблице `[libfuzzer.env]` или в системных
переменных окружения. Значения опций `hard_rss_limit_mb` и `detect_leaks` нужно задавать только через
соответствующие аргументы libFuzzer: `-rss_limit_mb` и `-detect_leaks`.
При этом наибольший приоритет имеют значения, заданные в файле конфигурации; средний приоритет имеют
значения, заданные в системных переменных окружения; низший приоритет имеют значения по умолчанию.

### Atheris

```toml
[atheris]
path = "/target_fuzzer"
args = "-dict=/json.dict -jobs=6 /corpus"
cmin = true
set_cover_merge = true
ld_preload = false
[atheris.env]
    ASAN_OPTIONS = "allocator_may_return_null=0"
```

Таблица `[atheris]`, помимо всех параметров таблицы `[libfuzzer]`, содержит один
дополнительный параметр:

**ld_preload** - булевый параметр (по умолчанию включен), который позволяет при
запуске Python-кода для фаззинга, сбора покрытия или анализа аварийных
завершений устанавливать переменную среды `LD_PRELOAD` равной пути до библиотеки
`asan_with_fuzzer.so`, необходимой при работе с кодом, имеющим расширения на
языках C/C++, для их инструментации.

Для Atheris по умолчанию задаётся переменная среды

`ASAN_OPTIONS="hard_rss_limit_mb=0,abort_on_error=1,detect_leaks=0,malloc_context_size=0,symbolize=0,`

`allocator_may_return_null=1"`

Значения по умолчанию можно менять путем переопределения их в таблице `[atheris.env]` или в системных
переменных окружения.
При этом наибольший приоритет имеют значения, заданные в файле конфигурации; средний приоритет имеют
значения, заданные в системных переменных окружения; низший приоритет имеют значения по умолчанию.

### AFL++

```toml
[aflplusplus]
path = "/afl"
args = "-t 5000 -i /corpus"
target = "/target_afl @@"
cmin = true
jobs = 6
[aflplusplus.env]
    AFL_PRINT_FILENAMES = "1"
    AFL_MAP_SIZE = "10000000"
```

Таблица `[aflplusplus]` может содержать следующие параметры:

**args** - аргументы AFL++. Необходимым аргументом является опция `-i` для
указания входного корпуса. Дополнительно можно
указать опции для инструментации (`-Q`, `-O` для бинарной инструментации),
тайм-аутов (`-t 5000` миллисекунд) и другие.

**target** - строка запуска обертки для AFL++. Вместо имени входного файла
следует использовать `@@`. Если обертка читает входные данные со стандартного
потока ввода, то `@@` указывать не нужно.

**cmin** - булевый параметр (по умолчанию включен), который включает
минимизацию входного корпуса при старте гибридного фаззинга.

**jobs** - число процессов AFL++ для запуска (по умолчанию 1).

Для таблицы `[aflplusplus]` запуск нескольких
процессов AFL++ осуществляется автоматически в соответствии с
[рекомендациями](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores):
запускается один основной фаззер (`afl_main-worker`) и `jobs-1` второстепенных процессов
(`afl_s<i>-worker`), каждый второстепенный фаззер имеет свой набор
генерируемых автоматически опций с настройками фаззинга.

Одновременно нельзя запустить более 64 процессов AFL++, так как это очень
неэффективная стратегия для гибридного фаззинга
([объяснение](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/fuzzing_in_depth.md#c-using-multiple-cores)).

**path** - путь до AFL++ и его утилит. Параметр не обязателен, если путь
добавлен в `$PATH` (в докере `sydr/ubuntu20.04-sydr-fuzz` уже добавлен).

**[aflplusplus.env]** - таблица, содержащая значения переменных окружения, которые будут
выставлены для каждого запускаемого процесса AFL++. Каждая строка таблицы задаёт
строковую переменную, имя которой совпадает с именем соответствующей переменной окружения.

Для настройки AFL++ можно использовать различные переменные окружения. Переменные
`AFL_SKIP_CPUFREQ=1`, `AFL_NO_UI=1`, `AFL_PRINT_FILENAMES`, `AFL_AUTORESUME`,
`AFL_MAP_SIZE=65536` выставляются автоматически по необходимости. `AFL_MAP_SIZE`
можно задать своим значением, однако это в большинстве случаев не требуется, т.к.
afl-fuzz определяет размер битовой карты автоматически. Переменная
`AFL_PRINT_FILENAMES=1` позволяет во время минимизации следить, какой файл
обрабатывается в данный момент. Это удобно, когда в корпусе находятся входные
файлы, приводящие к аварийному завершению, что приводит к ошибке работы
минимизации. При помощи `AFL_PRINT_FILENAMES=1` можно будет найти такие файлы
и удалить их. Также для тяжелых фаззинг целей можно выставить большое
значение переменной `AFL_FORKSRV_INIT_TMOUT`, отвечающей за максимальное время
инициализации форк-сервера AFL++, а также выставить переменную `AFL_MAP_SIZE=10000000`.
Для лучшего взаимодействия AFL++ и Sydr можно уменьшить интервал
синхронизации `AFL_SYNC_TIME` (указывается в минутах, по умолчанию 30 минут).
Также могут быть полезными переменные `AFL_DISABLE_TRIM`, `AFL_SHUFFLE_QUEUE`,
`AFL_NO_AFFINITY`.

По умолчанию задаются также переменные среды

`ASAN_OPTIONS="hard_rss_limit_mb=2048,abort_on_error=1,detect_leaks=0,malloc_context_size=0,symbolize=0,`

`allocator_may_return_null=1"`

`UBSAN_OPTIONS="halt_on_error=0,abort_on_error=0,malloc_context_size=0,allocator_may_return_null=1"`

Значения по умолчанию можно менять путем переопределения их в таблице `[aflplusplus.env]` или в системных
переменных окружения.
При этом наибольший приоритет имеют значения, заданные в файле конфигурации; средний приоритет имеют
значения, заданные в системных переменных окружения; низший приоритет имеют значения по умолчанию.
Полный список переменных окружения приведен
[здесь](https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/env_variables.md).

Значение некоторых параметров `ASAN_OPTIONS`:

**hard_rss_limit_mb** - задает ограничение памяти анализируемого приложения в Мб (по
умолчанию 2 Гб). Чтобы снять ограничение памяти, можно указать 0. Данная опция
помогает Casr обнаруживать oom и отличать аварийное завершение от oom на шаге
`sydr-fuzz casr`. Однако AFL++ не поддерживает ограничение памяти через
`ASAN_OPTIONS`. Для обработки oom в AFL++ рекомендуется выключить swap. Тогда
программа будет убиваться системным OOM Killer.

**detect_leaks** - булевый параметр (по умолчанию выключен), который включает
режим фаззинга, при котором срабатывания leak-санитайзера считаются аварийными
завершениями.

**allocator_may_return_null** - булевый параметр (по умолчанию включен), который
разрешает аллокатору возвращать нулевой указатель.

Задание параметров `halt_on_error=1,abort_on_error=1` для `UBSAN_OPTIONS`
включает режим фаззинга, при котором срабатывания ubsan-санитайзера приводят
к аварийным завершениям.

Конфигурация AFL++ может быть задана как с помощью одной таблицы `[aflplusplus]`,
так и с помощью списка таблиц `[[aflplusplus]]`. В первом случае все параметры,
заданные в таблице, применяются ко всем процессам AFL++. Во втором случае первая
таблица является основной и задаёт параметры для основного (main) процесса AFL++ и некоторого
числа дополнительных (secondary) процессов, а каждая следующая таблица позволяет запустить
определённое число дополнительных (secondary) процессов фаззера со своими параметрами.

Пример с несколькими таблицами:

```toml
[[aflplusplus]]
path = "/afl"
args = "-t 5000 -i /corpus"
target = "/target_afl @@"
cmin = true
jobs = 6
[aflplusplus.env]
    AFL_PRINT_FILENAMES = "1"

[[aflplusplus]]
args = "-t 10000"
target = "/target_afl_other @@"
jobs = 2
[aflplusplus.env]
    AFL_MAP_SIZE = "10000000"
```

Задание различных опций для дополнительных процессов фаззера
может быть полезно при использовании инструментации [CmpLog](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.cmplog.md) ([RedQueen](https://github.com/RUB-SysSec/redqueen))
или [laf-intel](https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.laf-intel.md) (COMPCOV).

Пример с несколькими таблицами для CmpLog:

```toml
[[aflplusplus]]
args = "-i /corpus -t 2000"
target = "/target_afl @@"
jobs = 4

[[aflplusplus]]
args = "-t 2000 -c /target_afl_cmplog -m none"
target = "/target_afl @@"
jobs = 2
```

Первая таблица списка `[[aflplusplus]]` может содержать все перечисленные выше
параметры. Каждая дополнительная таблица списка `[[aflplusplus]]` может содержать
все перечисленные выше параметры, кроме **path** и **cmin** (эти параметры задаются
только для первой таблицы списка).

При использовании списка `[[aflplusplus]]` директории для входного корпуса
(опция `-i` в **args**) должны совпадать во всех таблицах (кроме того, достаточно
задать опцию только для первой таблицы).

Для первой таблицы списка запускается один основной фаззер (`afl_main-worker`)
и `jobs-1` второстепенных процессов (`afl_s<i>-worker`), каждый второстепенный
фаззер имеет свой набор генерируемых автоматически опций с настройками фаззинга.
Для всех остальных таблиц списка `[[aflplusplus]]` производится запуск `jobs`
второстепенных процессов (`afl_s<i>-worker`), каждый второстепенный фаззер
имеет одинаковый набор заданных в этой таблице опций.

### cov

```toml
[cov]
target = "/instrumented_target @@"
[cov.env]
    CLASSIC_ENVVAR = "XXX"
```

Таблица `[cov]` содержит следующие параметры:

**target** - строка запуска инструментированного для сбора покрытия целевого
исполняемого файла. При сборке исполняемого файла следует использовать флаги:
`-fprofile-instr-generate -fcoverage-mapping`.

**[cov.env]** - таблица, содержащая значения переменных окружения, которые будут
выставлены при сборе покрытия. Каждая строка таблицы задаёт строковую переменную,
имя которой совпадает с именем соответствующей переменной окружения.

Значения переменных окружения можно задавать также в системных переменных окружения.
При этом значения, заданные в файле конфигурации, более приоритетны, чем
значения, заданные в системных переменных окружения.

### Результаты фаззинга

Результаты фаззинга и промежуточные артефакты сохраняются в директории проекта.
Путь до директории с выходным проектом может быть задан пользователем с помощью
опции `-o` перед командой запуска (`run`, `security`). Если опцию `-o` не задавать,
то директория с проектом автоматически создаcтся в текущей директории со
следующим именем: `<config-name>-out`. Директория с проектом имеет следующий вид:

    sydr-fuzz-out/
    ├── crashes
    │   ├── crash-deadbeaf
    │   ├── oom-cafebabe
    │   └── timeout-cafecafe
    ├── corpus
    │   └── seed
    ├── corpus-old
    │   └── seed
    ├── libfuzzer
    │   └── fuzz-0.log
    ├── aflplusplus
    │   ├── afl_main-worker
    │   │   ├── crashes
    │   │   ├── hangs
    │   │   └── queue
    │   ├── afl_s01-worker
    │   │   ├── crashes
    │   │   ├── hangs
    │   │   └── queue
    │   ├── sydr-worker
    │   │   ├── crashes
    │   │   └── queue
    │   └── logs
    │       ├── afl_main.log
    │       └── afl_s01.log
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
    │   └── timeout
    │       └── timeout-deadbeaf4
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

В зависимости от конфигурации гибридного фаззинга, директория проекта содержит
либо `libfuzzer`, либо `aflplusplus`. В директории `libfuzzer` хранятся логи libFuzzer'а.
Директория `aflplusplus` является общей выходной директорией для AFL++ и содержит
директории `aflplusplus/*-worker` для каждого запущенного процесса AFL++ и Sydr
(`sydr-worker` требуется для синхронизации между AFL++ и Sydr). Кажая worker-директория
содержит директории с рабочи корпусом (`queue`), найденными аварийными завершениями
(`crashes`) и зависаниями (`hangs`). В директории `aflplusplus/logs` хранятся логи AFL++.

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
в директорию `casr/timeout`.

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
файлом sydr-fuzz в директорию `/fuzz` внутри докера (`--privileged` необходим
для работы Casr, а также позволяет
докеру видеть локальный лицензионный USB ключ, `--network host` - сетевой ключ,
также в докер пробрасывается время системы):

    $ sudo docker run --privileged --network host -v /etc/localtime:/etc/localtime:ro \
        --rm -it -v $PWD:/fuzz sydr-fuzz-target /bin/bash

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
логе как "[SYDR] Files reloaded by libFuzzer: {}, unique {}" для libFuzzer и
"[SYDR] Files imported by AFL++: {}" для AFL++. Для libFuzzer дополнительно
печатается число уникальных полезных файлов, поскольку каждый запущенный
инстанс libFuzzer'а анализирует файлы независимо и один и тот же файл Sydr'а
может учитываться несколько раз.

Сами полезные файлы можно найти следующим образом.

Для libFuzzer:

    $ find name-out/libfuzzer -name "fuzz-*.log" | xargs -I {} grep -H --color "Reloaded.*sydr_" {}

Для AFL++:

    $ ls name-out/aflplusplus/afl_main-worker/queue | grep "sync:sydr-worker"

## Минимизация корпуса

Чтобы минимизировать корпус, надо запустить команду `cmin`:

    $ sydr-fuzz -c name.toml cmin

После этого содержимое оригинального корпуса будет помещено в директорию
`name-out/corpus-old`, минимизированный корпус будет в директории `name/corpus`.

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

Для запуска сбора покрытия на корпусе проекта и вывода краткого отчёта с цветной разметкой
можно выполнить следующую команду:

    $ sydr-fuzz -c name.toml cov-report -- -use-color=true

Для получения отчёта о покрытии в формате html можно воспользоваться следующей
командой:

    $ sydr-fuzz -c name.toml cov-show -- -format=html > index.html

Более того, можно получить покрытие в формате LCOV html:

    $ sydr-fuzz -c name.toml cov-export -- -format=lcov > name.lcov
    $ genhtml -o name-cov-html name.lcov

## Сбор покрытия (Python)

Sydr-fuzz позволяет собирать покрытие на корпусе для целевого Python-кода,
выполнять его обработку и получать отчет в формате html. Для этого достаточно
использовать команду

    $ sydr-fuzz -c name.toml pycov html

Более подробное описание находится в разделе "Опции сборa покрытия (Python)".

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
только секцию `[libfuzzer]`:

```toml
exit-on-time = 7200

[libfuzzer]
path = "/target_fuzzer"
args = "-dict=/json.dict -jobs=6 /corpus"
```

 или `[aflplusplus]`:

```toml
exit-on-time = 7200

[aflplusplus]
args = "-t 5000 -i /corpus"
target = "/target_afl @@"
jobs = 6
```

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

## Анализ аварийных заврешений с помощью Casr

Sydr-fuzz дает возможность осуществлять анализ аварийных завершений после фаззинга:
создание отчетов об аварийных завершениях, их дедупликация и кластеризация.
Для этого должна существовать непустая директория `name-out/crashes` с входными данными.
Конфигурационный файл может выглядеть следующим образом (может быть использован
тот же конфиг, на основе которого производился фаззинг, возможно и с `[aflplusplus]`):

```toml
[sydr]
target = "./target_sydr @@"

[libfuzzer]
path = "./target_fuzzer"
```

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

Для удобного просмотра отчетов можно воспользоваться специальным инструментом `casr-cli`:

    $ casr-cli name-out/casr/cl1/crash-deadbeef.casrep

Можно выбрать другой вид отчета с помощью аргумента **--view**:

    $ casr-cli --view slider name-out/casr/cl1/crash-deadbeef.casrep

Вывод отчета в stdout:

    $ casr-cli --view stdout name-out/casr/cl1/crash-deadbeef.casrep

Также инструментом можно воспользоваться для просмотра общей статистики Casr директории,
содержащей отчеты или кластеры:

    $ casr-cli name-out/casr

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

# Sydr: Symbolic DynamoRIO

Sydr - инструмент динамической символьной интерпретации на базе символьного
фреймворка [Triton](https://github.com/JonathanSalwan/Triton) и динамического
инструментатора [DynamoRIO](https://github.com/DynamoRIO/dynamorio). Инструмент
позволяет получить наборы входных данных для инвертирования условных переходов,
которые встретились по ходу выполнения программы. Более того, Sydr реализует
различные символьные предикаты безопасности для поиска ошибок выхода за границы
буфера, целочисленного переполнения, деления на нуль и др.

Схема работы инструмента выглядит следующим образом:

- Запуск программы на имеющихся наборах входных данных с целью построения
  предиката пути (системы уравнений, описывающей поток управления программы).
  Условие каждого перехода, зависящего от входных данных, добавляется в предикат
  пути.
- Инвертирование переходов из предиката пути с использованием математического
  решателя. В результате получаются новые входные данные, расширяющие покрытие
  программы. Переходы инвертируются асинхронно одновременно с построением
  предиката пути.

Стек инструментов:

- 4 уровень: инструмент динамической символьной интерпретации Sydr детектирует
  входные данные, строит предикат пути, разрешает косвенные передачи управления
  (switch), производит слайсинг предиката пути, инвертирует переходы, проверяет
  ошибочные ситуации (предикаты безопасности), генерирует новые входные данные
- 3 уровень: символьный фреймворк
  [Triton](https://github.com/JonathanSalwan/Triton) транслирует инструкции в
  формулы, хранит символьное состояние регистров и памяти
- 2 уровень: математический решатель [Bitwuzla](https://bitwuzla.github.io)
  проверяет
  выполнимость формул, для выполнимых формул предоставляет модель (набор значений
  переменных, при которых формула выполнима)
- 1 уровень: динамический инструментатор
  [DynamoRIO](https://github.com/DynamoRIO/dynamorio) выполняет программу,
  детектирует системные вызовы, предоставляет выполнявшиеся инструкции, значения
  регистров и памяти

# Использование Sydr

В этом разделе представлено руководство пользователя инструмента Sydr.

## Опции Sydr

    $ ./sydr --help
    Usage: ./sydr                           [-h] [-v] [-f FILE]
                                            [--sym-socket [=SOCKET(=*:*)]]
                                            [--sym-argv] [--sym-arg N]
                                            [--sym-env ENV_VAR]
                                            [--sym-stdin [STDIN_MASK]]
                                            [--sym-mem MEMORY]
                                            [-o DIRECTORY (=out)] [--flat [TAG]]
                                            [-r] [-d] [--dump-smt-failed]
                                            [--python] [-t] [--no-edge-trace]
                                            [-c DIRECTORY] [--config FILE]
                                            [--wait-jobs [=N(=200)]]
                                            [--follow-fork-mode MODE]
                                            [--symbolize-address [=MODE(=address)]]
                                            [--max-table-size ENTRIES (=200)]
                                            [--table TABLE] [--fuzzmem [=NUM(=10)]]
                                            [--fuzzmem-models [=NUM(=1000)]]
                                            [--no-invert] [-b BRANCH] [-n N]
                                            [--strategy DISTRIBUTION (=direct)]
                                            [-j N (=1)] [--optimistic] [-p]
                                            [--solving-timeout SECONDS (=10)]
                                            [-s SECONDS] [--bad-chars CHARS]
                                            [--models N (=1)]
                                            [--security [=CHECKERS(=all)]]
                                            [-l LEVEL (=info)] [--log-file FILE]
                                            [--stats-file FILE] [--no-console-log]
                                            [-m MEGABYTES] [--seed SEED] -- app
                                            [args]
    Sydr options:

    Generic options:
      -h [ --help ]                         Show help.
      -v [ --version ]                      Show version.

    Input:
      -f [ --sym-file ] FILE                Symbolic input file. Argument format:
                                            '<FILE>[,mask=<MASK_FILE>]'. See the
                                            full description at the end.
      --sym-socket [=SOCKET(=*:*)]          Symbolic socket. Argument format:
                                            '<SOCKET>[,mask=<MASK_FILE>]'. See the
                                            full description at the end.
      --sym-argv                            Symbolic command line arguments.
      --sym-arg N                           Symbolic N-th (starting from 1) command
                                            line argument.
      --sym-env ENV_VAR                     Symbolic environment variable. Argument
                                            format: '<ENV_VAR>[,mask=<MASK_FILE>]'.
                                            See the full description at the end.
      --sym-stdin [STDIN_MASK]              Symbolic stdin data. A path to mask
                                            file may be specified as STDIN_MASK.
      --sym-mem MEMORY                      Symbolic memory buffer. Argument
                                            format: '[<MODULE_NAME>:]<INSTR_ADDR>,<
                                            MEMORY_ACCESS>'. See the full
                                            description at the end.

    Output:
      -o [ --output-dir ] DIRECTORY (=out)  Output directory to store generated
                                            inputs.
      --flat [TAG]                          Make flat output directory without
                                            subdirectories for every input set.
                                            Only one input source is supported for
                                            the flat mode. This option also sets
                                            --no-edge-trace. Generated input name
                                            contains TAG.
      -r [ --remove ]                       Remove output directory before run.
      -d [ --dump-smt ]                     Dump SMT statements of execution
                                            artifacts.
      --dump-smt-failed                     Dump SMT statements for TIMEOUT,
                                            OUTOFMEM, and UNKNOWN solver queries.
      --python                              Use Python representation for formulas.
      -t [ --trace ]                        Save instruction trace.
      --no-edge-trace                       Do not save edge traces.

    Cache:
      -c [ --cache ] DIRECTORY              Directory to store Sydr shared cache.
                                            Sydr skips already traversed branches
                                            and found errors by security
                                            predicates. Cache supported only with
                                            direct inversion strategy.

    Config:
      --config FILE                         Read options from configuration FILE.
                                            If not specified, options are read from
                                            sydr.toml (if it exists in current
                                            directory).

    Symbolic interpretation:
      --wait-jobs [=N(=200)]                Stop path predicate builder thread when
                                            there are already N scheduled jobs.
                                            Resume the thread when all jobs are
                                            processed.
      --follow-fork-mode MODE               Perform symbolic interpretation only of
                                            parent|child process.

    Symbolic addresses:
      --symbolize-address [=MODE(=address)] Enable symbolic address processing for
                                            memory load operations. MODE
                                            address|memory defines how symbolic
                                            values would be handled. In address
                                            mode only symbolic addresses are
                                            processed, while all symbolic memory
                                            cells are concretized. Memory mode
                                            allows to handle symbolic memory cells
                                            too.
      --max-table-size ENTRIES (=200)       Max table size in entries for both
                                            symbolic addresses and jump tables.
                                            Restricts memory region that
                                            potentially can be accessed via
                                            symbolic address.
      --table TABLE                         Memory table location for symbolic
                                            addresses and jump tables. Table
                                            described by module, start address, and
                                            length in bytes. Argument format:
                                            '<MODULE>,<HEX_ADDRESS>,<LENGTH>' or
                                            '<HEX_ADDRESS>,<LENGTH>'. <LENGTH> is a
                                            hex or decimal value.
      --fuzzmem [=NUM(=10)]                 Fuzz symbolic addresses on memory reads
                                            and writes with SMT solver. Picking up
                                            different symbolic address values until
                                            solver returns UNSAT or NUM different
                                            values are generated.
      --fuzzmem-models [=NUM(=1000)]        Maximum models generated for symbolized
                                            addresses fuzzing in one Sydr run.

    Branch selection:
      --no-invert                           Do not invert branches.
      -b [ --invert-branch ] BRANCH         A program branch to invert. Argument
                                            format: '<MODULE_NAME>,<HEX_ADDRESS>'
                                            or '<HEX_ADDRESS>'.
      -n [ --invert-n ] N                   Try to invert N branches and stop.
      --strategy DISTRIBUTION (=direct)     Branches inversion order and selection
                                            strategy direct|reverse|uniform. Invert
                                            branches in direct order from first to
                                            last, invert branches in reverse order,
                                            or random shuffle branches order
                                            uniformly.

    Solving:
      -j [ --jobs ] N (=1)                  Number of parallel solving jobs.
      --optimistic                          Enable optimistic solving. Try to solve
                                            only target branch constraint on
                                            failure. Moreover, try eliminating
                                            constraints from non-nested branches
                                            and function calls.
      -p [ --path-predicate ]               Solve path predicate.
      --solving-timeout SECONDS (=10)       Timeout for one solver query.
      -s [ --solving-limit ] SECONDS        Total solving time limit.
      --bad-chars CHARS                     Restricted characters in symbolic input
                                            that should be avoided. Argument
                                            format: '[<OFFSET>,]<BAD_CHARS>'.
                                            BAD_CHARS define a specific character
                                            (32 or 0x20) or a range of characters
                                            (9-13). Optionally characters may be
                                            restricted for specified symbolic input
                                            OFFSET (0x123 or 10-100).
      --models N (=1)                       Maximum number of models to generate
                                            for each branch or security predicate.

    Security predicates:
      --security [=CHECKERS(=all)]          Run with checking comma-separated
                                            security predicates: zerodiv - division
                                            by zero; bounds - out of bounds access;
                                            null - null pointer dereference;
                                            intoverflow - integer overflow;
                                            intoverflow-inst - integer overflow
                                            sink is instruction; intoverflow-func -
                                            integer overflow sink is function
                                            argument; intoverflow-func-risk -
                                            integer overflow in risky function
                                            argument; invalid-heap - invalid free,
                                            double free, or invalid realloc;
                                            negsize - negative size argument in
                                            allocation and string functions.

    Logging:
      -l [ --log-level ] LEVEL (=info)      Specify logging level
                                            fatal|error|warning|info|debug|trace.
      --log-file FILE                       Save log to FILE. If not specified, log
                                            is saved to sydr.log in output
                                            directory.
      --stats-file FILE                     Save stats to FILE. If not specified,
                                            stats file is saved to stats.json in
                                            output directory.
      --no-console-log                      Do not print log to console.

    Parameters:
      -m [ --memory-limit ] MEGABYTES       Maximum memory consumption.
      --seed SEED                           Pseudo-random number generator seed.

    Suboptions:
      --sym-env <ENV_VAR>[,mask=<MASK_FILE>]

        ENV_VAR                             Symbolic environment variable name.
        mask=MASK_FILE                      Environment variable mask.

      --sym-file <FILE>[,mask=<MASK_FILE>]

        FILE                                Symbolic file name.
        mask=MASK_FILE                      File mask.

      --sym-mem <LOCATION>,<MEMORY_ACCESS>

        LOCATION                            Instruction module name and instruction
                                            address. LOCATION format: '[<MODULE_NA
                                            ME>:]<INSTR_ADDR>'.
        MEMORY_ACCESS                       Expression containing symbolic memory b
                                            uffer address and size. MEMORY_ACCESS f
                                            ormat: 'v(<address>,<size>)' or '(<addr
                                            ess>,<size>)', where '<address>' and '<
                                            size>' can contain arithmetic operation
                                            s (+, -, *) on MEMORY_ACCESS expression
                                            s, registers (rax, eax, r8, ...), and c
                                            onstants (decimal: 12, hex: 0x12, oct:
                                            012).

      --sym-socket <SOCKET>[,mask=<MASK_FILE>]

        SOCKET                              Symbolic socket: <ip>:<port>. May be wi
                                            ldcard: *:*.
        mask=MASK_FILE                      Socket mask.

    MASK_FILE - file each line of which contains points or intervals (delimited by
    '-') of symbolic bytes. Only these bytes will be symbolized.

Опции можно задавать как в командной строке, так и в файле конфигурации с помощью опции командной строки `--config`. При отсутствии опции `--config` в командной строке файлом конфигурации по умолчанию считается `sydr.toml`, если такой файл существует в текущей директории.

Опции, определённые в командной строке, считаются более приоритетными, чем опции, определённые в файле конфигурации.
При определении опции с одним и тем же именем и в командной строке, и в файле конфигурации будет
выбрано значение, определённое в командной строке. Однако существуют опции, которые можно задавать
только в файле конфигурации, например, эмуляция задаётся таблицей `emu`.
Подробное описание задания опций через конфигурационный файл можно найти в разделе "Формат конфигурационного файла".

### Символьные входные данные

Опция **-f [ \--sym-file ] FILE** указывает на путь к файлу, который считается
символьным (его содержимое будет подбираться в рамках символьной интерпретации).
Если программа на вход получает несколько файлов, то можно также отметить
несколько файлов как символьные. Для этого нужно повторить опцию необходимое
количество раз.

Опция **\--sym-socket [SOCKET]** указывает на символьное сетевое соединение.
Данные, полученные программой с соответствующего ip-адреса и порта, будут
считаться символьными. Опция **\--sym-socket** без дополнительных параметров
указывает, что все данные, полученные по сети, являются символьными.

Опция **\--sym-argv** указывает, что все аргументы, полученные программой (вся
строка), считаются символьными.

Опция **\--sym-arg N** указывает, что конкретный аргумент является символьным.
Аргументы нумеруются с **единицы**. Опция может повторяться с различными номерами
нужное количество раз.

Опция **\--sym-env ENV_VAR** указывает, что переменная среды с именем `ENV_VAR`
становится символьной. Эта опция может повторяться требуемое число раз.

Опция **\--sym-stdin [STDIN_MASK]** указывает, что входные данные, полученные со
стандартного потока ввода, являются символьными.

Опция **\--sym-mem [MODULE_NAME:]INSTR_ADDR,MEMORY_ACCESS** указывает, что буфер
на инструкции по адресу `[MODULE_NAME:]INSTR_ADDR` является символьным (содержит
входные данные). Адрес инструкции внутри модуля указывается с учётом базы
загрузки (image base). Адрес и размер буфера указывается в `MEMORY_ACCESS`.
Формат `MEMORY_ACCESS`: `v(address, size)` или `(address, size)`, где `address`
и `size` могут содержать арифметические операции (+, -, \*) над выражениями
`MEMORY_ACCESS`, регистрами (rax, eax, r8, ...) и константами (десятичными 12,
шестнадцатеричными 0x12 и восьмеричными 012).

### Выходные данные

Опция **-o [ \--output-dir ] DIRECTORY** является обязательной. Путь до
директории с результатами. Директория создастся автоматически. Если директория
уже создана, будет выведено сообщение об ошибке. Инструмент в целях
непреднамеренной перезаписи результатов требует отсутствие директории, в которую
будут записаны текущие результаты.

Опция **\--flat** позволяет сделать выходную директорию плоской. Каждый новый набор
входных данных будет генерироваться не в отдельной поддиректории, а в общей выходной
директории. Такой режим удобен для использования в гибридном фаззинге, где требуется
создавать только корпус новых файлов без какой-либо дополнительной информации. Опция
поддерживает только работу с одним источником символьных данных (файл, стандартный
поток ввода или буфер в памяти). Файлы лога `sydr.log` и статистики `stats.json`
будут также созданы в выходной директории, если не указать другой путь с помощью опций
`--log-file` и `--stats-file`. Опция `--flat` имеет параметр `TAG`, который добавляется
в имена сгенерированных файлов (а также в `sydr_tag.log` и `stats_tag.json`, если не указано
иного через соответствующие опции). Добавление тега к именам файлов позволяет безопасно
использовать одну и ту же выходную директорию при запуске нескольких процессов Sydr
подряд или одновременно. Обычно в качестве тега указывается уникальное имя входного
файла, на котором был запущен Sydr (по умолчанию тег не задан). При включении опции
`--flat` автоматически выключается генерация trace-файлов. Имена новых файлов имеют
следующий формат: `sydr_<tag>_<label>_<idx1>_<idx2>`. Поле `label` в зависимости от
типа инвертирования перехода может принимать значения `fuzzmem`, `opt` (optimistic)
и `sopt` (strong optimistic), для обычных переходов поле `label` остается пустым.
Поля `idx1` и `idx2` соответсвуют индексу инвертированного условного перехода
(инструкции) и порядковому номеру набора данных (для табличных переходов или
нескольких решений `--models`).

Опция **-r [ \--remove ]** указывает на то, что выходная директория будет
удалена перед запуском Sydr.

Опция **-d [ \--dump-smt ]** включает сохранение формул для каждого
инвертируемого перехода. Формулы сохраняются в формате SMT-LIBv2. Файлы можно
подавать на вход SMT-решателю. Также сохраняются трассы переходов для не SAT
запросов в файлах `trace_n`.

Опция **\--dump-smt-failed** включает сохранение формул для запросов к
решателю, которые не успели завершиться за тайм-аут или которые не удалось
обработать. Формулы сохраняются в формате SMT-LIBv2. Файлы можно подавать на
вход SMT-решателю. Также для таких запросов сохраняются трассы переходов в файлах
`trace_n`.

Опция **\--python**. Использование Python-представления для сохранения формул.

Опция **-t [ \--trace ]** позволяет сохранить трассу выполненных машинных
инструкций в текстовом виде. Если в начале строки с инструкцией присутствует
знак "+", то эта инструкция участвовала в обработке входных данных.
**Внимание!** Для больших программ и входных данных возможно замедление в
несколько раз из-за записи больших объемов данных на диск.

Опция **\--no-edge-trace** позволяет отключить сохранение трасс переходов для
экономии места на диске.

### Кэширование

Опция **-c [ \--cache ] DIRECTORY** позволяет указать директорию для кэширования
результатов работы Sydr. Данная директория разделяется между различными
запусками произвольного количества Sydr, анализирующих одно целевое приложение.
В этой директории битовые карты `branch.bitmap` и `context.bitmap` хранят информацию
об условных переходах в программе, чтобы уменьшить число повторных инвертирований одних
и тех же переходов. Файл `version` хранит версию формата битовой карты. Также в этой
директории хранится битовая карта `security.bitmap`, которая хранит найденные
потенциальные ошибки (`--security`). Повторно найденные ошибки тихо пропускаются.

### Конфигурационный файл

Опция **\--config FILE** позволяет задавать опции в конфигурационном файле.
По умолчанию (если эта опция не задана в командной строке) конфигурациионным считается
файл `sydr.toml` (если он существует в текущей директории).

**Символьная интерпретация**

Опция **\--wait-jobs N** позволяет экономить процессорное время. Построение
предиката пути приостанавливается, когда уже набрано N
необработанных запросов к математическому решателю. Как только все запросы будут
обработаны, построение предиката пути возобновляется.

Опция **\--follow-fork-mode MODE** позволяет указывать процесс для символьной
интерпретации после `fork()` аналогично gdb: `parent|child`. В режиме `parent`
будет символьно интерпретироваться только родитель. В режиме `child` после
каждого `fork()` интерпретируется дочерний процесс. По умолчанию символьно
интерпретируются все процессы. Данная опция может потребоваться для указания
интересующего процесса, если несколько процессов одновременно обрабатывают
символьные данные.

### Символьные адреса

Опция **\--symbolize-address MODE** включает обработку символьных адресов при доступах
к памяти на чтение. Анализ табличных переходов (switch-case) при этом включен всегда.
Режим `address|memory` позволяет задать способ обработки символьных значений. В режиме
`address` обрабатываются только символьные адреса, символьные ячейки памяти при этом
конкретизуются. Режим `memory` позволяет дополнительно обрабатывать символьные ячейки
памяти.

Опция **\--max-table-size ENTRIES** устанавливает максимальный размер потенцильно
адресуемой области памяти для символьного адреса. Размер памяти задается числом
элементов в таблице, к которой производится символьный доступ.

Опция **\--table TABLE** позволяет указать местоположение заранее известных таблиц
в виде: `<module name>,<address>,<length>` или `<address>, <length>`. Адрес начала
таблицы внутри модуля указывается с учётом базы загрузки (image base). Длина таблицы
указывается в байтах. Можно задавать несколько таблиц, последовательно перечисляя
опцию `--table`. Указанные таблицы используются при анализе символьных адресов и
табличных переходов (switch-case).

Опция **\--fuzzmem NUM** включает режим фаззинга символьных адресов. В данном
режиме для каждого символьного адреса (на чтение или на запись) с помощью SMT-решателя
генерируются `NUM` различных моделей входных данных, которые пытаются перебрать возможные
значения адреса. Данная опция несовместима с `--symbolize-address`.

Опция **\--fuzzmem-models NUM** позволяет ограничить общее число моделей, генерируемых
во время фаззинга символьных адресов. Опция полезна при проведении гибридного фаззинга.

### Выбор условных переходов

Опция **\--no-invert** - запуск без инвертирования переходов. Рекомендуется
использовать для проверки предикатов безопасности без инвертирования переходов.

Опция **-b [ \--invert-branch ] BRANCH** указывает конкретный условный переход
для инвертирования в виде: `<module name>,<address>` или `<address>`. Адрес
перехода внутри модуля указывается с учётом базы загрузки (image base). Можно
задавать несколько переходов, последовательно перечисляя опцию -b.

Опция **-n [ \--invert-n ] N**. Sydr пытается инвертировать `N` условных
переходов и завершает работу.
Можно использовать для равномерного выбора переходов для инвертирования при
фаззинге.

Опция **\--strategy DISTRIBUTION** позволяет задавать стратегию выбора порядка
инвертирования переходов: `direct|reverse|uniform`. Последовательное инвертирование
переходов `direct`, инвертирование переходов с конца `reverse` или случайный выбор по
равномерному распределению `uniform`.

### Решение

Опция **-j [ \--jobs ] N** позволяет указать число параллельных потоков для
решения (инвертирования переходов и/или проверки предикатов безопасности). По
умолчанию решение происходит в одном потоке. Потоки решения работают асинхронно
одновременно с потоком, который строит предикат пути.

Опция **\--optimistic** включает оптимистичные решения. Рекомендуется
использовать при фаззинге для более быстрого открытия новых путей. Если решателю
не удается решить запрос на инвертирование перехода, то производится попытка
получить решение при помощи следующих ослаблений предиката пути:
1) Решение только условия целевого перехода без предиката пути.
Такие решения в некоторых случаях
могут успешно инвертировать целевой переход без учета предыдущих переходов.
Например, `if (ch >= 0x20 && ch < 0x7f) {} if (ch == 0x7f) {}`. Последний
переход может быть успешно инвертирован без учета предыдущих. В выходной
директории оптимистичные решения с использованием этой техники сохраняются
в директориях с префиксом `optimistic`.
2) Решение условий, отобранных из предиката пути с учетом вложенных вызовов
функций и условных переходов.
Такие решения могут в некоторых случаях
могут успешно инвертировать целевой переход без учета переходов, уровень вложенности
которых не меньше уровня вложенности целевого перехода и инструкций вызова функций,
ведущих к целевому переходу.
Например,
`if (ch >= 0x20 && ch < 0x7f) { if (ch < 0x70) { if (ch == 0x50) {}} if (ch == 0x30) {}}`.
Последний переход может быть успешно инвертирован без учета второго и третьего переходов,
так как они находятся на том же или на более глубоком уровне вложенности. В выходной
директории оптимистичные решения с использованием этой техники сохраняются в
директориях с префиксом `strong_optimistic`.

Опция **-p [ \--path-predicate ]** - решение предиката пути. Получение нового
набора входных данных, которые ведут программу по тому же пути, как и
изначальный набор входных данных.

Опция **\--solving-timeout SECONDS**. Тайм-аут на один запрос к решателю.

Опция **\--solving-limit**. Предельное время, которое может быть проведено
в решателе. По достижению этого времени Sydr завершает работу.

Опция **\--bad-chars CHARS** позволяет задать ограничения на байты символьных
входных данных в виде: `[<offset>,]<bad chars>`. Указанные ограничения
применяются ко всем символьным входам. `<bad chars>` задает конкретный символ
(32 или 0x20) или диапазон символов (9-13), которые не должны содержаться в
символьных входных данных. Опционально можно задать смещение `<offset>` (0x123
или диапазон 10-100) во входных данных, по которому не должны содержаться
указанные символы.

Опция **\--models N** указывает максимальное число наборов входных данных, которое
необходимо сгенерировать для каждого инвертируемого перехода или предиката
безопасности. По умолчанию для каждого инвертируемого перехода генерируется
один набор входных данных.

### Предикаты безопасности

Опция **\--security** - проверка предикатов безопасности.
После опции `--security` можно указать через запятую список предикатов
безопасности, которые будут проверяться: `zerodiv` - деление на нуль; `null` -
разыменование нулевого указателя; `bounds` - выход за границу массива;
`intoverflow` - целочисленное переполнение; `intoverflow-inst` - целочисленное
переполнение, которое используется в вычислении адреса или условного перехода;
`intoverflow-func` - целочисленное переполнение, которое используется в аргументах
функции; `intoverflow-func-risk` - целочисленное переполнение, которое используется
только в аргументах "опасных" функций (`malloc`, `memcpy` и т.п.); `invalid-heap` -
некорректная работа с кучей (двойное освобождение, освобождение или реаллокация
по неверному адресу); `negsize` - отрицательный аргумент размера функций,
работающих со строками или динамической памятью; `all` - проверка всех предикатов
безопасности (по умолчанию).

### Логирование

Опция **-l [ \--log-level ] LEVEL (=info)** указывает уровень логирования событий
(info по умолчанию). Уровни логирования: `fatal|error|warning|info|debug|trace`.

Опция **\--log-file FILE** позволяет указать путь для сохранения файла лога. По
умолчанию лог сохраняется в `sydr.log` в выходной директории.

Опция **\--stats-file FILE** позволяет указать путь для сохранения файла со
статистикой. По умолчанию статистика сохраняется в `stats.json` в выходную
директорию.

Опция **\--no-console-log** - отключить вывод лога в stderr. Опция может быть
полезна, когда пользователь не хочет, чтобы ввод-вывод исследуемой программы
перемежался с логом.

**Параметры**

Опция **\-m [ \--memory-limit ] MEGABYTES** - устанавливает ограничение в мегабайтах по
используемой памяти для всего инструмента. По умолчанию используется вся доступная
в системе оперативная память минус 1 гигабайт. Для использования файла подкачки
возможно указать больше памяти, чем физически есть в системе.

Опция **\--seed SEED**. Затравка (seed) для генератора псевдо-случайных чисел.

## Примеры

Примеры запусков на различных источниках входных данных. Примеры можно найти в
директории `tests`.

    $ ./sydr --sym-argv -- tests/synthetic/bin64/argv good!
    $ ./sydr -o results --sym-arg 1 --sym-arg 3 -- tests/synthetic/bin64/argv_i ELA aaa PA
    $ echo xxxx > input && ./sydr --sym-file input -- tests/synthetic/bin64/file_read input
    $ echo xxxx > input && ./sydr --sym-stdin -- tests/synthetic/bin64/stdin < input
    $ CLASSIC_ENVVAR=xxxx ./sydr --sym-env CLASSIC_ENVVAR -- tests/synthetic/bin64/envvar
    $ ./sydr --sym-mem "0x811,(rbp-0x20+4*(rbp-0x2c,4),rax)" \
        -- tests/synthetic/bin64/sym_mem_buffer64 tests/synthetic/bin64/input_sym_mem_buffer
    $ LD_LIBRARY_PATH=tests/programs/lib ./sydr -r -f tests/programs/cjpeg_input \
        --optimistic -j 15 -- tests/programs/cjpeg tests/programs/cjpeg_input
    $ rm -rf out && ./sydr -r -o jasper-out -f tests/programs/jasper_input.bmp \
        -- tests/programs/jasper -f tests/programs/jasper_input.bmp -t bmp -F out -T mif
    $ rm -rf cache && ./sydr -r -c cache --optimistic -f tests/programs/elf_input \
        --solving-timeout 30 -j 15 -- tests/programs/readelf -a tests/programs/elf_input

Примеры с использованием сети требуют соответствующую утилиту, запущенную в
другом терминале, для эмуляции сетевого соединения. Все утилиты используют в
качестве аргументов только порт, на который слать данные. Символьный сокет может
быть указан как: `--sym-socket ip:port`.

    $ tests/synthetic/bin64/helper_socket_server 20007
    $ ./sydr --sym-socket 127.0.0.1:20007 -- tests/synthetic/bin64/socket_client_read 20007

    $ tests/synthetic/bin64/helper_socket_server_msg 20007
    $ ./sydr --sym-socket "*:20007" -- tests/synthetic/bin64/socket_client_msg 20007

    $ tests/synthetic/bin64/helper_socket_server_udp 20007
    $ ./sydr --sym-socket "*:20007" -- tests/synthetic/bin64/socket_client_udp 20007

    $ tests/synthetic/bin64/helper_socket_client 20007
    $ ./sydr --sym-socket -- tests/synthetic/bin64/socket_server 20007

Исходный код примеров можно найти в директории `tests/synthetic/src`.

## Формат конфигурационного файла

Файл конфигурации - это файл  формата `.toml`. Он может содержать базовые значения - числа, логические значения или строки (базовое значение состоит из имени и соответствующего ему значения, разделенных знаком `=`, например, `file = "input_file"`, `offset = 8`, `zerodiv = true`); массивы, заключённые в квадратные скобки `[]`, содержащие значения через запятую; таблицы с названиями в квадратных скобках; массивы таблиц с названиями в двойных квадратных скобках. Таблицы и массивы таблиц могут содержать любые из перечисленных элементов.

Опции, не имеющие дополнительных параметров, могут быть заданы логическими значениями. `true` означает, что опция задана, `false` означает, что опция не задана. Например, `remove = true`: опция `remove` задана; `path-predicate = false`: опция `path-predicate` не задана.

Опции с дополнительными параметрами могут быть заданы числами или строками, а также массивами, содержащими значения для повторяющейся опции.
Например: `strategy = "reverse"`, `invert-n = 100`, `security = ["null", "invalid-heap"]`, `bad-chars = [0, 8, 10]`.

Все пути к файлам задаются относительно директории, в которой расположен конфигурационный файл.

Формат задания опций со сложной структурой описан отдельно. Все такие опции могут быть заданы в виде строк (например, `table = "symptr_linear2,0x920,44"`) или массивов строк (для опций `--sym-socket`, `--sym-file`, `--sym-env` строки не должны содержать множество значений, разделённых запятыми), а также в виде таблиц или массивов таблиц.

При задании сложных опций в виде строк или массивов строк используется формат, описанный в "Опции Sydr" (например, `sym-mem = "sym_mem_buffer64:0x811,v(0xdeadbeef,0x8)"`). Далее в текущем разделе описан формат задания сложных опций в виде таблиц или массивов таблиц.

**[[sym-file]]**

Таблица для опции должна содержать имя символьного файла (`file`, в виде строки). Дополнительно может быть задан файл маски (`mask`, в виде строки).

Например:

```toml
    [sym-file]
        file = "input"
        mask = "mask_file"
```

**[[sym-socket]]**

Таблица для опции должна содержать параметры сокета в виде строки (`socket`) в формате `ip:port` (по умолчанию `*:*` - для этого нужно определить логическое значение `socket = true`) или в виде строк IP-адреса и порта (`ip` и `port`), причём описание сокета должно быть задано только одним из допустимых вариантов. Дополнительно может быть задан файл маски (`mask`, в виде строки).

Например:

```toml
    sym-socket = true
```

или

```toml
    [sym-socket]
        ip = "127.0.0.1"
        port = "30008"
```

или

```toml
    [sym-socket]
        socket = true
        mask = "mask_file"
```

или

```toml
    [sym-socket]
        socket = "127.0.0.1:30008"
```

**[[sym-env]]**

Таблица для опции должна содержать имя символьной переменной (`env-var`, в виде строки). Дополнительно может быть задан файл маски (`mask`, в виде строки).

Например:

```toml
    [sym-env]
        env-var = "CLASSIC_ENVVAR"
        mask = "mask_file"
```

**[[sym-mem]]**

Таблица для опции должна содержать адрес инструкции (`instr-addr`, в виде строки, содержащей число в 16-ричной системе счисления) и буфер. Буфер может быть задан в виде адреса и размера (`vma` и `size`, в виде строк, содержащих числа в 16-ричной системе счисления) или в виде адресного выражения (`expr`, в виде строки), причём буфер должен быть задан только одним из допустимых вариантов. Дополнительно может быть задано имя модуля инструкции (`module-name`, в виде строки).

Например:

```toml
    [sym-mem]
        instr-addr = "0x811"
        module-name = "sym_mem_buffer64"
        vma = "0xdeadbeef"
        size = "0x8"
```

или

```toml
    [sym-mem]
        instr-addr = "0x6ba"
        module-name = "double_dereference_32"
        expr = "(ebp-0x1c+4*(ebp-0x2c+4*(ebp-0x34,4),4),4)"
```

**[[table]]**

Таблица для опции должна содержать адрес (`hex-address`, в виде строки, содержащей число в 16-ричной системе счисления) и размер (`length`, в виде строки, содержащей число в 10-тичной или 16-ричной системе счисления) таблицы, в которой хранятся символьные адреса и jump-таблицы. Дополнительно может быть задано имя модуля, в котором находится таблица (`module`, в виде строки).

Например:

```toml
    [table]
        module = "symptr_linear2"
        hex-address = "0x920"
        length = "44"
```

**[[invert-branch]]**

Таблица для опции должна содержать адрес инструкции, на которой происходит ветвление (`addr`, в виде строки). Дополнительно может быть задано имя модуля инструкции (`module-name`, в виде строки).

Например:

```toml
    [[invert-branch]]
        addr = "0x80495c1"
        module-name = "multithread_sum_32"

    [[invert-branch]]
        addr = "0xdeadbeef"
        module-name = "multithread_sum_32"
```

**[[bad-chars]]**

Таблица для опции должна содержать номера символов или диапазоны символов в виде строк (`bad-chars`). Дополнительно может быть задано смещение в символьных входных данных в виде строк (`offset`).

Например:

```toml
    [bad-chars]
        bad-chars = "0x0-0x20"
        offset = "0x10"
```

или

```toml
    [bad-chars]
        bad-chars = "0x10"
```

**[[security]]**

Таблица для опции должна содержать логические значения по названиям чекеров.

Например:

```toml
    [security]
        zerodiv = true
        bounds = true
        null = true
        intoverflow = false
        intoverflow-inst = false
        intoverflow-func = false
        intoverflow-risk = false
        invalid-heap = true
        negsize = true
```

**Пример конфигурационного файла:**

```toml
    remove = true
    output-dir = "out"
    invert-n = 100

    sym-file = ["file_1", "file_2"]

    [sym-mem]
        instr-addr = "0x85c"
        expr = "v(rbp-8,16)"

    [invert-branch]
        addr = "0x9af"
        module-name = "sym_mem_buffer_64"

    [[bad-chars]]
        bad-chars = "0x0-0x20"

    [[bad-chars]]
        bad-chars = "0x7a-0xff"

    [security]
        zerodiv = true
        intoverflow = true
        intoverflow-inst = true
        invalid-heap = true
```

## Результаты работы инструмента

Все результаты сохраняются в директории, указанной в опции `-o`. Каждый набор
входных данных сохраняется в отдельной директории `input_idx`, где idx -
уникальный индекс условного перехода. Директория `input_idx` содержит все
символьные входы, сохраненные в виде файлов (`file_<inputName>`, `arg_<N>`,
`socket_<inputName>`, `stdin`, `env_<varName>`) и файл `trace` с траcсой
выполненных условных переходов для этого входного файла. Последний условный
переход в трассе инвертируется, относительно текущего выполнения (в файле он
записал уже выполненным в другую сторону). Если для одного пути исполнения
сгенерировано несколько наборов входных данных (их максимальное число задается
с помощью опции `--models`), то к именам файлов добавляется префикс с уникальным
индексом i: `i_file_<inputName>`, `i_arg_<N>` и т. д. Если была указана опция
`--fuzzmem`, то выходная директория также содержит `fuzzmem_idx` директории
с наборами входных данных, которые пытаются перебрать значения определенного
символьного адреса. Уникальный индекс idx для таких директорий не зависит от
индексов условных переходов.

При включенной опции `--optimistic` оптимистичные решения сохраняются в
директориях `optimistic_idx` и `strong_optimistic_idx`.

Дополнительно в выходной директории (`-o`) сохраняются изначальные данные,
полученные из стандартного потока ввода (`--sym-stdin`) и символьного сокета
(`--sym-socket`) в файлах `stdin` и `socket_<inputName>` соответственно.

Также в выходной директории сохраняется файл `stats.json`, который содержит
основную статистику о работе инструмента:

- `symbolic-branches` - общее число найденных символьных переходов
- `skipped-branches` - число пропущенных переходов, которые уже были
  инвертированы ранее (присутствуют в кэше) или из-за опции `--invert-branch`
- `inverted-branches` - число успешно инвертированных переходов
- `unresolved-branches` - число переходов, для которых не существует решения,
  чтобы их инвертировать
- `symbolic-addresses` - общее число найденных инструкций с символьными адресами
- `fuzzed-addresses` - число символьных адресов, к которым был применен фаззинг
  (опция `--fuzzmem`)
- `fuzz-address-models` - число моделей, сгенерированных во время фаззинга
  символьных адресов
- `optimistic` - число оптимистичных решений (только последнего условия)
- `strong-optimistic` - число оптимистичных решений с учетом вложенных вызовов
  функций и условных переходов
- `solving-time` - общее время (в миллисекундах), проведенное в решателе
- `sat` - число успешно решенных запросов к решателю
- `unsat` - число невыполнимых запросов к решетею
- `timeout` - число запросов к решателю, которые не уложились в тайм-аут
- `out-of-mem` - число запросов к решателю, которые не уложились в ограничение
по памяти
- `unknown` - число запросов, которые решатель не смог обработать

Следует отметить, что `sat` >= `inverted-branches`. Переход может являться
таблицей переходов. В таком случае у него могут быть несколько целевых адресов.

Содержимое файла `out/stats.json`:

    {"symbolic-branches":4,"skipped-branches":0,"inverted-branches":4,"unresolved-branches":0,
     "symbolic-addresses":1,"fuzzed-addresses":1,"fuzz-address-models":10,"optimistic":0,
     "strong-optimistic":0,"solving-time":654,"sat":14,"unsat":0,"timeout":0,"out-of-mem":0,"unknown":0}

Если указана опция `--path-predicate`, то проверяется выполнимость текущего пути
выполнения программы для проверки корректности работы символьного вычислителя.
Трасса условных переходов сохраняется в файле `path_predicate_trace`.

Если указана опция `--dump-smt`, то создаются соответствующие файлы с уравнениями
под названием `<predicate_idx>.smt2` в корне выходной директории. Индекс
соответствует индексу папки с входными данными. В файле с предикатом находится
набор формул для инвертирования последнего условного перехода из файла трассы.
Если опции `--dump-smt` и `--path-predicate` используются совместно, то также
сохраняются формулы для всего пути выполнения. Формулы могут быть напрямую
переданы SMT-решателю:

    $ z3 predicate_0.smt2

Опция `--trace` сохраняет трассу инструкций в корне выходной директории под
названием `instruction_trace`.

Также по умолчанию лог сохраняется в файл `sydr.log`.

Пример структуры файлов выходной директории:

    out/
    ├── input_0
    │   ├── file_input
    │   └── trace
    ├── input_1
    │   ├── file_input
    │   └── trace
    ├── input_2
    │   ├── file_input
    │   └── trace
    ├── input_3
    │   ├── file_input
    │   └── trace
    ├── instruction_trace
    ├── path_predicate.smt2
    ├── path_predicate_trace
    ├── predicate_0.smt2
    ├── predicate_1.smt2
    ├── predicate_2.smt2
    ├── predicate_3.smt2
    ├── stats.json
    └── sydr.log

Если указана опция `--flat`, то выходная директория будет иметь плоскую
структуру, никакие дополнительные файлы, кроме лога и статистики, сохранятся
не будут. К именам всех файлов добавляется `TAG` (по умолчанию тег пустой).
Файлы лога и статистики также сохраняются в выходной директории (если не указано
другого пути с помощью `--log-file`, `--stats-file`).

Пример структуры файлов выходной директории при использовании опции `--flat`:

    out/
    ├── sydr_tag_0
    ├── sydr_tag_1
    ├── sydr_tag_fuzzmem_0_0
    ├── sydr_tag_fuzzmem_0_1
    ├── sydr_tag_fuzzmem_0_2
    ├── sydr_tag_opt_2
    ├── sydr_tag_sopt_3
    ├── stats_tag.json
    └── sydr_tag.log

Содержимое файла трассы условных переходов `out/input_2/trace`:

    /opt/sydr/tests/synthetic/bin64/file_read:0x970->0x976
    /opt/sydr/tests/synthetic/bin64/file_read:0x97c->0x982
    /opt/sydr/tests/synthetic/bin64/file_read:0x988->0x98a

Содержимое файла с уравнениями `out/predicate_2.smt2`:

    (declare-fun file_file_2 () (_ BitVec 8))
    (define-fun ref!2 () (_ BitVec 8) file_file_2) ; Byte reference
    (define-fun ref!40 () (_ BitVec 8) (bvsub ref!2 (_ bv100 8))) ; CMP operation
    (define-fun ref!46 () (_ BitVec 1) (ite (= ref!40 (_ bv0 8)) (_ bv1 1) (_ bv0 1))) ; Zero flag
    (assert (not (= ref!46 (_ bv0 1))))
    (check-sat)
    (get-model)

Подробнее о языке SMT-LIBv2 можно почитать по
[ссылке](https://www.riseforfun.com/Z3/tutorial/guide).

## Типовые ошибки

**No symbolic branches** - не было обнаружено условных переходов, зависящих от
входных данных.

**Failed to disassemble instruction INSTRUCTION** - Capstone не смог
дизассемблировать инструкцию.

**Instruction is not supported: INSTRUCTION** - в Triton отсутствует символьная
трансляция для инструкции INSTRUCTION. Пожалуйста, сообщайте такие символьные
инструкции, которые встретились в реальных программах, разработчикам Sydr.

**Unsatisfiable path predicate** - предикат пути неразрешим. Данная ошибка
указывает на возможные ошибки в движке символьной интерпретации. **Пожалуйста,
сообщите о данной ошибке разработчикам Sydr.**

**Memory limit for Sydr exceeds the physical RAM on the machine** - предупреждение о
том, что указанное ограничение памяти превышает свободную память в системе (без учета
файла подкачки).

**Possibly not enough memory for solving: MEGABYTES Mb for N threads. Decreasing
the number of threads or increasing memory limit should help** - выделенной
инструменту памяти может быть недостаточно для корректной работы решателя. Данное
предупреждение указывает либо на слишком большое число рабочих потоков, либо на
слишком малое количество выделенной для работы инструмента памяти.

**Can't lookup module for address ADDR** - не удалось восстановить имя модуля.
Это никак не влияет на результат работы инструмента. Просто в трассе будет
отсутствовать имя модуля.

## Маски

Чтобы сделать символьным только часть входного файла можно использовать маски на
входные файлы. Для каждого символьного источника маска задается отдельно. Файл с
масками содержит в себе номера байтов или отрезки байтов, которые должны быть
символьными. Поддерживаются как десятичный, так и шестнадцатеричный способ
задания. Например, следующая маска на файл говорит, что байты во входном файле
0, 5, 6, 7, 100 и все байты из отрезка [160, 255] включительно символьные:

    0
    5-7
    0x64
    0xa0-0xff

## Предикаты безопасности

Чтобы проверить предикаты безопасности, надо запуститься с опцией `--security`.
Предикаты безопасности позволяют обнаружить ошибки, такие как
разыменование нулевого указателя, выход за границу массива, деление на нуль,
переполнение целочисленного типа или некорректная работа с кучей. Все
результаты сохраняются в директории, указанной в опции `-o`. Каждый набор
входных данных, приводящий к разыменованию нулевого указателя, выходу за левую
границу массива, делению на нуль или переполнению целочисленного типа сохраняется в отдельной директории `<null_deref_idx>`, `out_of_bounds_idx>`,
 `<div_by_zero_idx>` или `<int_overflow_idx>`
соответственно, где idx - порядковый номер набора входных данных для соответствующего предиката
безопасности.

Целочисленное переполнение бывает знаковым и беззнаковым. Входные данные для
знакового переполнения сохраняются в директории с суффиксом `signed`, для
беззнакового - `unsigned`. Если одновременно возможны оба типа переполнения на
одних входных данных, то суффикс знака будет отсутствовать.

При выходе за границу массива или разыменовании нулевого указателя может
выполняться условие write-what-where (CWE-123). Условие указывает на то, что
адрес и записываемое в память значение зависят от входных данных. В этом случае
входные данные будут сохранены в директории с суффиксом `www`.

Опция `--no-invert` позволяет запускаться без инвертирования переходов.

Примеры запусков с проверкой предикатов безопасности. Примеры можно
найти в директории `tests`:

    $ printf 'a%.0s' {1..72} > input && ./sydr --no-invert --dump-smt --security --sym-stdin \
        -- tests/synthetic/bin64/null_pointer_deref < input
    $ echo '4' > input && ./sydr --no-invert --dump-smt --security --sym-stdin \
        -- tests/synthetic/bin64/out_of_bounds_heap < input
    $ echo '4' > input && ./sydr --no-invert --dump-smt --security --sym-stdin \
        -- tests/synthetic/bin64/out_of_bounds_stack < input
    $ printf '1' > input && ./sydr --no-invert --dump-smt --security --sym-stdin \
        -- tests/synthetic/bin64/div_by_zero < input
    $ echo '\x02\x00\x00\x00\x08\x00\x00\x00' > input && ./sydr --no-invert --dump-smt \
        --security --sym-stdin -- tests/synthetic/bin64/int_overflow_branch < input
    $ echo '\x02\x00\x00\x00' > input && ./sydr --no-invert --dump-smt --security --sym-stdin \
        -- tests/synthetic/bin64/int_overflow_mem < input

Пример структуры файлов выходной директории при запуске с опциями `--security` и `--no-invert`:

    out/
    ├── instruction_trace
    ├── null_deref_0
    │   └── stdin
    ├── null_deref_1
    │   └── stdin
    ├── null_deref_1
    │   └── stdin
    ├── out_of_bounds_0
    │   └── stdin
    ├── out_of_bounds_1
    │   └── stdin
    ├── div_by_zero_0
    │   └── stdin
    ├── div_by_zero_1
    │   └── stdin
    ├── int_overflow_0_unsigned
    │   └── stdin
    ├── int_overflow_1_signed
    │   └── stdin
    ├── null_deref_predicate_0.smt2
    ├── null_deref_predicate_1.smt2
    ├── out_of_bounds_predicate_0.smt2
    ├── out_of_bounds_predicate_1.smt2
    ├── div_by_zero_predicate_0.smt2
    ├── div_by_zero_predicate_1.smt2
    ├── int_overflow_predicate_0_unsigned.smt2
    └── int_overflow_predicate_1_signed.smt2

## Эмуляция

Если в конфигурационном файле присутствует таблица `emu`, то выполнение целевой программы эмулируется символьным вычислителем.

Параметры эмуляции определены в файле конфигурации в таблице `emu`. Обязательно должны быть определены архитектура и начальное значение счётчика команд. В качестве дополнительных данных можно указать точки выхода, список регистров, области памяти, начальные отображения памяти и переходы.

Все числа для эмуляции в файле конфигурации должны быть записаны в виде строк, например `"0x123"`.

Архитектура определяется как базовое значение `arch`. Возможными вариантами архитектуры являются "x86", "x86-64", "arm32" и "aarch64".

Точки выхода содержатся в массиве с именем `exit`. Можно определить несколько точек выхода (например, `exit = ["0x8ac", "0x96a"]`).

Начальные значения регистров могут быть определены в таблице с именем `emu.registers` (префикс `emu.` означает, что эта таблица вложена в таблицу `emu`). Таблица регистров должна содержать значения желаемых регистров, ассоциированных с их названиями (например, `rax = "0x30"`). В этой таблице обязательно должно быть определено начальное значение счётчика команд (`rip`).

Области памяти описывают области виртуальной памяти, которые считаются известными (доступными) во время эмуляции. Регионы могут быть определены в массиве таблиц `emu.region`, каждая из которых должна быть описана отдельно. Каждая таблица области памяти должна содержать значения адреса виртуальной памяти региона (`vma`) и размера региона (`size`).

Начальные отображения памяти описывают области памяти, конкрентные значения которых хранятся в файлах. Эти значения могут использоваться во время эмуляции. Отображения могут быть определены в массиве таблиц `emu.memory`, каждая из которых должна быть описана отдельно. Каждая таблица отображения памяти должна содержать значения адреса виртуальной памяти, соответствующей отображению (`vma`), размера отображения (`size`), пути к файлу для получения конкретных значений памяти (`path`) и смещения в файле, с которого начинается отображение (`offset`).

Переходы описывают места в эмулируемой программе, которые будут пропущены при выполнении. Они содержат адрес первой инструкции, которая будет пропущена, и информацию, которая будет конкретизирована на этом этапе программы (например, чтобы пропустить вызов `fgets`, потребуется определить адрес инструкции `call`, конкретизировать по крайней мере значение регистра `rip/eip` и область памяти, в которой `fgets` будет хранить считанную строку).

Переходы могут быть определены в массиве таблиц `emu.transition`, каждая из которых должна быть описана отдельно. Каждая таблица переходов обязательно должна содержать значение адреса инструкции, начиная с которой фрагмент программы будет пропущен (`point`). В качестве дополнительных данных могут быть определены значения регистров, информация о файлах для конкретизации областей памяти и буферы символьной памяти перехода.

Значения регистров перехода могут быть определены в таблице `emu.transition.registers` в том же формате, что и таблица начальных значений регистров.

Информация о конкретизируемых областях памяти перехода может быть определена в массиве таблиц `emu.transition.memory`, каждая из которых должна быть описана отдельно. Каждая такая таблица либо может быть описана в том же формате, что и начальные таблицы отображений памяти, либо может содержать адресное выражение (`expr`) вместо `vma` и `size` в том же формате, что и параметр MEMORY_ACCESS для опции `sym-mem`.

Буферы символьной памяти перехода описывают буферы, содержащие символьные данные. Они могут быть определены в массиве таблиц `emu.transition.symbolize`, каждая из которых должна быть описана отдельно. Каждая таблица буфера символьной памяти может быть описана либо адресом буфера (`vma`) и его размером (`size`), либо адресным выражением (`expr`) в том же формате, что и параметр MEMORY_ACCESS для опции `sym-mem`.

**Пример файла конфигурации для эмуляции**

Тестовая программа cruehead64 - это программа-CrackMe, в которой по пользовательским значениям логина и пароля производятся вычисления, приводящие к успешному или неуспешному результату. На успешный результат указывает присутствие в стандартном потоке вывода сообщения "Now try the next CrackMe!", на неуспешный - "No luck there, mate!". Цель инструмента Sydr заключается в достижении успешного результата выполнения этой программы путём подбора подходящего к заданному логину пароля.

Файл конфигурации для тестовой программы cruehead64:

```toml
    remove = true
    log-level = "trace"

    [[bad-chars]]
        bad-chars = "0x71-0xff"

    [[bad-chars]]
        bad-chars = "0x0-0x20"

    [emu]
        arch = "x86-64"
        exit = ["0x4007CB"]

        [emu.registers]
            rip = "0x400627"
            rbp = "0x7fffffffdec0"
            rsp = "0x7fffffffdec8"
            fs = "0x0"

        [[emu.region]] # stack
            vma = "0x7fffffffde60"
            size = "0x70"

        [[emu.memory]] # fs:0x28
            path = "./input_cruehead"
            vma = "0x28"
            size = "0x8"
            offset = "0x20"
            # 0xbfef1dbdbfefbdbf

        [[emu.memory]] # .text
            path = "./cruehead64"
            vma = "0x400540"
            size = "0x302"
            offset = "0x540"

        [[emu.memory]] # .bss
            path = "./cruehead64"
            vma = "0x601050"
            size = "0x10"
            offset = "0x1048"

        [[emu.memory]] # .data
            path = "./cruehead64"
            vma = "0x601038"
            size = "0x10"
            offset = "0x1038"

        [[emu.transition]] # puts() "Login:"
            point = "0x40066F"
            [emu.transition.registers]
                rip = "0x400674"

        [[emu.transition]] # fgets(): read login
            point = "0x400687"
            [emu.transition.registers]
                rip = "0x40068c"
            [[emu.transition.memory]] # "Andrey"
                path = "./input_cruehead"
                expr = "v(rbp-0x30,7)"
                offset = "0x0"

        [[emu.transition]] # strlen() of login
            point = "0x400693"
            [emu.transition.registers]
                rax = "0x7"
                rip = "0x400698"

        [[emu.transition]] # puts() "\nPassword:"
            point = "0x400717"
            [emu.transition.registers]
                rip = "0x40071c"

        [[emu.transition]] # fgets(): read password
            point = "0x40072F"
            [emu.transition.registers]
                rip = "0x400734"
            [[emu.transition.memory]] # "123456"
                path = "./input_cruehead"
                expr = "v(rbp-0x20,7)"
                offset = "0x7"
            [[emu.transition.symbolize]]
                expr = "(rbp-0x20,6)"

        [[emu.transition]] # strlen() of password
            point = "0x40073B"
            [emu.transition.registers]
                rax = "0x7"
                rip = "0x400740"

        [[emu.transition]] # good input puts()
            point = "0x40079E"
            [emu.transition.registers]
                rip = "0x4007a3"

        [[emu.transition]] # bad input puts()
            point = "0x4007AC"
            [emu.transition.registers]
                rip = "0x4007b1"
```

В приведённом файле конфигурации указаны требуемая архитекура (`"x86-64"`), точка выхода (`0x4007CB`), заданы начальные значения регистров `rip`, `rbp`, `rsp`, `fp`, определён регион памяти для стека, заданы отображения памяти и переходы. За символом `#` следуют комментарии для лучшего понимания файла.

Регион памяти для доступа к стеку задан своим адресом и размером. Это означает, что диапазон адресов `0x7fffffffde60 - 0x7fffffffded0` будет доступен для чтения и записи во время эмуляции.

В файле заданы следующие отображения памяти: память, где располагается "канарейка" (`fs:0x28`, отображается из файла `input_cruehead`), отображения секций `.text`, `.bss` и `.data` (из файла `cruehead64`). Эти отображения позволяют считать содержимое "канарейки" (`fs:0x28`, в комментарии после описания этого отображения приведено содержимое памяти), читать программные инструкции по заданным адресам (секция `.text`), обращаться к инициализированным и неинициализированным пользовательским данным (секции `.data` и `.bss`).

Переходы в приведённом файле позволяют пропустить вызовы функций стандартной библиотеки языка Си:

- вызовы функции `puts`, которая выводит на стандартный поток вывода содержимое переданной строки: для таких переходов указано значение регистра `rip`, которое будет установлено в результате применения переходов; это означает, что вызовы функции `puts` пропускаются без изменения остальных регистров и памяти, а также без пометки символьной памяти;
- вызовы функции `fgets`, которая считывает строку со стандартного потока ввода (в нашем случае - считывание логина и пароля): для таких переходов указаны значения регистра rip (что позволяет перейти к следующей инструкции после применения переходов), значения областей памяти (с помощью адресных выражений), в которые функция записала бы считанные строки (при применении переходов эти строки, находящиеся в файле `input_cruehead`, записываются в эти области "вручную"); для считывания пароля с помощью адресного выражения указаны адрес и размер буфера для пометки памяти (при выполнении перехода указанная область памяти будет помечена как символьная);
- вызовы функции `strlen`, которая возвращает длину переданной строки (для вычисления длин логина и пароля): для таких переходов указаны значения регистров rip (что позволяет перейти к следующей инструкции после применения переходов) и rax (регистр, в котором передаётся возвращаемое из функции значение).

Для каждого перехода указан адрес инструкции, на которой переход должен быть применён. При задании отображения памяти или буфера для пометки памяти с помощью адресного выражения нужно помнить, что подстановка значений регистров и памяти происходит непосредственно в момент применения перехода.

Для запуска рассмотренной тестовой программы можно использовать следующую строку запуска:

    $ ./sydr --config tests/synthetic/bin64/cruehead_64.toml

Опция `--bad-chars` используется для подбора легко отображаемого и копируемого пароля (например, `-MK9!i`). Для проверки успешности подбора пароля можно создать файл, записать в него логин и подобранный пароль, а затем запустить тестовую программу, используя сформированный файл как входные данные:

    $ echo "Andrey" > out/input_0/input
    $ cat out/input_0/mem_0 >> out/input_0/input
    $ echo -n -e "\n" >> out/input_0/input
    $ ./tests/synthetic/bin64/cruehead64 < out/input_0/input

**Запуск эмуляции**

Во время эмуляции символьный вычислитель пытается интерпретировать инструкции программы. В качестве начального значения счётчика команд берётся значение, определённое в файле конфигурации.

На каждой итерации цикла эмуляции выполняется следующий набор действий:

- применяется переход (если существует переход по текущему адресу инструкции);
- эмуляция прекращается, если достигнута точка выхода;
- происходит пометка символьного буфера памяти, определенного в опциях (если адрес инструкции совпадает с адресом в опции);
- инструкция интерпретируется.

**Внимание!** Переходы являются наиболее приоритетными действиями в цикле; переходы и точки выхода не должны соответствовать одному и тому же адресу.

Эмуляция может быть прервана в нескольких случаях:

- достижение точки выхода;
- невозможность прочитать инструкцию по текущему адресу из-за невалидной памяти;
- ошибка при дизассемблировании инструкции.

Если указана опция `-m`, то эмуляция, кроме основных случаев, может быть прервана из-за ограничения по памяти для символьного вычислителя. Если указана опция `--invert-n`, то эмуляция, кроме основных случаев, может быть прервана из-за ограничения количества инвертированных ветвей.

Если указана опция `-b` (`--invert-branch`), то конкретная ветвь будет инвертирована, если это возможно. Если указана опция `--bad-chars`, то сгенерированные входные данные не будут содержать указанных символов.

После того как эмуляция прерывается, Sydr переходит к инвертированию переходов. Однако если эмуляция была прервана ошибкой при применении перехода, или ошибкой при пометке символьных буферов памяти, или произошло совпадение адреса инструкции перехода и точки выхода, то инвертирование переходов не происходит, Sydr завершает работу с ненулевым кодом возврата.

**Примеры эмуляции**

Чтобы запустить Sydr с эмуляцией, нужно использовать опцию `--config` с соответствующим файлом конфигурации. **Внимание!** Символьная память должна быть определена либо с помощью опции `--sym-mem`, либо по крайней мере в одном из описаний переходов в файле конфигурации.

Примеры запуска Sydr с эмуляцией:

    $ ./sydr --config tests/synthetic/bin64/cruehead_64.toml
    $ ./sydr -l trace -r --sym-mem "0x804863a,(ebp-0x1c,6)" \
        --config tests/synthetic/bin32/cruehead_32.toml \
        --bad-chars "0x7a-0xff" --bad-chars "0-0x20"
    $ ./sydr -l trace -r --sym-mem "0x55555555480d,(rbp-0x20,6)" \
        --config tests/synthetic/bin64/emulation_function_call_64.toml \
        --bad-chars "0x7a-0xff" --bad-chars "0-0x20"
    $ ./sydr -l trace -r --sym-mem "0x565556a4,(ebp-0x1c,6)" \
        --config tests/synthetic/bin32/emulation_function_call_32.toml \
        --bad-chars "0x7a-0xff" --bad-chars "0-0x20"
    $ ./sydr -l trace -r --config tests/synthetic/bin32/emulation_fp_32.toml \
        --bad-chars "0x7a-0xff" --bad-chars "0-0x20"
    $ ./sydr --sym-mem "0x400548,(x0,6)" \
        --config tests/synthetic/bin64/cruehead_aarch64.toml
    $ ./sydr --sym-mem "0x1044c,(r0,6)" \
        --config tests/synthetic/bin32/cruehead_arm32.toml

## Рекомендации к применению и ограничения

Анализируемую программу необходимо собирать без санитайзеров, т.к. динамический
инструментатор DynamoRIO использует собственный загрузчик, который не
поддерживает работу санитайзеров.

Sydr работает только на 64-битной ОС. Однако он поддерживает запуск как
32-битных, так и 64-битных программ. Triton не поддерживает инструкции,
работающие с числами с плавающей точкой, поэтому символьная интерпретация таких
инструкций пропускается.

Sydr не отслеживает передачу данных между разными процессами.

Рекомендуется не использовать сложные арифметические вычисления над входными
данными (например, криптографические алгоритмы) в анализируемой части программы.
По возможности не стоит встраивать в анализируемую программу избыточные
преобразования над входными данными (например, конвертацию числа в строку).

Рекомендуется использовать параллельное инвертирование переходов (опция `-j`).
При этом следует внимательно следить за потребляемой памятью, т.к. символьная
интерпретация требовательна к памяти. Следует выбирать оптимальное число
потоков, чтобы оперативной памяти хватало. Число потоков зависит от
анализируемой программы, поэтому стоит экспериментально прикинуть число потоков
для конкретной программы. Число потоков должно быть не больше числа ядер на
машине. Но желательно не меньше 4 потоков.

Для файлов объемом более 1 Мб рекомендуется использовать маски на файлы.

Чтобы проверить, что Вы все правильно делаете, можно сделать пробный запуск
и убедиться, что генерируются новые входы. Если новые файлы не
генерируются, то с опцией `-l debug` можно убедиться, что происходит пометка
входных данных (`ReadSymbolicInput`), а также обратить внимание на число
символьных переходов.

Сгенерированные подтверждения ошибок от предикатов безопасности желательно
проверять на программе, собранной с санитайзерами. Например, деление на нуль
чисел с плавающей точкой не приводит к аварийному завершению программы,
собранной без санитайзеров. Верификация найденных предикатами безопасности
ошибок на санитайзерах реализована в `sydr-fuzz security`.

UNSAT (невыполнимый) запросы возникают при анализе всех реальных программ и
могут быть связаны с:

- Несовместностью путей исполнения: `if (a > 5) { if (a < 5) {/*incompatible path;*/} }`
- Невозможностью изменить путь исполнения в контексте пути. Например, условный
  переход, который зависит от входных данных, которые уже были ограничены в
  программе: `if (ch >= 0x20 && ch < 0x7f) { /*sat*/ } if (ch == 0x7f) { /*unsat*/ }`.
  Однако переход `ch == 0x7f` может быть успешно пройден с использованием опции
  `--optimistic`.
- Неточностью символьной интерпретации, связанной с неявными зависимостями в
  коде (доступ по символьным указателям). Например, ограничение для
  `if (a[input[0] % len] == '!')` не будет добавлено, т.к. символьное значение
  `input[0] % len` при разыменовании `a[input[0] % len]` будет конкретизовано.

Предикаты безопасности замедляют работу инструмента, поэтому лучше инвертировать
переходы во время фаззинга без опции `--security`. Потом уже можно будет
на хорошем корпусе запуститься с опциями `--security`, `--no-invert` и `--cache`
только для проверки предикатов безопасности. Настоятельно рекомендуется использовать
опцию `--cache` для пропуска дублирующихся ошибок. Рекомендуется использовать
`sydr-fuzz security`, который уже реализует подобный механизм.

На фаззинг лучше запускать Sydr c опцией `--solving-limit`, которая ограничивает
суммарное время, проведенное в решателе,
для равномерной по времени работы Sydr с разными входными данными.
Использование кэша `--cache` позволяет пропустить инвертирование тех переходов,
которые уже несколько раз встречались в процессе анализа и были обработаны. Также
рекомендуется использовать опцию `--optimistic`, которая позволяет попытаться
неточно инвертировать переход, когда это не удается сделать с учетом всего пути.
Таким образом, суммарное число успешно инвертированных переходов становится
больше. Описанные в этом абзаце опции автоматически подставляются в sydr-fuzz.

Для символьной интерпретации сложных программ может иметь смысл
ограничивать размер
используемой формулами памяти (`-m`). Если в логах Sydr заметно много запросов с
TIMEOUT, а покрытие растет медленно, то можно попробовать увеличить тайм-аут на
один запрос к решателю (`--solving-timeout`).

Обработка чтений из памяти по символьным адресам включается с помощью опции
`--symbolize-address`. При анализе символьных адресов увеличивается общее число
помеченных инструкций, вследствие чего растет потребление памяти, SMT-формулы
становятся сложнее, а время символьной интерпретации программы может возрастать
в несколько раз. Включение данного режима позволяет найти новые символьные переходы
и увеличить покрытие программы по базовым блокам, но в некоторых случаях, вследствие
изменений символьной модели программы, часть символьных переходов может пропускаться.
Поэтому анализ программ рекомендуется проводить в несколько этапов: обычный запуск
Sydr и дополнительный запуск с включенной обработкой символьных адресов (чтобы повторно
не открывать одни и те же пути, рекомендуется использовать кэш `--cache` между запусками).
Анализ символьных адресов можно настроить с помощью дополнительных параметров. Опция
`--max-table-size` позволяет задать максимальное число элементов в таблице, чтобы
ограничить размер возможной области символьного доступа. С помощью опции `--table`
возможно указать таблицы с уже известным расположением в памяти. Тогда символьный доступ
внутри описанной области памяти будет ограничен ее пределами. Опции `--table` и
`--max-table-size` позволяют также настроить анализ табличных переходов, которые,
в отличие от символьных адресов, включены всегда.

Фаззинг символьных адресов включается с помощью опции `--fuzzmem` и является более
легковесным анализом адресных зависимостей, чем `--symbolize-address`. В данном режиме
для каждого символьного адреса с помощью SMT-решателя подбирается заданное число
наборов входных данных, которые изменяют текущее значение этого адреса. Так как для каждого
символьного адреса может быть сгенерировано большое число входных данных (несколько тысяч
и больше), то рекомендуется ограничить число генерируемых моделей в разумных пределах,
например, 100 моделей или меньше. Также рекомендуется использовать кэш `--cache`, чтобы
избежать повторной генерации моделей для одних и тех же символьных адресов.
Также стоит ограничить общее число генерируемых за один запуск Sydr fuzzmem-моделей c
помощью опции `--fuzzmem-models`. Ограничение в 1000 моделей поможет сделать гибридный
фаззинг более сбалансированным. Фаззинг символьных адресов автоматически
включается в sydr-fuzz.

## Скрипт, аннотирующий выходные файлы Sydr

Данный скрипт заменяет шестнадцатеричные адреса в логе, трассе переходов или
трассе инструкций на номера строчек и имена функций.

### Использование

    $ scripts/annotate.py --help
    usage: annotate.py [-h] [-s] [--security] input output

    Annotate Sydr output files with line numbers/files and function names.

    positional arguments:
      input       Sydr log or trace file.
      output      Annotated output file.

    optional arguments:
      -h, --help  show this help message and exit
      -s, --skip-libc  Skip libc for speedup.
      --security       Annotate just security logs.

Пример запуска:

    $ ./sydr -t --sym-argv -- tests/synthetic/bin64/argv good!
    $ scripts/annotate.py out/input_3/trace out/input_3/trace.out
    $ scripts/annotate.py out/sydr.log out/sydr.log.out
    $ scripts/annotate.py out/instruction_trace out/instruction_trace.out

# Статьи и презентации

1. Vishnyakov A., Fedotov A., Kuts D., Novikov A., Parygina D., Kobrin E.,
   Logunova V., Belecky P., Kurmangaleev Sh. Sydr: Cutting Edge Dynamic Symbolic
   Execution. 2020 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE, 2020, pp.
   46-54. DOI: 10.1109/ISPRAS51486.2020.00014
   \[[статья](https://arxiv.org/abs/2011.09269)\]
   \[[слайды](https://vishnya.xyz/vishnyakov-isprasopen2020.pdf)\]
   \[[видео](https://www.ispras.ru/conf/2020/video/compiler-technology-11-december.mp4#t=6021)\]
2. Федотов, А. Н., Курмангалеев, Ш. Ф. (2020).
   CASR: анализ coredump файлов в ОС Linux и составление отчётов об ошибках.
   Труды Института системного программирования РАН, 32(4).
   \[[статья](https://www.researchgate.net/publication/346176971)\]
3. Kuts D. Towards Symbolic Pointers Reasoning in Dynamic Symbolic Execution.
   2021 Ivannikov Memorial Workshop (IVMEM), IEEE, 2021.
   \[[статья](https://arxiv.org/abs/2109.03698)\]
   \[[слайды](https://vishnya.xyz/mirror/kuts-ivmem2021.pdf)\]
4. Vishnyakov A., Logunova V., Kobrin E., Kuts D., Parygina D., Fedotov A.
   Symbolic Security Predicates: Hunt Program Weaknesses. 2021 Ivannikov ISPRAS
   Open Conference (ISPRAS), IEEE, 2021.
   \[[статья](https://arxiv.org/abs/2111.05770)\]
   \[[слайды](https://vishnya.xyz/vishnyakov-isprasopen2021.pdf)\]
   \[[видео](https://youtu.be/CI-Zioq5G84?t=6583)\]
5. Savidov G., Fedotov A. Casr-Cluster: Crash Clustering for Linux Applications.
   2021 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE, 2021.
   \[[статья](https://arxiv.org/abs/2112.13719)\]
   \[[слайды](https://vishnya.xyz/mirror/casr-cluster.pdf)\]
6. Кобрин И.А., Вишняков А.В., Федотов А.Н. Гибридный фаззинг фреймворка
   машинного обучения TensorFlow. МиТСОБИ 2022.
   \[[слайды](https://vishnya.xyz/kobrin-mitsobi2022.pdf)\]
7. Вишняков А.В., Кобрин И.А., Федотов А.Н. Поиск ошибок в бинарном коде
   методами динамической символьной интерпретации. Труды Института системного
   программирования РАН, 34(2), 2022, c. 25-42.
   \[[статья](https://ispranproceedings.elpub.ru/jour/article/view/1512/1346)\]
   \[[слайды](https://vishnya.xyz/vishnyakov-mitsobi2022.pdf)\]
8. Федотов А. Sydr: Технология динамического анализа. Пленарная сессия IVMEM 2022.
   \[[слайды](https://sydr-fuzz.github.io/papers/fedotov-plenum-sydr-ivmem2022.pdf)\]
   \[[видео](https://youtu.be/L7ZRV2Voee4?t=5652)\]
9. Федотов А. SDL в искусственном интеллекте. Пленарная сессия IVMEM 2022.
   \[[слайды](https://sydr-fuzz.github.io/papers/fedotov-plenum-sdlai-ivmem2022.pdf)\]
   \[[видео](https://youtu.be/L7ZRV2Voee4?t=7658)\]
10. Parygina D., Vishnyakov A., Fedotov A. Strong Optimistic Solving for Dynamic
   Symbolic Execution. 2022 Ivannikov Memorial Workshop (IVMEM), IEEE, 2022.
   \[[статья](https://arxiv.org/abs/2209.03710)\]
   \[[cлайды](https://sydr-fuzz.github.io/papers/parygina-ivmem2022.pdf)\]
   \[[видео](https://youtu.be/L7ZRV2Voee4?t=14710)\]
11. Федотов А. Sydr: Гибридный фаззинг. Круглый стол по безопасной разработке ПО
   IVMEM 2022.
   \[[cлайды](https://sydr-fuzz.github.io/papers/fedotov-cybersec-ivmem2022.pdf)\]
12. Федотов А. Sydr & CASR: Динамический анализ для SDL. Разработка доверенного
    ПО ISP RAS Open 2022.
   \[[слайды](https://sydr-fuzz.github.io/papers/fedotov-cybersec-isprasopen2022.pdf)\]
13. Федотов А. Разработка доверенных версий фреймворков машинного обучения.
    Системы доверенного ИИ ISP RAS Open 2022.
   \[[слайды](https://sydr-fuzz.github.io/papers/fedotov-sdlai-isprasopen2022.pdf)\]
   \[[видео](https://youtu.be/4SglZ8f4R5k?t=7684)\]
14. Vishnyakov A., Kuts D., Logunova V., Parygina D., Kobrin E., Savidov G.,
   Fedotov A. Sydr-Fuzz: Continuous Hybrid Fuzzing and Dynamic Analysis for
   Security Development Lifecycle. 2022 Ivannikov ISPRAS Open Conference
   (ISPRAS), IEEE.
   \[[статья](https://arxiv.org/abs/2211.11595)\]
   \[[слайды](https://vishnya.xyz/vishnyakov-isprasopen2022.pdf)\]
   \[[видео](https://youtu.be/qw_tzzgX04E?t=16813)\]
