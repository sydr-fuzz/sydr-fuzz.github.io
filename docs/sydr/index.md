# Sydr: Symbolic DynamoRIO

* TOC
{:toc}

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
  проверяет выполнимость формул, для выполнимых формул предоставляет модель
  (набор значений переменных, при которых формула выполнима)
- 1 уровень: динамический инструментатор
  [DynamoRIO](https://github.com/DynamoRIO/dynamorio) выполняет программу,
  детектирует системные вызовы, предоставляет выполнявшиеся инструкции,
  значения регистров и памяти

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
                                            allocation and string functions; trunc 
                                            - numeric truncation error;
                                            injection - OS command injection;
                                            format - controlled format string
                                            injection.

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
работающих со строками или динамической памятью; `trunc` - целочисленное усечение,
которое происходит при присваивании значения в переменную меньшего размера;
`injection` - инъекция в системные вызовы для исполнения команд; `format` -
контролируемая модификация коммандной строки в функциях форматированного
вывода; `all` - проверка всех предикатов безопасности (по умолчанию).

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
        trunc = true
        invalid-heap = true
        negsize = true
        injection = true
        format = true
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

## Утилита, аннотирующая выходные файлы Sydr

Данная утилита заменяет шестнадцатеричные адреса в логе, трассе переходов или
трассе инструкций на номера строчек и имена функций.

### Использование

    $ sydr-annotate -h
    Annotate log files produced by Sydr using addr2line rust crate

    USAGE:
        sydr-annotate [OPTIONS] <INPUT> <OUTPUT>

    ARGS:
        <INPUT>     Log file to annotate
        <OUTPUT>    Where to save annotated log file

    OPTIONS:
        -h, --help                 Print help information
        -l, --log-level <LEVEL>    Logging level [default: info] [possible values: minimal,
                                   info, debug, trace]
            --security             Annotate only security results
            --skip-libc            Do not annotate locations inside libc
        -V, --version              Print version information

Пример запуска:

    $ ./sydr -t --sym-argv -- tests/synthetic/bin64/argv good!
    $ ./sydr-annotate out/input_3/trace out/input_3/trace.out
    $ ./sydr-annotate out/sydr.log out/sydr.log.out
    $ ./sydr-annotate out/instruction_trace out/instruction_trace.out
