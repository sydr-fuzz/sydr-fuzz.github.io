## Создание фаззинг целей

* TOC
{:toc}

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

При использовании libFuzzer с [LPM](https://github.com/google/libprotobuf-mutator?tab=readme-ov-file#integrating-with-libfuzzer) в обертке с помощью
макроса `DEFINE_PROTO_FUZZER` предлагается реализовать функцию `TestOneProtoInput`, которая
получает в качестве входных данных protobuf-сообщение. Поэтому перед вызовом целевой функции
обертка дополнительно должна осуществлять его [преобразование к соответствующему формату](https://chromium.googlesource.com/chromium/src/+/main/testing/libfuzzer/libprotobuf-mutator.md#Write-the-Fuzz-Target-and-Conversion-Code).

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

### Обертка Honggfuzz

Для Honggfuzz написание отдельной обертки не требуется, можно полностью использовать
код обертки Sydr или libFuzzer. Отличие заключается только в сборке с другой инструментацией.

Honggfuzz поддерживает получение входных данных для обертки из файла и из стандартного
потока ввода. Если используется файл, то в строке запуска фаззинг-цели путь до файла
нужно заменить символом `___FILE___`. При использовании стандартного потока ввода
фаззеру нужно указать опцию `--stdin_input|-s`.

Honggfuzz позволяет проводить фаззинг без какой-либо обратной связи (режим черного
ящика), для этого можно указать `--noinst|-x` в аргументах. В таком случае можно взять
уже собранную под Sydr обертку. В этом режиме фаззинг не сохраняет новые данные в корпус,
и может быть использован только для поиска ошибок, при этом отсутствие санитайзеров
в сборке сводит вероятность нахождения ошибок к минимуму.

Чтобы собрать обертку с инструментацией фаззера, при сборке цели нужно
использовать компиляторы, поставляемые вместе с Honggfuzz: `hfuzz-clang`/`hfuzz-clang++`,
`hfuzz-cc`/`hfuzz-c++`. Также при сборке нужно указать санитайзеры и опцию
для дебаг-информации:

`-g -fsanitize=address,bounds,integer,undefined,null,float-divide-by-zero`

В аргументах фаззеру можно указать опцию `--instrument|-z` для фаззинга с обратной
связью по покрытию, основанной на инструментации (опция необязательна - фаззер обнаруживает
инструментацию автоматически). Помимо обратной связи от программной инструментации,
Honggfuzz также может получать обратную связь от аппаратной части (BTS, Intel PT). Для этого
нужно указать опции `--linux_perf_bts_edge`, `--linux_perf_ipt_block`, `--linux_perf_instr`,
`--linux_perf_branch`. Поробнее об инструментации фаззинг целей Honggfuzz написано
[здесь](https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md).

Рекомендуется собирать обертку для работы в Persistent mode (опция `--persistent|-P`).
В этом режиме Honggfuzz будет фаззить цель много раз в одном процессе,
вместо того чтобы создавать каждый раз процесс заново, что ускоряет фаззинг
в несколько раз. Для сборки оберток Honggfuzz в Persistent mode можно
воспользоваться оберткой для libFuzzer. Для этого стоит собирать библиотеку
и обертку компиляторами `hfuzz-*`. При этом дополнительно (кроме санитайзеров
и дебаг информации) никаких флагов указывать не нужно.
Для использования Persistent mode без libFuzzer-обертки можно использовать символ
`HF_ITER`. Подробнее об использовании Persistent mode написано в
[документации](https://github.com/google/honggfuzz/blob/master/docs/PersistentFuzzing.md).

### Обертка LibAFL-DiFuzz

Для LibAFL-DiFuzz написание отдельной обертки не требуется, можно полностью использовать
код обертки для Sydr или libFuzzer. Отличие заключается только в сборке с другой инструментацией.

LibAFL-DiFuzz поддерживает получение входных данных для обертки из файла или из стандартного
потока ввода. Если используется файл, то в строке запуска фаззинг-цели путь до файла
нужно заменить символом `@@`. При использовании стандартного потока ввода
ничего указывать не нужно.

Чтобы собрать обертку для LibAFL-DiFuzz, рекомендуется использовать наш шаблон сборки и
утилиту `get_target.py`, позволяющую сгенерировать шаблон с нужными именами и путями до файлов.
Шаблон можно модифицировать, добавляя в `Makefile.toml` свои скрипты, некоторые
аргументы статического инструментатора `DiFuzz` (`DiFuzz-Rust`, `DiFuzz-Go`), а также можно менять
задачи `[tasks.debug_unix]`, `[tasks.coverage_unix]` и `[tasks.casr_unix]` для сборки оберток для дебага,
покрытия и анализа аварийных завершений, соответственно.
Крайне не рекомендуется менять уже заданные аргументы для всех утилит, менять в задачах
`[tasks.target_unix]` и `[tasks.difuzz_unix]` что-либо, кроме пути до скрипта сборки проекта.
В противном случае могут возникать ошибки при сборке обертки или самого фаззера.
Чтобы собрать необходимые бинарные файлы, нужно запустить в директории, где лежит `Makefile.toml`,
следующий скрипт:
```bash
$ LIBAFL_DIR="/path/to/libafl" cargo make target
```
Если нужно собрать всё для полного пайплайна (запуск, покрытие, анализ аварийных завершений), нужно запустить:
```bash
$ LIBAFL_DIR="/path/to/libafl" cargo make all
```
Цель для фаззинга, покрытия и отладки и вспомогательный файл `ets.toml` будут лежать в
той же директории, что и `Makefile.toml`. Если нужно, чтобы цель находилась в другой директории, нужно запустить:
```bash
$ LIBAFL_DIR="/path/to/libafl" OUT_DIR="/out/dir" cargo make all
```
Тогда цели будут находиться в указанной `OUT_DIR` директории.

Если требуется собрать обертку, не используя `Makefile.toml` из шаблона, то необходимо будет собрать
две фаззинг цели с разными инструментациями (для статического анализа и для фаззинга).

Для `C`/`C++` проектов первую фаззинг цель (для анализа) нужно собрать с помощью компилятора `wllvm`/`wllvm++`
и далее проанализировать инструментом `DiFuzz`.

Для `Rust` нужно собрать цель, добавив в `RUSTFLAGS` опции `--emit=llvm-bc -C debuginfo=2 -C debug-assertions=yes -C opt-level=0`,
объединить сгенерированные `target/debug/*.bc` файлы в один с помощью утилиты `llvm-link-18` и проанализировать итоговый `.bc`
файл инструментом `DiFuzz-Rust`.

Для `Go` заранее собирать цель не требуется. Вместо этого для анализа инструменту `DiFuzz-Go` нужно указать путь до `.go` обертки,
содержащей функцию `main` (обертка обязательно должна лежать внутри директории проекта и в директории этой обертки не должно быть
других `.go` файлов с функцией `main`).

На выходе будет создан файл `ets.toml` который далее передается на вход к `ETSSharedManager` (через опцию `-i`) и
который впоследствии будет передаваться фаззеру (через опцию `-e`). Чтобы собрать вторую цель, нужно сначала
запустить `ETSSharedManager` один раз с опцией `-a create` и затем с `-a parse` (дав на вход `-i /path/to/in/ets.toml`
и на выход `-o /path/to/out/ets.toml`).

После этого для `C`/`C++` проектов нужно добавить в коде фаззинг цели в функцию `main` следующее:

```c
extern void libafl_start_forkserver(void);
// Для C++ extern "C" void libafl_start_forkserver(void);

int main(int argc, char **argv) {
    __AFL_INIT();
    ...
}
```

Затем необходимо собрать фаззинг цель с помощью компилятора `libafl_cc` (`libafl_cxx`).

Для `Rust` проектов нужно добавить в коде фаззинг цели в функцию `main` следующее:

```rust
fn main() -> Result<()> {
    extern "C" { fn libafl_start_forkserver(); }
    unsafe { libafl_start_forkserver(); }
    ...
}
```

Затем необходимо собрать фаззинг цель с помощью компилятора `libafl_rustc`. Пример команды сборки:

```bash
$ LIBAFL_SHARED_NAME="project" LIBAFL_PROJECT_DIR="/path/to/project" RUSTC=/path/to/rust-difuzz/bin/libafl_rustc cargo build
```

После сборки нужно запустить `ETSSharedManager` еще раз с опциями `-a dump` и `-a remove`.

Для `Go` не требуется добавлять ничего в код фаззинг цели. На этапе инструментации все необходимые вызовы
служебных функций и импорты библиотек будут вставлены в код автоматически. Сначала нужно проинструментировать проект
с помощью `goinstr_difuzz`:

```bash
$ goinstr_difuzz -i /path/to/project -e /path/to/ets.toml -a insert -l info -o /path/to/output/dir
```

Затем проинструментировать с помощью `goinstr_sancov`:

```bash
$ goinstr_sancov -i /path/to/project -a insert -l info -o /path/to/output/dir
```

В опции `-i` необходимо задать путь до директории анализируемого проекта, в котором должен лежать файл `go.mod`,
в `-e` путь до `ets.toml`, в `-o` путь до выходной директории, в которую будет скопирован весь инструментированный проект с
таким же именем с приставкой `-instr` к исходному имени директории. Если директория `/path/to/output/dir/project-instr` уже
существует, то она будет удалена и перезаписана. Но если сначала проинструментировать проект через `goinstr_difuzz`, а затем
через `goinstr_sancov`, `goinstr_sancov` не удалит директорию `/path/to/output/dir/project-instr`, а просто проинструментирует ее.
После инструментации цель для фаззинга можно собирать через `go build`, добавив в переменную окружения `CGO_LDFLAGS` опцию линковки
`-L/path/to/libforkserver_dir` с путем до библиотеки `libforkserver`. Например:

```bash
$ cd /path/to/output/dir/project-instr
$ CGO_LDFLAGS="-L/path/to/libforkserver_dir" go build path/to/main.go
```

В результате будет собрана цель для фаззинга и получен файл `ets.toml`, которые далее можно
использовать в конфигурационном файле для запуска через Sydr-fuzz.

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

### Обертка Jazzer

Для подготовки обертки можно воспользоваться
[гайдом OSS-Fuzz](https://google.github.io/oss-fuzz/getting-started/new-project-guide/jvm-lang/).
В простейшем случае необходимо реализовать класс с именем `*Fuzzer`, без
директивы `package` в заголовке файла. В самом классе должен быть реализован
статический метод `fuzzerTestOneInput(byte[])` или `fuzzerTestOneInput(FuzzedDataProvider)`.
`FuzzedDataProvider` упрощает процесс создания обертки, преобразуя необработанные входные байты,
полученные от фаззера, в примитивные типы Java.

Для сборки обертки можно воспользоваться компилятором `javac`, которому
необходимо передать Java файл. Также в аргументе `-cp` (class path) могут быть
указаны пути до зависимостей. Например:

    $ javac -cp /usr/local/lib/jazzer_standalone_deploy.jar ExampleFuzzer.java

Для использования `FuzzedDataProvider` необходимо
в начало файла поместить строку `import com.code_intelligence.jazzer.api.FuzzedDataProvider;`
и при сборке указать путь до jazzer API, как это сделано в примере выше.

Если целевая библиотека содержит расширения на языках C/C++, рекомендуется
инструментация исходных файлов при сборкe библиотеки. Для этого требуется
использовать флаг `-fsanitize=address,fuzzer-no-link` при сборке C/C++ библиотек.
Более подробно об этом можно прочитать в
[документации](https://github.com/CodeIntelligenceTesting/jazzer/blob/main/docs/advanced.md)
Jazzer.

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;

public class ExampleFuzzer {
    public static void fuzzerTestOneInput(FuzzedDataProvider data) {
        ...
        // Call a function of the project under test with arguments derived from
        // data and throw an exception if something unwanted happens.
        ...
    }
}
```

### Обертка Jazzer.js

Для подготовки Jazzer.js обертки можно воспользоваться его
[документацией](https://github.com/CodeIntelligenceTesting/jazzer.js/blob/main/docs/fuzz-targets.md).
Требуется реализовать и экспортировать функцию `fuzz(data)`, которая принимает на
вход мутированный буфер и передает его в функцию, являющуюся целью фаззинга.

Поскольку исходный тип данных буфера (Buffer) является не слишком удобным представлением данных,
Jazzer.js предоставляет класс FuzzedDataProvider, позволяющий извлекать примитивные типы из буфера.
Для использования FuzzedDataProvider необходимо подключить модуль @jazzer.js/core в начале обертки.

Для корректной работы обертки требуется выдать ей права на выполнение с помощью
утилиты `chmod +x` и указать путь до интрепретатора npx с аргументом jazzer в начале обертки,
используя `#!`, например `#!/usr/bin/env -S npx jazzer`.

Если целевая библиотека содержит расширения на языках C/C++, рекомендуется
инструментация исходных файлов при сборкe библиотеки. Для этого требуется
использовать флаг `-fsanitize=address,fuzzer-no-link` при сборке.

```js
const { FuzzedDataProvider } = require("@jazzer.js/core");

module.exports.fuzz = function (fuzzerInputData) {
	const data = new FuzzedDataProvider(fuzzerInputData);
	const intParam = data.consumeIntegral(4);
	const stringParam = data.consumeString(4, "utf-8");
	myAwesomeCode(intParam, stringParam);
};
```

### Обертка Sharpfuzz

Для сборки обертки необходимо в новой созданной директории создать консольное
.NET приложение и добавить в него модуль `Sharpfuzz`:

    $ mkdir build_fuzz && cd build_fuzz
    $ dotnet new console
    $ dotnet add package SharpFuzz

Затем в файле `Program.cs` можно написать обертку под нужный фазз-таргет.
Для подготовки `Sharpfuzz` обертки можно воспользоваться его
[документацией](https://github.com/Metalnem/sharpfuzz/blob/master/README.md).
Требуется из функции Main вызвать функцию `Fuzzer.OutOfProcess.Run()`, в качестве
параметра которой нужно передать функцию, являющуюся целью фаззинга. Также
необходимо в начале обертки подключить модуль `Sharpfuzz`.

```c#
using System;
using System.IO;
using SharpFuzz;

namespace Jil.Fuzz
{
  public class Program
  {
    public static void Main(string[] args)
    {
      Fuzzer.OutOfProcess.Run(stream =>
      {
        try
        {
          using (var reader = new StreamReader(stream))
          {
            JSON.DeserializeDynamic(reader);
          }
        }
        catch (DeserializationException) { }
      });
    }
  }
}
```

В файле `build_fuzz.csproj` нужно связать обертку с модулем проекта. Для этого нужно либо
собрать сам проект (в директории проекта с помощью `dotnet build` или `dotnet publish`),
найти скомпилированный модуль `target_name.dll` (обычно лежит внутри директории `bin/`)
и указать путь до него в `build_fuzz.csproj` файле, либо можно указать путь до .csproj
файла проекта, тогда при сборке фазз-таргета проект будет пересобираться автоматически:

```xml
<ItemGroup>
    <Reference Include="target_name">
      <HintPath>/path/to/bin/target_name.dll</HintPath>
    </Reference>
    <PackageReference Include="SharpFuzz" Version="2.1.1" />
</ItemGroup>
```
либо
```xml
<ItemGroup>
    <ProjectReference Include="/path/to/csproj/target_name.csproj" />
    <PackageReference Include="SharpFuzz" Version="2.1.1" />
</ItemGroup>
```

После этого нужно собрать фазз-таргет и проинструментировать его для фаззинга
с помощью инструмента [Sharpfuzz](https://github.com/Metalnem/sharpfuzz):

    $ dotnet publish build_fuzz.csproj -c release -o bin
    $ sharpfuzz bin/target_name.dll


### Обертка luzer

Для подготовки luzer обертки можно воспользоваться его
[документацией](https://github.com/ligurio/luzer/blob/master/docs/usage.md). По
сути, требуется реализовать функцию `TestOneInput(buf)`, которая принимает на
вход мутированный буфер и передает его в код, являющийся целью фаззинга. Саму функцию
следует передать в качестве первого аргумента функции `luzer.Fuzz`.

Также в начале обертки требуется указать используемый интерпретатор Lua и
импортировать модуль `luzer` для инструментации целевого кода.


```lua
#!/usr/bin/env lua

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(4)
    myAwesomeCode(str)
end

luzer.Fuzz(TestOneInput, nil, nil)
```

Для сбора покрытия с помощью [LuaCov](https://github.com/lunarmodules/luacov) следует создать отдельную обёртку, заменив в ней вызов функции `luzer.Fuzz` на следующий код.

```lua
local buf = io.read()
if not buf then return nil end
TestOneInput(buf)
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
