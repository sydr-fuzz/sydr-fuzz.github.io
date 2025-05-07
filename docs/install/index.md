# Зависимости и установка Sydr-fuzz

* TOC
{:toc}

# Минимальные системные требования

- Операционная система: Ubuntu 18.04/20.04/22.04, Astra 1.7, ALT Workstation 10.0 и
  аналоги - 64-bit.
- Процессор (CPU): Intel Core i3 или аналогичный AMD.
- Оперативная память (RAM): 4 ГБ.

# Рекомендуемые системные требования

- Операционная система: Ubuntu 18.04/20.04/22.04 - 64-bit.
- Процессор (CPU): Intel Core i7 (Desktop) или аналогичный AMD.
- Оперативная память (RAM): 32 ГБ и больше.

# Зависимости

Перед установкой инструмента установите следующие зависимости.

    $ sudo apt install gcc-multilib binutils lsb-release gdb lcov

Для корректной работы лицензионного USB ключа требуется установить последнюю
версию
[Sentinel HASP/LDK Run-time Environment](https://supportportal.thalesgroup.com/csm?id=kb_search&u_related_product_names=50303b92db852e00d298728dae96199d&query=kbcat_drivers_%26_runtime_packages&_runtime_packages&spa=1&u_all_related_operating_systems=66689e154fe293409a523c728110c74c)
(перед установкой желательно вынуть USB ключ, и вставить его назад по завершении
установки):

    $ tar xf aksusbd*.tar.gz
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

Рекомендуется воспользоваться нашим докером `sydr/ubuntu20.04-sydr-fuzz`.
Докер можно выкачать с помощью команды:

    $ docker pull sydr/ubuntu20.04-sydr-fuzz

`DockerFile` можно найти [тут](https://github.com/ispras/oss-sydr-fuzz/blob/master/docker/ubuntu20.04-sydr-fuzz/Dockerfile).
Затем запускать гибридный фаззинг внутри него. Дальнейшая документация
основывается на использовании нашего докера. Далее перечислены зависимости,
которые нужно установить, если запуск производится на другой системе.

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

## Зависимости Honggfuzz

Фаззер Honggfuzz уже установлен в нашем докере `sydr/ubuntu20.04-sydr-fuzz`. При запуске
на другой системе потребуется скачать и установить Honggfuzz (можно из
[репозитория](https://github.com/google/honggfuzz)). Для работы Honggfuzz также необходимо
установить дополнительные пакеты `binutils-dev`, `libunwind-dev` и `libblocksruntime-dev`.

## Зависимости Atheris

Библиотека фаззинга Atheris и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
и установить Atheris (можно из [репозитория](https://github.com/google/atheris)).
Для работы sydr-fuzz с Atheris также необходима библиотека сбора покрытия
[Coverage](https://coverage.readthedocs.io/en/latest/install.html).

## Зависимости Jazzer

Фаззер Jazzer и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
и установить Jazzer (можно из [репозитория](https://github.com/CodeIntelligenceTesting/jazzer)).
Для сбора покрытия понадобится библиотека [Jacoco](https://github.com/jacoco/jacoco).

## Зависимости Jazzer.js

Фаззер Jazzer.js и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
и установить Jazzer.js (можно из [репозитория](https://github.com/CodeIntelligenceTesting/jazzer.js)).

## Зависимости luzer

Фаззер luzer и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu22.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
и установить luzer (для возможности задания параметра `args` в toml-конфиге можно использовать ветку `patched` [форк-репозитория](https://github.com/azanegin/luzer.git)). Перед установкой
luzer рекомендуется установить lua5.1 и llvm >=17. Для сбора информации о покрытии необходимо
установить утилиту [luacov](https://github.com/lunarmodules/luacov).

## Зависимости Sharpfuzz

Фаззер Sharpfuzz и все необходимые утилиты уже установлены в нашем докере
`sydr/ubuntu20.04-sydr-fuzz`. При запуске на другой системе потребуется скачать
Sharpfuzz (можно из [репозитория](https://github.com/Metalnem/sharpfuzz)),
AFL++ (можно из [репозитория](https://github.com/AFLplusplus/AFLplusplus)),
для сборки и запуска C# програм понадобится скачать .NET SDK (можно с [сайта](https://learn.microsoft.com/en-us/dotnet/core/install/linux)).
Для сбора покрытия в форматах html, clover, coveralls, xml, opencover, cobertura, text
понадобится инструмент `minicover` (скачать можно по гайдам из [репозитория](https://github.com/lucaslorentz/minicover)).
Для сбора покрытия в форматах html (с помощью genhtml) или lcov
понадобится инструмент `AltCover` (скачать можно по гайдам из [репозитория](https://github.com/SteveGilham/altcover)).
