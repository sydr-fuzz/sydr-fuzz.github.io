# Sydr-fuzz

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

# Документация

- [sydr-fuzz.md](sydr-fuzz) - подробное описание опций и применения инструмента гибридного фаззинга Sydr-Fuzz.
- [install.md](install) - зависимости и установка релиза Sydr-Fuzz.
- [config.md](config) - полная спецификация конфигурационного файла для Sydr-Fuzz.
- [sydr.md](sydr) - документация Sydr - инструмента динамической символьной интерпретации, входящего в состав Sydr-Fuzz.
- [misc.md](misc) - инструкции по созданию фаззинг целей и подготовки докера для фаззинга.

# Трофеи

Список трофеев можно найти в репозитории
[OSS-Sydr-Fuzz](https://github.com/ispras/oss-sydr-fuzz/blob/master/TROPHIES.md).

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
15. Вишняков А.В. Поиск ошибок в бинарном коде методами динамической символьной интерпретации.
   PhD thesis.
   \[[диссертация](https://vishnya.xyz/vishnyakov-phd-thesis2022.pdf)\]
   \[[автореферат](https://vishnya.xyz/vishnyakov-phd-synopsis2022.pdf)\]
   \[[cлайды](https://vishnya.xyz/vishnyakov-phd-thesis2022-presentation.pdf)\]
16. Fedotov A., Vishnyakov A. CASR: Your Life Vest in a Sea of Crashes. OFFZONE 2023.
   \[[слайды](https://sydr-fuzz.github.io/papers/fedotov-casr-offzone2023.pdf)\]
   \[[видео](https://www.youtube.com/watch?v=EgEeICZQD9M)\]
17. Padaryan V., Stepanov V., Vishnyakov A. Fuzzing for SDL: Select, Cover, Reveal.
   OFFZONE 2023
   \[[слайды](https://sydr-fuzz.github.io/papers/vishnyakov-sydr-offzone2023.pdf)\]
   \[[видео](https://youtu.be/ASZMRp8AoTQ?si=HW0q_TxtbMWCkuoH&t=1067)\]
18. Mezhuev T., Kobrin I., Vishnyakov A., Kuts D. Numeric Truncation Security Predicate.
   2023 Ivannikov ISPRAS Open Conference (ISPRAS), IEEE.
   \[[статья](https://arxiv.org/abs/2312.06425)\]
   \[[слайды](https://vishnya.xyz/mirror/mezhuev-ispopen2023.pdf)\]
   \[[видео](https://www.youtube.com/watch?v=oMpSgMFFiXc&t=18608s)\]
