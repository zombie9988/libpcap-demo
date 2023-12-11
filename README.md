### Тестовый пример использования libpcap

## Сборка

Установите необходимые библиотеки:

```bash
libpcap-dev libsystemd-dev libyara-dev libpcap-dev libgrpc-dev
```

Сконфигурируйте `Cmake`:

```bash
mkdir build
cd build
cmake ..
```

Соберите проект:

```bash
make
```

Запустите программу:

```bash
./libpcap-demo
```

### Пример использования

```bash
./libpcap-demo -i ens33 -r example.yar -h localhost:50051
```