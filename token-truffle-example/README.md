## Как запустить
Установка нужных для проекта модулей:
```bash
npm install
```

Компиляция
```bash
 ./node_modules/.bin/truffle compile
```

Пример теста:
https://github.com/smartzplatform/sale/blob/master/test/SmartzTokenTest.js

Запуск тестов:
1) Запуск ganache – выполнять в отдельном окне терминала
```bash
./node_modules/.bin/ganache-cli -l 10000000 
```

или: с выдачей лога в файл
```bash
./node_modules/.bin/ganache-cli -l 10000000 &>/tmp/ganache.log
```

или: с работой в фоне (Linux / MacOS / Windows git-bash) - можно в том же окне
```bash
./node_modules/.bin/ganache-cli -l 10000000 &>/tmp/ganache.log &
```

2) запуск тестов - в отдельном окне:
```bash
./node_modules/.bin/truffle test
```
