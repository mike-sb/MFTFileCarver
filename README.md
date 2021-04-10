# MFTFileCarver

## Eng

Carving file entries from images/ dumps/ byte files. Recovers FN atr, giving std info.

Example used on $MFT dump

### How to use?
Just download Python 3.0 and higher.
For safety purpuse use this script on files. If u want to access whole disk -  use comand line as Admin and instead of @filename@ use  "\\\\.\\E: " or "\\.\physicaldrive0" 
as an example.
U can also use full path to the file.
```sh
py carver.py filename
```

## Rus

Карвинг файловых записей из образов/дампов/бинарников . Восстановление FN атрибута, STANDART_INFORMATION и времени доступа.

В экспериментальной части НИР была использована копия $MFT

### Как пользоваться?
Скачайте Python 3.0 и выше.
В целях безопасности используйте этот скрипт для файлов. 
Если вы хотите получить доступ ко всему диску - используйте командную строку в качестве администратора и вместо @ filename @ используйте "\_\_\_\. \_\_ E:" или "\_\. \ Physicaldrive0"
Также можно использовать полный путь к файлу.
```sh
py carver.py filename
```



