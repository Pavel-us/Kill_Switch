#!/bin/bash

# Определяем путь к текущему скрипту
SCRIPT_DIR=$(dirname "$(realpath "$0")")

# Запускаем Kill_Switch.py, который находится в той же папке
sudo DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY python3 "$SCRIPT_DIR/Kill_Switch.py"
