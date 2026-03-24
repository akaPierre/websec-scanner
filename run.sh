#!/bin/bash
# run.sh — WebSec Scanner launcher

set -e

JAR="target/websec-scanner-1.0.0.jar"

if [ ! -f "$JAR" ]; then
    echo "JAR não encontrado. Compilando..."
    mvn clean package -DskipTests -q
    echo "Build concluído."
fi

if [ -n "$1" ]; then
    java -Xms128m -Xmx256m -jar "$JAR" "$1"
else
    java -Xms128m -Xmx256m -jar "$JAR"
fi