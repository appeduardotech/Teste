#!/usr/bin/env bash
# hello.sh — script inofensivo para demonstração
set -euo pipefail

echo "Olá! Este é um script de teste seguro."
echo "Data: $(date)"
echo "Usuário: $(whoami)"
echo "Diretório atual: $(pwd)"
echo "Sistema: $(uname -a)"

# Cria um arquivo temporário como prova de execução
TMPFILE=$(mktemp /tmp/hello_test.XXXXXX)
echo "Executado em $(date -Iseconds)" > "$TMPFILE"
echo "Arquivo de prova criado em: $TMPFILE"

echo "Script finalizado com sucesso."
