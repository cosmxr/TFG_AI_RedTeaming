#!/bin/sh
echo "Esperando a que Ollama Judge arranque..."
until ollama list > /dev/null 2>&1; do
    sleep 2
done

echo "Descargando WhiteRabbitNeo Judge..."
ollama pull hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:latest

echo "Precargando modelo en RAM..."
ollama run hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:latest \
  "ping" --verbose 2>/dev/null || true

echo "WhiteRabbitNeo Judge listo en RAM"