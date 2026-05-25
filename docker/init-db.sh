#!/bin/sh
# ============================================================
# init-db.sh — Ejecuta init.sql al arrancar SQL Server en Docker
# Solo crea objetos si no existen, nunca borra datos
# ============================================================

echo "[DB] Esperando a que SQL Server esté listo..."
until /opt/mssql-tools18/bin/sqlcmd \
    -S localhost -U sa -P "${SA_PASSWORD}" \
    -Q "SELECT 1" -C > /dev/null 2>&1; do
    echo "[DB] ... SQL Server no está listo aún, reintentando..."
    sleep 3
done

echo "[DB] SQL Server listo. Ejecutando script de inicialización..."
/opt/mssql-tools18/bin/sqlcmd \
    -S localhost -U sa -P "${SA_PASSWORD}" \
    -i /init.sql -C

echo "[DB] Inicialización completada."