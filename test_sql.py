import pyodbc

# Para LocalDB el formato correcto es con "Server=" y punto y coma al final
CADENA_CONEXION = (
    "DRIVER={ODBC Driver 17 for SQL Server};"
    "SERVER=(localdb)\\MSSQLLocalDB;"
    "DATABASE=TFG_RedTeaming;"
    "Integrated Security=True;"       # <-- Cambiamos Trusted_Connection por Integrated Security
    "MultipleActiveResultSets=True;"
)

try:
    conn = pyodbc.connect(CADENA_CONEXION)
    print("✓ Conexión exitosa a SQL Server!")
    
    # Prueba adicional: verificar que las tablas existen
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM Auditorias")
    print(f"✓ Tabla Auditorias encontrada correctamente.")
    conn.close()
    
except Exception as e:
    print(f"✗ Error de conexión: {e}")