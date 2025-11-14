# Inventario de red

Herramienta para inventariar dispositivos de red leyendo archivos PCAP o interfaces en vivo. 
Exporta resultados en CSV, JSON o Excel.

## Ejemplos:

# Desde archivo PCAP:
cargo run -- --pcap captura.pcap --output-format csv

# Desde interfaz en vivo:
cargo run -- --iface eth0 --output-format json

# Eliminar duplicados
cargo run -- --pcap red.pcap --unique --output-format xlsx

Requiere archivo OUI:
data/mac-vendors-export.json
