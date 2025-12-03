use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::process;

use chrono::{DateTime, Local, TimeZone};
use clap::Parser;
use pcap::{Capture, Device, Offline, Packet};
use serde::{Deserialize, Serialize};

// Mis argumentos de línea de comandos (CLI)
#[derive(Parser)]
#[command(author, version, about = "Inventario de red desde PCAP o interfaz")]
struct Args {
    // Archivo PCAP de entrada
    #[arg(short, long, required_unless_present("iface"))]
    pcap: Option<String>,

    // Interfaz de red para captura en vivo
    #[arg(short, long, required_unless_present("pcap"))]
    iface: Option<String>,

    // Ruta a mi base de datos OUI/Vendor en formato JSON
    // ¡Asegúrate de que este archivo exista en el directorio de ejecución!
    #[arg(short = 'j', long, default_value = "mac-vendors-export.json")]
    oui_db: String,

    // Formato de salida: csv, xlsx o json
    #[arg(short, long, default_value = "csv")]
    output_format: String,

    // Bandera para forzar la unicidad
    #[arg(long)]
    unique: bool,
}

// Estructura para deserializar el JSON del fabricante OUI
#[derive(Deserialize)]
struct Manufacturer {
    #[serde(rename = "macPrefix")]
    prefix: String,
    #[serde(rename = "vendorName")]
    name: String,
}

// Mi registro final de inventario
#[derive(Serialize, Clone)]
struct Record {
    mac: String,
    vendor: String,
    count: u64,
    first_seen: String,
    last_seen: String,
}

fn main() {
    let args = Args::parse();

    // 1. Cargar el mapa OUI (Vendor)
    let file = File::open(&args.oui_db).unwrap_or_else(|e| {
        eprintln!("Error al abrir mi base de datos {}: {}", &args.oui_db, e);
        eprintln!("Asegúrate de que el archivo 'mac-vendors-export.json' esté presente.");
        process::exit(1);
    });
    let manufacturers: Vec<Manufacturer> = serde_json::from_reader(file).unwrap_or_else(|e| {
        eprintln!("Error al parsear el JSON {}: {}", &args.oui_db, e);
        process::exit(1);
    });

    // Construyo un HashMap para búsquedas rápidas (OUI -> Vendor Name)
    let oui_map: HashMap<String, String> = manufacturers
        .into_iter()
        .map(|m| (m.prefix.to_uppercase(), m.name))
        .collect();

    let mut inventory: HashMap<String, Record> = HashMap::new();

    // 2. Procesar PCAP o Interfaz
    if let Some(pcap_path) = args.pcap {
        println!("Procesando archivo PCAP: {}", pcap_path);
        let mut cap = Capture::<Offline>::from_file(&pcap_path).unwrap_or_else(|e| {
            eprintln!("Error al abrir el PCAP {}: {}", pcap_path, e);
            process::exit(1);
        });
        process_packets(&mut cap, &oui_map, &mut inventory);
    } else if let Some(iface_name) = args.iface {
        println!("Capturando en interfaz: {}", iface_name);

        let device = Device::list().unwrap_or_else(|e| {
            eprintln!("Error listando interfaces: {}", e);
            process::exit(1);
        })
        .into_iter()
        .find(|d| d.name == iface_name)
        .unwrap_or_else(|| {
            eprintln!("Interfaz {} no encontrada", iface_name);
            eprintln!("Intenta ejecutar con 'sudo' y usa el nombre real de tu interfaz (ej: en0, ens33).");
            process::exit(1);
        });

        let mut cap = Capture::from_device(device)
            .unwrap()
            .promisc(true)
            .open()
            .unwrap_or_else(|e| {
                eprintln!("Error iniciando captura: {}", e);
                eprintln!("Asegúrate de tener permisos (usa 'sudo').");
                process::exit(1);
            });
        process_packets(&mut cap, &oui_map, &mut inventory);
    }

    // 3. Exportar resultados
    let records_count = inventory.len(); // Guardo el tamaño del inventario
    let mut records: Vec<Record> = inventory.into_values().collect();

    // Lógica para eliminar duplicados si el usuario lo exige
    if args.unique {
        let mut seen = HashSet::new();
        records.retain(|r| seen.insert(r.mac.clone()));
    }

    // Mensaje de diagnóstico final
    if records_count == 0 {
        eprintln!("Advertencia: No se encontraron dispositivos únicos en el tráfico capturado.");
    }

    export_results(&records, &args.output_format);
}

// Proceso los paquetes, ya sea de PCAP o de captura en vivo.
fn process_packets<T: pcap::Activated>(
    cap: &mut Capture<T>,
    oui_map: &HashMap<String, String>,
    inventory: &mut HashMap<String, Record>,
) {
    let mut counter = 0; // <<< Contador de diagnóstico
    while let Ok(packet) = cap.next_packet() {
        handle_packet(&packet, oui_map, inventory);

        counter += 1;
        // Muestro el progreso cada 10,000 paquetes
        if counter % 10000 == 0 {
            println!("\t[INFO] Paquetes procesados: {}...", counter);
        }
    }
    // Muestra el resumen final de la captura
    println!("Procesamiento finalizado. Total paquetes vistos: {}. Dispositivos únicos en inventario: {}",
        counter, inventory.len());
}

// Mi lógica clave de procesamiento: extraigo MAC, busco Vendor, actualizo inventario.
fn handle_packet(
    packet: &Packet,
    oui_map: &HashMap<String, String>,
    inventory: &mut HashMap<String, Record>,
) {
    // Necesito al menos 12 bytes para DST + SRC MACs
    if packet.data.len() < 12 {
        return;
    }

    let dst = &packet.data[0..6];
    let src = &packet.data[6..12];

    // Convierto el timestamp a String solo una vez por paquete (Optimización)
    let ts = packet.header.ts;
    let datetime: DateTime<Local> = Local
        .timestamp_opt(ts.tv_sec.into(), ts.tv_usec as u32 * 1000)
        .earliest()
        .unwrap_or_else(|| {
            Local::now() // Uso la hora local si el timestamp es inválido
        });
    let timestamp = datetime.format("%Y-%m-%d %H:%M:%S%.6f").to_string();


    for mac_bytes in [src, dst] {
        // 1. Formateo la MAC y OUI
        let mac = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2],
            mac_bytes[3], mac_bytes[4], mac_bytes[5]
        );

        let oui = format!(
            "{:02X}:{:02X}:{:02X}",
            mac_bytes[0], mac_bytes[1], mac_bytes[2]
        );

        // 2. Busco el Vendor
        let vendor = oui_map
            .get(&oui)
            .cloned()
            .unwrap_or_else(|| "Unknown".to_string());

        // 3. Actualizo o inserto el registro en el inventario
        inventory
            .entry(mac)
            .and_modify(|rec| {
                rec.count += 1;
                // Clono el timestamp si modifico un registro existente
                rec.last_seen = timestamp.clone();
            })
            // Uso or_insert_with para no crear la estructura a menos que sea necesaria
            .or_insert_with(|| {
                // Genero la MAC string de nuevo porque la anterior se movió a 'entry(mac)'
                let mac_str = mac_bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(":");
                Record {
                    mac: mac_str,
                    vendor,
                    count: 1,
                    first_seen: timestamp.clone(),
                    last_seen: timestamp.clone(),
                }
            });
    }
}

fn export_results(records: &[Record], format: &str) {
    match format.to_lowercase().as_str() {
        "csv" => export_csv(records),
        "json" => export_json(records),
        "xlsx" => {
            export_excel(records)
        }
        _ => eprintln!("Formato desconocido. Usar csv, json o xlsx."),
    }
}

// Funciones de exportación

fn export_csv(records: &[Record]) {
    let mut wtr = csv::Writer::from_path("inventory.csv").unwrap_or_else(|e| {
        eprintln!("Error al crear inventory.csv: {}", e);
        process::exit(1);
    });
    for r in records {
        wtr.serialize(r).unwrap_or_else(|e| {
            eprintln!("Error al serializar registro CSV: {}", e);
        });
    }
    wtr.flush().unwrap_or_else(|e| {
        eprintln!("Error al escribir en inventory.csv: {}", e);
    });
    println!("Inventario exportado a inventory.csv");
}

fn export_json(records: &[Record]) {
    let file = File::create("inventory.json").unwrap_or_else(|e| {
        eprintln!("Error al crear inventory.json: {}", e);
        process::exit(1);
    });
    serde_json::to_writer_pretty(file, &records).unwrap_or_else(|e| {
        eprintln!("Error al escribir JSON: {}", e);
    });
    println!("Inventario exportado a inventory.json");
}

// Función corregida para el manejo de formato XLSX (sin advertencias ni errores)
fn export_excel(records: &[Record]) {
    use xlsxwriter::{Workbook, Format};

    let workbook = Workbook::new("inventory.xlsx").unwrap_or_else(|e| {
        eprintln!("Error al crear workbook XLSX: {}", e);
        process::exit(1);
    });
    let mut sheet = workbook.add_worksheet(None).unwrap();

    // --- Configuración de formato para negritas (elimina advertencia) ---
    let mut format_bold = Format::new();
    format_bold.set_bold();
    let bold = &format_bold;
    // ------------------------------------------------------------------

    sheet.write_string(0, 0, "MAC", Some(bold)).unwrap();
    sheet.write_string(0, 1, "Vendor", Some(bold)).unwrap();
    sheet.write_string(0, 2, "Count", Some(bold)).unwrap();
    sheet.write_string(0, 3, "First Seen", Some(bold)).unwrap();
    sheet.write_string(0, 4, "Last Seen", Some(bold)).unwrap();

    for (i, r) in records.iter().enumerate() {
        let row = (i + 1) as u32;
        sheet.write_string(row, 0, &r.mac, None).unwrap();
        sheet.write_string(row, 1, &r.vendor, None).unwrap();
        sheet.write_number(row, 2, r.count as f64, None).unwrap();
        sheet.write_string(row, 3, &r.first_seen, None).unwrap();
        sheet.write_string(row, 4, &r.last_seen, None).unwrap();
    }
    workbook.close().unwrap_or_else(|e| {
        eprintln!("Error al cerrar workbook XLSX: {}", e);
    });
    println!("Inventario exportado a inventory.xlsx");
}
