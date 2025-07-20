from scapy.all import sniff, PcapWriter, IP, TCP, UDP, ICMP, ARP, conf
from datetime import datetime
import os
import argparse 
import logging
import sys
import signal
import threading
import queue
# Dati di configurazione

# Configurazione file di output
FILE_DIR = "capture"
FILE_NAME= "capture"
FILE_PATH = os.path.join(FILE_DIR, FILE_NAME)
logger=None

# Configurazione del numero massimo di pacchetti da catturare
MAX_PACKETS = 1000  # Numero massimo di pacchetti da catturare per file
pcap_writer= None  # Scrittore pcap
log_count = 0  # Contatore per i file di log

# Coda per i pacchetti catturati
packet_queue = queue.Queue()
stop_event = threading.Event()
packets_count = 0

# Lock per la scrittura su file pcap
pcap_lock = threading.Lock()

# Gestione del segnale di interruzione
def stop_sniffer(sig, frame):
    logger.info("Segnale di terminazione ricevuto. Chiudo il pcap...")
    stop_event.set()  # Imposta l'evento di stop

# Funzioni per sniffare i pacchetti e scriverli su file pcap
def packet_sniffer(filter, iface):
    """Funzione per sniffare i pacchetti."""
    sniff(prn=packet_callback, filter=filter, iface=iface, store=False, stop_filter=lambda x: stop_event.is_set())

def packet_writer():
    """Thread per scrivere i pacchetti nella coda in un file pcap."""
    global pcap_writer, stop_event, packets_count
    while not stop_event.is_set() or not packet_queue.empty():
        try:
            pkt = packet_queue.get(timeout=1)  # Attendi un pacchetto nella coda
        except queue.Empty:
            continue
        with pcap_lock:
            if pcap_writer is None:
                continue
            pcap_writer.write(pkt)  # Scrivi il pacchetto nel file pcap
        
        packets_count += 1
        # Rotazione del file pcap se raggiunto il numero massimo di pacchetti
        if packets_count >= MAX_PACKETS:
            with pcap_lock:
                if pcap_writer is not None:
                    logger.info(f"Raggiunto il limite di {MAX_PACKETS} pacchetti. Rotazione file pcap...")
                    pcap_writer.close()
                    create_pcap_writer()
                    packets_count = 0
 


def setup_logging():
    """Configura il logging per il modulo."""
    global FILE_DIR, FILE_NAME, logger, log_count
    if not os.path.exists(FILE_DIR):
        os.makedirs(FILE_DIR)
    while True:
        if os.path.exists(f"{FILE_DIR}/{FILE_NAME}_{log_count}.log"):
            log_count += 1  # Incrementa il contatore se il file esiste già
        else: 
            log_file = os.path.join(FILE_DIR, f"{FILE_NAME}_{log_count}.log")
            break
    logging.basicConfig(filename=log_file,level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)
    return logger

def get_new_file_name():
    """Genera un nuovo nome di file pcap basato sul contatore dei file."""
    global FILE_NAME, FILE_DIR
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S_%f")
    return os.path.join(FILE_DIR, f"{FILE_NAME}_{timestamp}.pcap")

def create_pcap_writer():
    """Crea un nuovo scrittore pcap per il file di output."""
    global pcap_writer, FILE_DIR, FILE_NAME
    if not os.path.exists(FILE_DIR):
        os.makedirs(FILE_DIR)
    pcap_file = get_new_file_name()
    pcap_writer = PcapWriter(pcap_file, append=True, sync=True)
    if logger:
        logger.info(f"\nNuovo file pcap creato: {pcap_file}")
    else:
        print(f"\nNuovo file pcap creato: {pcap_file}")

def packet_callback(pkt):
    """Callback per ogni pacchetto catturato."""
    global pcap_writer, packets, logger, MAX_PACKETS
    packet_queue.put(pkt)


    timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')
    logger.info(f"\n--- Nuovo pacchetto ---\nTimestamp: {timestamp}")

    if IP in pkt:
        ip_layer = pkt[IP]
        if logger:
            logger.info(f"Sorgente IP: {ip_layer.src} -> Destinazione IP: {ip_layer.dst} | Protocollo: {ip_layer.proto}")
        else:
            print(f"Sorgente IP: {ip_layer.src} -> Destinazione IP: {ip_layer.dst} | Protocollo: {ip_layer.proto}")
        
    if TCP in pkt:
        tcp_layer = pkt[TCP]
        if logger:
            logger.info(f"TCP {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {tcp_layer.flags}")
        else:
            print(f"TCP {tcp_layer.sport} -> {tcp_layer.dport} | Flags: {tcp_layer.flags}")

    if UDP in pkt:
        udp_layer = pkt[UDP]
        if logger:
            logger.info(f"UDP {udp_layer.sport} -> {udp_layer.dport}")
        else:
            print(f"UDP {udp_layer.sport} -> {udp_layer.dport}")
    if ICMP in pkt:
        icmp_layer = pkt[ICMP]
        if logger:
            logger.info(f"ICMP Type: {icmp_layer.type} Code: {icmp_layer.code}")
        else:
            print(f"ICMP Type: {icmp_layer.type} Code: {icmp_layer.code}")
    if ARP in pkt:
        arp_layer = pkt[ARP]
        if logger:
            logger.info(f"ARP {arp_layer.psrc} -> {arp_layer.pdst} | Op: {arp_layer.op}")
        else:
            print(f"ARP {arp_layer.psrc} -> {arp_layer.pdst} | Op: {arp_layer.op}")

def main():
    global FILE_DIR, FILE_NAME, MAX_PACKETS
    parser = argparse.ArgumentParser(description="Sniffer di rete con filtro personalizzabile")
    parser.add_argument('--filter', type=str, default="", help="Filtro BPF (es: 'tcp', 'port 80')")
    parser.add_argument('--iface', type=str, default=conf.iface, help="Interfaccia di rete da sniffare (default: None, usa l'interfaccia predefinita)")
    parser.add_argument('--dir', type=str, default=FILE_DIR, help="Directory per i file di output (default: 'capture')")    
    parser.add_argument('--output', type=str, default=FILE_PATH, help="File di output per i pacchetti catturati (default: 'capture/capture.pcap')")
    parser.add_argument('--max-packets', type=int, default=MAX_PACKETS, help="Numero massimo di pacchetti da catturare per file (default: 1000)")
    args = parser.parse_args()

    # Aggiorna le variabili globali con i valori degli argomenti
    MAX_PACKETS = args.max_packets  # Aggiorna il numero massimo di pacchetti
    FILE_DIR = args.dir  # Aggiorna la directory di output
    FILE_NAME = args.output  # Aggiorna il nome del file di output
    
    # Setup logging
    setup_logging()
    logger.info("Avvio sniffer multithread.")

    # Inizializza il primo file pcap
    create_pcap_writer()

    # Gestione segnali
    signal.signal(signal.SIGINT, stop_sniffer)
    signal.signal(signal.SIGTERM, stop_sniffer)

    # Avvio thread
    sniffer_thread = threading.Thread(target=packet_sniffer, args=(args.filter, args.iface))
    writer_thread = threading.Thread(target=packet_writer)

    sniffer_thread.start()
    writer_thread.start()


    logger.info(f"Sniffer avviato con:\n filtro: '{args.filter}'\n iface: '{args.iface}'\n dir: '{args.dir}'\n output: '{args.output}'\n max_packets '{args.max_packets}. Premi CTRL+C per fermarlo.")
    
    try:
        sniffer_thread.join()
        writer_thread.join()
        logger.info("Sniffer terminato.")
        
    except KeyboardInterrupt:
        stop_event.set()
        logger.info("Sniffer interrotto dall'utente.")
        print("\nSniffer interrotto dall'utente.")
    finally:
        stop_event.set()
        writer_thread.join()
        sniffer_thread.join()
        with pcap_lock:
            if pcap_writer is not None:
                pcap_writer.close()
        logger.info("Sniffer terminato. Bye!")
    
if __name__ == "__main__":
    main()
