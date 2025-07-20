Certo! Ecco un file README dettagliato per il tuo script Python di sniffing di rete multithread con gestione rotazione file pcap e logging.

---

# Sniffer di Rete Multithread con Rotazione File e Logging

Questo script Python utilizza **Scapy** per catturare pacchetti di rete in tempo reale da un'interfaccia specificata, salvarli in file pcap con rotazione automatica dopo un numero massimo di pacchetti, e loggare le informazioni dei pacchetti catturati.

---

## Caratteristiche principali

* Sniffing multithread per separare la cattura e la scrittura su file pcap
* Rotazione automatica dei file pcap dopo aver raggiunto un limite massimo di pacchetti
* Logging dettagliato delle informazioni di ogni pacchetto (IP, TCP, UDP, ICMP, ARP)
* Gestione dei segnali di interruzione (Ctrl+C) per chiusura pulita
* Filtraggio BPF personalizzabile
* Configurazione tramite linea di comando (interfaccia, filtro, directory di output, nome file, max pacchetti)

---

## Requisiti

* Python 3.x
* Libreria `scapy` (installabile con `pip install scapy`)

---

## Installazione

1. Clona o scarica questo repository.
2. Assicurati di avere `scapy` installato:

   ```bash
   pip install scapy
   ```

---

## Uso

Esegui lo script da terminale con le opzioni desiderate:

```bash
python sniffer.py [--filter FILTER] [--iface INTERFACE] [--dir DIRECTORY] [--output OUTPUT_FILE] [--max-packets NUM]
```

### Opzioni disponibili

| Opzione         | Descrizione                                                                  | Default                         |
| --------------- | ---------------------------------------------------------------------------- | ------------------------------- |
| `--filter`      | Filtro BPF per catturare solo pacchetti specifici (es: `"tcp"`, `"port 80"`) | `""` (nessun filtro)            |
| `--iface`       | Interfaccia di rete da sniffare                                              | Interfaccia di default di Scapy |
| `--dir`         | Directory dove salvare i file di output (pcap e log)                         | `capture`                       |
| `--output`      | Nome base del file pcap di output                                            | `capture/capture.pcap`          |
| `--max-packets` | Numero massimo di pacchetti per file pcap prima della rotazione              | `1000`                          |

### Esempio di utilizzo

Sniffa pacchetti TCP sull'interfaccia `eth0`, salva i pcap in `logs` e ruota i file dopo 500 pacchetti:

```bash
python sniffer.py --filter "tcp" --iface eth0 --dir logs --max-packets 500
```

---

## Come funziona

* **Thread Sniffer:** cattura pacchetti in base al filtro e all'interfaccia specificati, mettendoli in una coda thread-safe.
* **Thread Writer:** legge i pacchetti dalla coda e li scrive su un file pcap. Quando il numero di pacchetti raggiunge il limite massimo, chiude il file e ne crea uno nuovo con un timestamp nel nome.
* **Logging:** per ogni pacchetto catturato, salva nel file di log informazioni dettagliate (indirizzi IP, porte, protocolli, ecc.).
* **Interruzione pulita:** con Ctrl+C o segnali di terminazione, lo script chiude correttamente il file pcap e termina i thread.

---

## Struttura file

* **sniffer.py:** script principale
* **capture/**: directory di default per i file pcap e log (creata automaticamente se non esiste)

---

## Considerazioni

* Assicurati di eseguire lo script con privilegi sufficienti per sniffare l'interfaccia (es. `sudo` su Linux).
* La rotazione dei file consente di non avere file pcap troppo grandi e facilita la gestione dei dati.
* Il logging dettagliato aiuta nell'analisi successiva dei pacchetti catturati.

---

## Contatti

Per domande o suggerimenti, sentiti libero di contattarmi!
