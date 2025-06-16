# Network Scanner v2.0

Scanner di rete avanzato scritto in C++23 con Boost 1.88.0. Supporta rilevamento automatico della rete locale, risoluzione DNS, ricerca per hostname e scansione parallela multi-thread.

## Caratteristiche

- **Auto-rilevamento rete locale**: Trova automaticamente la subnet corrente
- **Scansione multi-thread**: Utilizza fino a 8 thread per scansioni veloci
- **Risoluzione DNS inversa**: Mostra i nomi degli host oltre agli IP
- **Filtro hostname**: Cerca dispositivi per nome (anche parziale)
- **Animazione progresso**: Feedback visivo durante la scansione
- **Modalità verbose**: Mostra host trovati in tempo reale
- **Retry automatico**: 2 tentativi per ogni host per maggiore affidabilità
- **Export risultati**: Salva i risultati in file di testo formattato
- **Cross-platform**: Supporta Windows e Linux

## Miglioramenti per risultati affidabili

Il programma implementa diverse strategie per garantire risultati consistenti:

1. **Timeout aumentato**: 1 secondo invece di 500ms per host lenti
2. **Retry automatico**: 2 tentativi per ogni host
3. **Thread pool con wait**: Attende il completamento di tutte le scansioni
4. **Rate limiting**: 20ms tra ogni richiesta per evitare sovraccarichi
5. **Verifica risposta**: Controlla che la risposta ICMP provenga dall'host corretto
6. **DNS con timeout**: Massimo 2 secondi per la risoluzione del nome

## Requisiti

- **Compilatore C++23** (GCC 13+, Clang 16+, MSVC 2022)
- **Boost 1.88.0** o superiore
- **CMake 3.26** o superiore
- **Privilegi amministratore/root** per socket ICMP raw

## Installazione

### Linux

```bash
# Installa dipendenze (Ubuntu/Debian)
sudo apt update
sudo apt install build-essential cmake gcc-13 g++-13
sudo apt install libboost-all-dev

# Clona e compila
git clone <repository>
cd network-scanner
chmod +x build.sh
./build.sh
```

### Windows

1. Installa Visual Studio 2022 con workload C++
2. Installa Boost 1.88.0 da https://www.boost.org/
3. Imposta la variabile d'ambiente `BOOST_ROOT`

```powershell
# Compila con build.bat
build.bat

# O manualmente
mkdir build
cd build
cmake .. -G "Visual Studio 17 2022"
cmake --build . --config Release
```

## Utilizzo

### Esempi base

```bash
# Auto-rileva e scansiona la rete locale
sudo ./network_scanner

# Modalità verbose - mostra host in tempo reale
sudo ./network_scanner -v

# Cerca dispositivi con "router" nel nome
sudo ./network_scanner -f router

# Scansiona range specifico
sudo ./network_scanner 192.168.1.0 0:254

# Cerca PC in un range specifico e salva risultati
sudo ./network_scanner 10.0.0.0 1:100 -f PC -o risultati.txt

# Combina verbose e filtro
sudo ./network_scanner -v -f server
```

### Opzioni linea di comando

- `-h, --help`: Mostra aiuto
- `-v, --verbose`: Modalità verbose (mostra host trovati in tempo reale)
- `-f, --filter <nome>`: Filtra per hostname (case insensitive)
- `-o, --output <file>`: Salva risultati su file
- `[ip_base] [start:end]`: Range IP personalizzato (opzionale)

## Output

Durante la scansione:
```
⠸ Scansione in corso... Analizzati: 45/254 | Attivi: 8
```

Risultati finali:
```
================================================================================
HOST ATTIVI TROVATI
================================================================================
IP Address           Hostname
--------------------------------------------------------------------------------
192.168.1.1          router.local
192.168.1.10         pc-office.local
192.168.1.20         nas-server.local
192.168.1.50         printer-hp.local

================================================================================
Totale host attivi: 4
```

## Funzionamento tecnico

1. **Rilevamento rete**: Enumera le interfacce di rete e trova quella attiva non-loopback
2. **Calcolo subnet**: Determina il range di IP dalla netmask
3. **Thread pool**: Distribuisce le scansioni su N thread (N = numero di core)
4. **ICMP ping**: Invia echo request e attende reply con timeout 500ms
5. **DNS lookup**: Per ogni host attivo, risolve il nome tramite DNS inverso
6. **Filtro**: Applica il filtro hostname se specificato

## Troubleshooting

### Risultati inconsistenti tra scansioni

Se noti che i risultati variano tra le esecuzioni, ecco le possibili cause e soluzioni:

**Cause comuni:**
1. **Dispositivi in sleep/risparmio energetico**: Alcuni dispositivi non rispondono quando in standby
2. **Firewall dinamici**: Alcuni firewall limitano le risposte ICMP dopo molte richieste
3. **Congestione di rete**: La rete potrebbe essere sovraccarica
4. **WiFi instabile**: I dispositivi wireless possono avere connessioni intermittenti

**Soluzioni:**
- Usa la modalità verbose (`-v`) per vedere cosa succede in tempo reale
- Riduci il range di scansione per concentrarti su IP specifici
- Esegui la scansione in orari con meno traffico di rete
- Per dispositivi critici, verifica manualmente con `ping` diretto

### "Permission denied" su Linux
```bash
# Esegui con sudo
sudo ./network_scanner

# O imposta capability (permanente)
sudo setcap cap_net_raw+ep ./network_scanner
```

### "Richiede privilegi amministratore" su Windows
- Click destro sull'eseguibile → "Esegui come amministratore"
- O apri un prompt dei comandi come amministratore

### Nessun host trovato
- Verifica che il firewall non blocchi ICMP
- Alcuni dispositivi potrebbero non rispondere al ping
- Prova un range IP diverso o verifica la subnet

### Compilazione fallisce
- Verifica versione compilatore (C++23 richiesto)
- Controlla che Boost sia installato correttamente
- Su Windows, verifica `BOOST_ROOT` sia impostato

## Performance

- **Velocità**: ~30-50 host/secondo (con rate limiting per affidabilità)
- **Thread**: Massimo 8 thread concorrenti per evitare sovraccarichi
- **Memory**: ~10-20 MB per scansione completa /24
- **Timeout**: 1 secondo per host + 2 tentativi = max 2s per host
- **DNS**: Timeout 2 secondi per risoluzione nome

## Ottimizzazione risultati

Per ottenere i migliori risultati:

1. **Prima scansione**: Esegui con `-v` per identificare dispositivi problematici
2. **Scansioni successive**: Usa filtri per concentrarti su dispositivi specifici
3. **Orario**: Evita orari di punta della rete (backup notturni, ecc.)
4. **Range ridotti**: Scansiona subnet più piccole per maggiore precisione

## Limitazioni

- Richiede privilegi elevati per socket ICMP raw
- Alcuni dispositivi potrebbero non rispondere al ping
- La risoluzione DNS può essere lenta per alcuni host
- Firewall/antivirus potrebbero interferire

## Licenza

Questo software è fornito "così com'è" per scopi educativi e di testing.
Usa responsabilmente e solo su reti di cui hai autorizzazione.