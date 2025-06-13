# Network Scanner v2.0

Scanner di rete avanzato scritto in C++23 con Boost 1.88.0. Supporta rilevamento automatico della rete locale, risoluzione DNS, ricerca per hostname e scansione parallela multi-thread.

## Caratteristiche

- **Auto-rilevamento rete locale**: Trova automaticamente la subnet corrente
- **Scansione multi-thread**: Utilizza tutti i core disponibili per scansioni veloci
- **Risoluzione DNS inversa**: Mostra i nomi degli host oltre agli IP
- **Filtro hostname**: Cerca dispositivi per nome (anche parziale)
- **Animazione progresso**: Feedback visivo durante la scansione
- **Export risultati**: Salva i risultati in file di testo formattato
- **Cross-platform**: Supporta Windows e Linux

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

# Cerca dispositivi con "router" nel nome
sudo ./network_scanner -f router

# Scansiona range specifico
sudo ./network_scanner 192.168.1.0 0:254

# Cerca PC in un range specifico e salva risultati
sudo ./network_scanner 10.0.0.0 1:100 -f PC -o risultati.txt
```

### Opzioni linea di comando

- `-h, --help`: Mostra aiuto
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

- **Velocità**: ~50-100 host/secondo (dipende dalla rete)
- **Memory**: ~10-20 MB per scansione completa /24
- **CPU**: Utilizza tutti i core disponibili

## Limitazioni

- Richiede privilegi elevati per socket ICMP raw
- Alcuni dispositivi potrebbero non rispondere al ping
- La risoluzione DNS può essere lenta per alcuni host
- Firewall/antivirus potrebbero interferire

## Licenza

Questo software è fornito "così com'è" per scopi educativi e di testing.
Usa responsabilmente e solo su reti di cui hai autorizzazione.