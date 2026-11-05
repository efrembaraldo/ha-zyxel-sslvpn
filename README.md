# Home Assistant Add-on: Zyxel SSL VPN

Client SSL VPN per firewall Zyxel ZLD (USG FLEX, ATP, serie VPN), compatibile con il protocollo di Zyxel SecuExtender 4.x. L'add-on crea un'interfaccia TUN sull'host di Home Assistant con le route verso le reti remote, e può opzionalmente fare da gateway per altri host della LAN.

Architetture supportate: `amd64`, `aarch64`.

## Ispirazione

Questo progetto è nato dallo studio di [rainpwn/zyxel-secuextender-linux](https://github.com/rainpwn/zyxel-secuextender-linux), un client Linux per il protocollo SecuExtender di Zyxel, che ha ispirato lo sviluppo di `ha-zyxel-sslvpn`.

## Installazione

1. In Home Assistant vai su **Impostazioni → Add-on → Store degli add-on**.
2. Menu ⋮ → **Repository** → aggiungi l'URL di questo repository.
3. Installa **Zyxel SSL VPN**, configuralo (vedi sotto) e avvialo.

## Configurazione

Esempio:

```yaml
host: vpn.example.com
port: 443
username: mario
password: segreta
certificate_pin: "AB:CD:EF:..."
insecure: false
interface_name: zyvpn0
gateway_mode: false
lan_interface: ""
no_nat: false
auto_reconnect: true
reconnect_delay: 15
verbose: false
```

| Opzione | Descrizione |
|---|---|
| `host` | Indirizzo o FQDN del firewall |
| `port` | Porta SSL VPN (default `443`) |
| `username` / `password` | Credenziali VPN |
| `certificate_pin` | SHA256 del certificato del firewall (hex, anche con `:`) |
| `insecure` | Non verifica il certificato (sconsigliato) |
| `interface_name` | Nome interfaccia TUN (default `zyvpn0`) |
| `gateway_mode` | Abilita forwarding IPv4 e NAT: gli host della LAN che usano HA come gateway raggiungono le reti dietro la VPN |
| `lan_interface` | Con `gateway_mode`: inoltra solo il traffico proveniente da questa interfaccia |
| `no_nat` | Con `gateway_mode`: niente masquerade (il lato remoto deve instradare la LAN verso il tunnel) |
| `auto_reconnect` | Riconnette automaticamente se la sessione cade |
| `reconnect_delay` | Secondi tra i tentativi (5–600) |
| `verbose` | Log dettagliato (stampa l'XML di configurazione ricevuto) |

È obbligatorio impostare `certificate_pin` **oppure** `insecure`. Se lasci vuoto il pin e `insecure` è falso, il primo avvio fallisce e il log mostra l'impronta del certificato da copiare nella configurazione.

## Note e limitazioni

- L'add-on richiede `host_network`, il privilegio `NET_ADMIN` e il device `/dev/net/tun`. Su alcune installazioni potrebbe essere necessario disattivare la modalità protetta dell'add-on.
- I server DNS inviati dal firewall non vengono applicati (nel container non c'è `resolvectl`): sono solo scritti nel log.
- Con `gateway_mode`, se `/proc/sys` è in sola lettura il forwarding IPv4 deve essere già attivo sull'host.
- Allo stop dell'add-on il client esegue il logout dal firewall.

## Struttura del repository

```
repository.yaml
zyxel_sslvpn/
├── config.yaml          # opzioni e schema
├── Dockerfile, build.yaml
├── DOCS.md              # documentazione mostrata nella UI di HA
├── translations/it.yaml
└── rootfs/
    ├── etc/services.d/zyxel-sslvpn/{run,finish}
    └── usr/bin/zyxel_sslvpn.py   # client, legge /data/options.json
```

## Uso standalone dello script

Lo script funziona anche fuori da Home Assistant (Linux, come root):

```bash
sudo ./zyxel_sslvpn.py vpn.example.com 443 utente --pin <sha256 certificato>
```

Per l'uso nell'add-on viene invocato con `--options-file /data/options.json`.

## Da completare

Sostituisci i placeholder `CHANGE-ME` in `repository.yaml` e `zyxel_sslvpn/config.yaml` con l'URL del tuo repository GitHub.
