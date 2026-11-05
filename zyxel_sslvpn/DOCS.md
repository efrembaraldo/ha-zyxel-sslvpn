# Zyxel SSL VPN

Client SSL VPN per firewall Zyxel ZLD (USG FLEX, ATP, VPN), compatibile con il
protocollo di SecuExtender 4.x. Crea un'interfaccia TUN sull'host di Home
Assistant con le route verso le reti remote.

## Opzioni

| Opzione | Descrizione |
|---|---|
| `host` | Indirizzo/FQDN del firewall |
| `port` | Porta SSL VPN (default 443) |
| `username` / `password` | Credenziali VPN |
| `certificate_pin` | SHA256 del certificato del firewall (hex, anche con `:`). Se vuoto e `insecure` è falso, il primo avvio fallisce e il log mostra il valore da copiare |
| `insecure` | Non verifica il certificato (sconsigliato) |
| `interface_name` | Nome interfaccia TUN (default `zyvpn0`) |
| `gateway_mode` | Abilita forwarding IPv4 + NAT: gli altri host della LAN che usano HA come gateway raggiungono le reti dietro la VPN |
| `lan_interface` | Con `gateway_mode`: inoltra solo pacchetti provenienti da questa interfaccia |
| `no_nat` | Con `gateway_mode`: niente masquerade (il lato remoto deve instradare la LAN) |
| `auto_reconnect` | Riconnette automaticamente se la sessione cade |
| `reconnect_delay` | Secondi tra i tentativi (5–600) |
| `verbose` | Log dettagliato (stampa l'XML di configurazione) |

## Esempio

```yaml
host: vpn.example.com
port: 443
username: mario
password: segreta
certificate_pin: "AB:CD:..."
gateway_mode: false
auto_reconnect: true
```

## Note

- L'add-on usa `host_network`, `NET_ADMIN` e `/dev/net/tun`. Se la protezione
  è attiva potrebbe essere necessario disattivarla in Info → Modalità protetta.
- I server DNS inviati dal firewall non vengono applicati (nel container non c'è `resolvectl`); sono scritti nel log.
- In `gateway_mode` se `/proc/sys` è in sola lettura il forwarding deve già essere attivo sull'host.
