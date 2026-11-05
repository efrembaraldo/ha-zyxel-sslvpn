#!/usr/bin/env python3
"""zyxel_sslvpn.py - SSL VPN client for Zyxel ZLD firewalls (USG FLEX, ATP, VPN series),
speaking the same protocol as Zyxel SecuExtender 4.x.

  sudo ./zyxel_sslvpn.py vpn.example.com 443 user --pin <certificate sha256>

The protocol is documented in PROTOCOL.md.
"""
import argparse, getpass, hashlib, json, os, re, select, shutil, signal, socket, ssl, struct, subprocess, sys, threading, time, fcntl
from urllib.parse import quote

__version__ = "0.2.0"

PROXY_PORT = 10444      # hard-coded in SecuExtender (SetConnCTX)
MTU = 1370              # MTU of the SecuExtender TAP adapter
IFF_TUN, IFF_NO_PI, TUNSETIFF = 0x0001, 0x1000, 0x400454CA
IP_FORWARD = "/proc/sys/net/ipv4/ip_forward"
RULE_TAG = "zyxel_sslvpn"   # name of the nft table and comment of the iptables rules (used to remove them on exit)
IFNAME_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")


def tls_connect(a):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # firewalls ship self-signed certificates: checked against --pin below
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2  # same as the Windows client
    s = ctx.wrap_socket(socket.create_connection((a.host, a.port), timeout=30), server_hostname=a.host)
    fp = hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
    if not a.insecure and fp != a.pin.replace(":", "").lower():
        sys.exit(f"Unexpected certificate, sha256={fp}\n(if this is your firewall, run again with --pin {fp})")
    return s


def recv_until(s, marker, limit=65536):
    buf = b""
    while marker not in buf:
        d = s.recv(4096)
        if not d or len(buf) > limit:
            raise ConnectionError(f"connection closed before {marker!r}: {buf[:300]!r}")
        buf += d
    return buf


def login(a, password):
    body = f"username={quote(a.user, safe='')}&pwd={quote(password, safe='')}&password={quote(password, safe='')}&loginTosslvpn=true"
    hp = f"{a.host}:{a.port}"
    req = (f"POST / HTTP/1.1\r\nHost: {hp}\r\nReferer: https://{hp}\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nConnection: Keep-Alive\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
    with tls_connect(a) as s:
        s.sendall(req.encode())
        resp = recv_until(s, b"\r\n\r\n").decode("latin1")
    m = re.search(r"Set-Cookie: authtok=([^;\r\n]*);", resp, re.I)
    if not m:
        sys.exit("Login failed, no authtok cookie. Response headers:\n" + resp.split("\r\n\r\n")[0])
    return m.group(1)


def logout(a, tok):
    hp = f"{a.host}:{a.port}"
    body = "perform=logout"
    req = (f"POST /setuser.cgi HTTP/1.1\r\nHost: {hp}\r\nReferer: https://{hp}\r\nCookie: authtok={tok};\r\n"
           f"Content-Type: application/x-www-form-urlencoded\r\nConnection: Keep-Alive\r\n"
           f"Content-Length: {len(body)}\r\n\r\n{body}")
    try:
        with tls_connect(a) as s:
            s.sendall(req.encode())
    except OSError as e:
        print("logout not sent:", e, file=sys.stderr)


def negotiate(a, tok):
    s = tls_connect(a)
    s.sendall((f"CONNECT 127.0.0.1:{PROXY_PORT} HTTP/1.1\r\nUser-Agent: WinInet\r\nHost: {a.host}:{a.port}\r\n"
               f"Content-Length: 0\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\n"
               f"Cookie: authtok={tok}\r\n\r\n").encode())
    head, _, rest = recv_until(s, b"\r\n\r\n").partition(b"\r\n\r\n")
    if not head.startswith(b"HTTP/1.0 200 Connection Established"):
        hint = " (the firewall's SSL VPN daemon is down; Zyxel's client suggests a reboot)" if b"502" in head else ""
        sys.exit(f"CONNECT refused{hint}: {head[:200]!r}")
    s.sendall(f"GET /NetExtInit {tok}".encode())
    buf = rest
    while b"</configuration>" not in buf:
        d = s.recv(4096)
        if not d:
            sys.exit(f"incomplete configuration: {buf[:300]!r}")
        buf += d
    xml, _, extra = buf.partition(b"</configuration>")
    xml = xml.decode("latin1") + "</configuration>"
    if a.verbose:
        print(xml, file=sys.stderr)
    s.sendall(f"GET /NetExtDone {tok}".encode())
    return s, parse_config(xml), extra


def parse_config(xml):
    tag = lambda name, text: re.findall(rf"<{name}>\s*([^<]*?)\s*</{name}>", text, re.I)
    node = re.search(r"<node>(.*?)</node>", xml, re.I | re.S)
    if not node:
        sys.exit("XML without <node>:\n" + xml)
    n = node.group(1)
    areas = [(tag("ip", x)[0], tag("mask", x)[0]) for x in re.findall(r"<area>(.*?)</area>", xml, re.I | re.S)
             if tag("ip", x) and tag("mask", x)]
    return {"ip": tag("ip", n)[0], "mask": (tag("mask", n) or ["255.255.255.255"])[0],
            "peer": tag("localip", n)[0], "dns": tag("dns", xml)[:8], "areas": areas[:8]}


def sh(*cmd, check=True, quiet=False):
    if not quiet:
        print("+", " ".join(cmd), file=sys.stderr)
    return subprocess.run(cmd, check=check, stderr=subprocess.DEVNULL if quiet else None)


def setup_tun(name, cfg, no_dns):
    fd = os.open("/dev/net/tun", os.O_RDWR)
    ifr = fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH", name.encode(), IFF_TUN | IFF_NO_PI))
    name = ifr[:16].rstrip(b"\0").decode()
    sh("ip", "link", "set", name, "mtu", str(MTU), "up")
    sh("ip", "addr", "add", cfg["ip"], "peer", cfg["peer"], "dev", name)
    for net, mask in cfg["areas"]:
        sh("ip", "route", "replace", f"{net}/{mask}", "dev", name)
    if cfg["dns"] and not no_dns:
        if shutil.which("resolvectl"):
            sh("resolvectl", "dns", name, *cfg["dns"], check=False)
        else:
            print("resolvectl not found, DNS servers not set:", cfg["dns"], file=sys.stderr)
    return fd, name  # non-persistent tun: closing fd removes the interface, its routes and DNS


def nft_ruleset(tun, lan, nat):
    """nft table (family ip) for gateway mode. Packets from the tunnel may only belong to connections that
    started on the LAN side; TCP MSS follows the tunnel MTU; LAN source addresses are masqueraded."""
    fwd = [f'iifname "{tun}" ct state != {{ established, related }} drop']
    if lan:
        fwd.append(f'oifname "{tun}" iifname != "{lan}" drop')
    fwd.append(f'oifname "{tun}" tcp flags syn tcp option maxseg size set rt mtu')
    lines = [f"table ip {RULE_TAG} {{", "  chain forward {", "    type filter hook forward priority -10; policy accept;"]
    lines += [f"    {r}" for r in fwd] + ["  }"]
    if nat:
        lines += ["  chain postrouting {", "    type nat hook postrouting priority srcnat; policy accept;",
                  f'    oifname "{tun}" masquerade', "  }"]
    return "\n".join(lines + ["}"]) + "\n"


def ipt_rules(tun, lan, nat):
    """iptables rules (table, chain, spec) in the order they must have in the chain. Used when nft is missing."""
    rules = [("filter", "FORWARD", ["-i", tun, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"]),
             ("filter", "FORWARD", ["-i", tun, "-j", "DROP"])]
    if lan:
        rules.append(("filter", "FORWARD", ["-o", tun, "!", "-i", lan, "-j", "DROP"]))
    rules.append(("mangle", "FORWARD", ["-o", tun, "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
                                        "-j", "TCPMSS", "--clamp-mss-to-pmtu"]))
    rules.append(("filter", "FORWARD", ["-o", tun, "-j", "ACCEPT"]))
    if nat:
        rules.append(("nat", "POSTROUTING", ["-o", tun, "-j", "MASQUERADE"]))
    return [(t, c, s + ["-m", "comment", "--comment", RULE_TAG]) for t, c, s in rules]


def ipt_apply(rules, add):
    for table, chain, spec in (reversed(rules) if add else rules):
        if add and table == "filter":
            sh("iptables", "-t", table, "-I", chain, "1", *spec)  # reversed loop: final order = list order
        elif add:
            sh("iptables", "-t", table, "-A", chain, *spec)
        else:
            sh("iptables", "-t", table, "-D", chain, *spec, check=False, quiet=True)


def setup_forward(tun, lan, nat):
    """Gateway mode: enable IPv4 forwarding and install the firewall rules. Returns the state for teardown_forward."""
    if lan and (not IFNAME_RE.match(lan) or not os.path.isdir(f"/sys/class/net/{lan}")):
        sys.exit(f"--lan-iface {lan!r}: interface not found")
    with open(IP_FORWARD) as f:
        st = {"prev": f.read().strip(), "backend": None, "rules": None}
    try:
        print(f"+ echo 1 > {IP_FORWARD}  (was {st['prev']})", file=sys.stderr)
        try:
            with open(IP_FORWARD, "w") as f:
                f.write("1")
        except OSError as e:  # read-only /proc/sys in a container: fine if the host already forwards
            if st["prev"] != "1":
                raise
            print(f"ip_forward already 1, write skipped: {e}", file=sys.stderr)
        if shutil.which("nft"):
            st["backend"] = "nft"
            sh("nft", "delete", "table", "ip", RULE_TAG, check=False, quiet=True)  # leftover of a killed run
            ruleset = nft_ruleset(tun, lan, nat)
            print(f"+ nft -f -\n{ruleset}", file=sys.stderr, end="")
            subprocess.run(["nft", "-f", "-"], input=ruleset.encode(), check=True)
            if shutil.which("iptables"):
                pol = subprocess.run(["iptables", "-S", "FORWARD"], capture_output=True, text=True, check=False).stdout
                if "-P FORWARD DROP" in pol:
                    print("warning: iptables FORWARD policy is DROP (ufw, docker?). Packets from the LAN may be "
                          "dropped before they reach the tunnel; allow them in that firewall.", file=sys.stderr)
        elif shutil.which("iptables"):
            st["backend"], st["rules"] = "iptables", ipt_rules(tun, lan, nat)
            ipt_apply(st["rules"], add=False)  # leftover of a killed run: removes rules with the same spec
            ipt_apply(st["rules"], add=True)
        else:
            sys.exit("neither nft nor iptables found: cannot configure forwarding")
    except (subprocess.CalledProcessError, OSError) as e:
        teardown_forward(st)
        sys.exit(f"gateway setup failed: {e}")
    except BaseException:
        teardown_forward(st)
        raise
    return st


def teardown_forward(st):
    if st["backend"] == "nft":
        sh("nft", "delete", "table", "ip", RULE_TAG, check=False, quiet=True)
    elif st["backend"] == "iptables":
        ipt_apply(st["rules"], add=False)
    try:
        with open(IP_FORWARD, "w") as f:
            f.write(st["prev"])
    except OSError as e:
        print("ip_forward not restored:", e, file=sys.stderr)


def pump(s, fd, extra, verbose):
    buf, first = extra, True
    while True:
        r = [s] if s.pending() else select.select([s, fd], [], [])[0]
        if fd in r:
            pkt = os.read(fd, 65535)
            s.sendall(struct.pack(">H", len(pkt)) + pkt)
        if s in r:
            d = s.recv(65536)
            if not d:
                print("tunnel closed by the firewall", file=sys.stderr)
                return
            buf += d
            while len(buf) >= 2 and len(buf) >= 2 + (n := struct.unpack(">H", buf[:2])[0]):
                pkt, buf = buf[2:2 + n], buf[2 + n:]
                if first:
                    first = False
                    if verbose or pkt[:1] and pkt[0] >> 4 not in (4, 6):
                        print("first packet from the firewall:", pkt[:32].hex(), file=sys.stderr)
                os.write(fd, pkt)


def load_options(path):
    """Add-on mode: build the same namespace argparse would produce from the add-on options (/data/options.json)."""
    with open(path) as f:
        o = json.load(f)
    pin = (o.get("certificate_pin") or "").strip()
    insecure = bool(o.get("insecure", False))
    if not insecure and not pin:
        sys.exit("Configuration error: set 'certificate_pin' or enable 'insecure'")
    lan = (o.get("lan_interface") or "").strip() or None
    a = argparse.Namespace(
        host=o["host"].strip(), port=int(o.get("port", 443)), user=o["username"],
        pin=pin, insecure=insecure, dev=(o.get("interface_name") or "zyvpn0").strip(),
        no_dns=True,  # no resolvectl inside the add-on container
        forward=bool(o.get("gateway_mode", False)), lan_iface=lan, no_nat=bool(o.get("no_nat", False)),
        password_stdin=False, verbose=bool(o.get("verbose", False)),
        reconnect=bool(o.get("auto_reconnect", True)), reconnect_delay=int(o.get("reconnect_delay", 15)))
    if (a.lan_iface or a.no_nat) and not a.forward:
        sys.exit("Configuration error: 'lan_interface' and 'no_nat' need 'gateway_mode'")
    return a, o["password"]


def parse_args():
    p = argparse.ArgumentParser(description="Zyxel SSL VPN client (SecuExtender protocol)")
    p.add_argument("host", nargs="?"); p.add_argument("port", nargs="?", type=int); p.add_argument("user", nargs="?")
    p.add_argument("--options-file", metavar="JSON",
                   help="Home Assistant add-on mode: read all settings from this file (e.g. /data/options.json)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--pin", help="sha256 of the firewall certificate (hex)")
    g.add_argument("--insecure", action="store_true", help="do not check the certificate")
    p.add_argument("--dev", default="zyvpn%d", help="tun interface name")
    p.add_argument("--no-dns", action="store_true", help="ignore the DNS servers pushed by the firewall")
    p.add_argument("--forward", action="store_true",
                   help="gateway mode: enable IPv4 forwarding and NAT so LAN hosts that use this machine as gateway "
                        "reach the networks behind the tunnel (undone on exit)")
    p.add_argument("--lan-iface", metavar="IFACE",
                   help="with --forward: only forward packets that enter from this interface to the tunnel")
    p.add_argument("--no-nat", action="store_true",
                   help="with --forward: do not masquerade (the remote side must route the LAN back to the tunnel)")
    p.add_argument("--password-stdin", action="store_true",
                   help="read the password from the first line of stdin; disconnect when stdin is closed")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    a = p.parse_args()
    if a.options_file:
        return a
    if not (a.host and a.port and a.user):
        p.error("host, port and user are required (or use --options-file)")
    if not (a.pin or a.insecure):
        p.error("one of --pin or --insecure is required")
    if (a.lan_iface or a.no_nat) and not a.forward:
        p.error("--lan-iface and --no-nat need --forward")
    a.reconnect, a.reconnect_delay = False, 0
    return a


def run_session(a, password):
    tok = login(a, password)
    print("login ok", file=sys.stderr)
    try:
        s, cfg, extra = negotiate(a, tok)
        s.settimeout(None)
        print(f"tunnel: ip {cfg['ip']} peer {cfg['peer']} dns {cfg['dns']} routes {cfg['areas']}", file=sys.stderr)
        fd, name = setup_tun(a.dev, cfg, a.no_dns)
        fwd = None
        try:
            if a.forward:
                fwd = setup_forward(name, a.lan_iface, not a.no_nat)
            print(f"connected on {name}, Ctrl+C to disconnect", file=sys.stderr)
            pump(s, fd, extra, a.verbose)
        finally:
            if fwd:
                teardown_forward(fwd)
            os.close(fd)
            s.close()
    finally:
        logout(a, tok)
        print("logged out", file=sys.stderr)


def main():
    a = parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (tun device, routes)")
    if a.options_file:
        a, password = load_options(a.options_file)
    elif a.password_stdin:
        password = sys.stdin.readline().rstrip("\n")
    else:
        password = os.environ.get("ZYXEL_VPN_PASSWORD") or getpass.getpass("Password: ")
    for sig in (signal.SIGINT, signal.SIGTERM):  # kill and systemd stop must log out too
        signal.signal(sig, signal.default_int_handler)
    if a.password_stdin:  # the GUI runs us as root through pkexec and cannot signal us: it closes stdin instead
        threading.Thread(target=lambda: (sys.stdin.read(), os.kill(os.getpid(), signal.SIGTERM)), daemon=True).start()

    try:
        while True:
            try:
                run_session(a, password)
            except SystemExit as e:  # login/negotiation errors call sys.exit(message)
                if not a.reconnect:
                    raise
                print(f"error: {e.code}", file=sys.stderr)
            except (OSError, ConnectionError, ssl.SSLError) as e:
                if not a.reconnect:
                    raise
                print(f"connection error: {e}", file=sys.stderr)
            if not a.reconnect:
                break
            print(f"reconnecting in {a.reconnect_delay}s", file=sys.stderr)
            time.sleep(a.reconnect_delay)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
