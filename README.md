# Modbus-Bridge

Ta projekt omogoča transparentno povezavo med Seltron WDC EXT (RS-232, Modbus ASCII) in Modbus TCP (npr. Node-RED, SCADA, Home Assistant).

## Opis

- **WDC je MASTER na RS-232 (Modbus ASCII, 9600-N-8-1; Seltron EXT).**
- Ta skripta je Modbus TCP SLAVE (unit=128) in pretvarja TCP zahteve v EXT (phase-1 + phase-2).
- Node-RED/SCADA uporablja enake naslove kot WDC.

### Optimizacije proti timeoutom:
- **Serve-from-cache (TTL):** če je blok svež (privzeto <5 s), se podatki vrnejo takoj.
- **De-duplication:** več vzporednih enakih branj (start, qty) deli isti pending zahtevek.
- **Razbijanje velikih branj:** večja branja se razdelijo na manjše kose, prijazno do EXT cikla.

---

## Topologija

```
[Node-RED/SCADA] --Modbus TCP (unit=128, port=5020)--> [Modbus Bridge] --RS232 EXT--> [WDC (master)]
```

---

## Namestitev

Potrebne knjižnice:
```sh
pip install pyserial pymodbus==3.6.6
```

---

## Zagon

Primer zagona na Windows:
```sh
python modbus.py --serial COM3 --tcp-port 5020 --debug
```
Primer zagona na Linux:
```sh
python3 modbus.py --serial /dev/ttyUSB0 --tcp-port 5020 --debug
```

**Argumenti:**
- `--serial`: RS232 port (npr. COM3 na Windows ali /dev/ttyUSB0 na Linux)
- `--tcp-port`: TCP port za Modbus TCP (privzeto 5020)
- `--timeout`: timeout za EXT fazo-2 (privzeto 30s)
- `--cache-ttl`: koliko časa se šteje blok kot svež (privzeto 5s)
- `--debug`: vklopi izpis EXT faz in hexdump

---

## Primer Node-RED nastavitve

- Modbus TCP node:
  - Host: IP Modbus Bridge naprave
  - Port: 5020
  - Unit ID: 128

---

## Omejitve

- Proxy deluje samo z Modbus ASCII (Seltron EXT).
- Na TCP strani naj bo samo en master hkrati.
- Proxy ne podpira Modbus RTU.

---

## Znane težave

- Če pride do timeouta, se vrne zadnja znana vrednost iz cache-a.
- V primeru težav zaženi s `--debug` za več informacij.

---

## Povzetek kode (`modbus.py`)

Skripta implementira:
- **RS232 listener** za EXT protokol (ASCII-only), ki čaka na zahteve WDC (master).
- **Modbus TCP strežnik** (slave, unit=128), ki sprejema zahteve iz SCADA/Node-RED in jih pretvarja v EXT zahteve.
- **Cache** in **de-duplication** za hitrejše in zanesljivejše odgovore.
- **Razbijanje velikih branj** na manjše kose za prijaznost do EXT cikla.
- **Threading** za sočasno obdelavo serijskih in TCP zahtevkov.

Več informacij najdeš v izvorni kodi [`modbus.py`](modbus.py).