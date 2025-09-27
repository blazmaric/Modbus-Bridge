#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Seltron WDC <-> Modbus TCP TRANSPARENT PROXY (ACTIVE, ASCII-only) z vrsto zahtev, cache TTL in de-dupe branj

- WDC je MASTER na RS-232 (Modbus ASCII, 9600-N-8-1; Seltron EXT).
- Ta skripta je SCADA SLAVE s fiksnim UNIT_ID = 128 in pretvarja TCP READ/WRITE
  v EXT (phase-1 + phase-2). Node-RED/HA uporablja enake naslove kot WDC.

Optimizacije proti timeoutom:
  • Serve-from-cache (TTL): če je blok svež (npr. <5 s), vrnemo takoj.
  • De-duplication: več vzporednih enakih branj (start, qty) deli isti pending req.

Odvisnosti:
  pip3 install pyserial pymodbus==3.6.6
"""

import sys, time, threading, serial, re, argparse
from dataclasses import dataclass, field
from typing import List, Optional, Deque, Tuple, Dict
from collections import deque

# =================== PRIVZETE NASTAVITVE ===================
UNIT_ID      = 0x80      # FIKSNO: 128 (SCADA)
EXT_BASE     = 0x1000    # EXT okno (faza-1)
SERIAL_BAUD  = 9600
TCP_BIND     = "0.0.0.0"
IMAGE_SIZE   = 8192

# =================== GLOBALNO STANJE ===================
image:   List[int] = [0]*IMAGE_SIZE           # zadnje znane vrednosti
last_ts: List[float] = [0.0]*IMAGE_SIZE       # timestamp posodobitve vsakega registra
outbox:  List[int] = [0]*IMAGE_SIZE           # write buffer
image_lock = threading.Lock()

@dataclass
class Req:
    op: str                    # "read" ali "write"
    start: int
    qty: int
    values: Optional[List[int]] = None
    done: bool = False
    error: Optional[str] = None
    cond: threading.Condition = field(default_factory=lambda: threading.Condition())

# Vrsta, trenutno aktivna, in de-dupe mapa
queue_lock   = threading.Lock()
queue_cond   = threading.Condition(queue_lock)
req_queue: Deque[Req] = deque()
current_req: Optional[Req] = None
pending_reads: Dict[Tuple[int,int], Req] = {}   # (start,qty) -> Req, za de-dupe

# =================== POMOŽNE ===================
HEX_RE = re.compile(br'^[0-9A-Fa-f]+$')

def clamp16(x: int) -> int:
    return x & 0xFFFF

def hexdump(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)

# ------------------- ASCII utili -------------------
def lrc(payload: bytes) -> int:
    s = 0
    for b in payload:
        s = (s + b) & 0xFF
    return (-s) & 0xFF

def ascii_build(addr: int, fn: int, body: bytes) -> bytes:
    raw = bytes([addr, fn]) + body
    return b':' + (raw + bytes([lrc(raw)])).hex().upper().encode() + b'\r\n'

def ascii_parse(frame: bytes) -> Tuple[int,int,bytes]:
    if not (frame.startswith(b':') and frame.endswith(b'\r\n')):
        raise ValueError("ASCII: bad delimiters")
    hexpart = frame[1:-2]
    if not HEX_RE.match(hexpart):
        raise ValueError("ASCII: non-hex")
    raw = bytes.fromhex(hexpart.decode('ascii'))
    if len(raw) < 4:
        raise ValueError("ASCII: too short")
    if raw[-1] != lrc(raw[:-1]):
        raise ValueError("ASCII: LRC mismatch")
    return raw[0], raw[1], raw[2:-1]

# =================== RS232 SLAVE (ASCII-only) ===================
class SeltronExtSlave(threading.Thread):
    def __init__(self, port: str, debug: bool):
        super().__init__(daemon=True)
        self.ser = serial.Serial(
            port=port, baudrate=SERIAL_BAUD,
            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE, timeout=0.05,
        )
        self.rx_buf = b""
        self.debug = debug

    def run(self):
        while True:
            try:
                chunk = self.ser.read(256)
                if chunk:
                    self.rx_buf += chunk
                    if len(self.rx_buf) > 16384:
                        self.rx_buf = self.rx_buf[-4096:]

                    while True:
                        i = self.rx_buf.find(b':')
                        if i < 0:
                            self.rx_buf = b""  # počisti šum pred ':'
                            break
                        if i > 0:
                            self.rx_buf = self.rx_buf[i:]
                        j = self.rx_buf.find(b'\r\n')
                        if j < 0:
                            break

                        frame = self.rx_buf[:j+2]
                        self.rx_buf = self.rx_buf[j+2:]

                        try:
                            addr, fn, body = ascii_parse(frame)
                        except Exception:
                            continue

                        if addr == UNIT_ID:
                            self._handle_pdu(fn, body)

            except Exception as e:
                print(f"[SER] Error: {e}", file=sys.stderr)
                time.sleep(0.05)

    def _send(self, fn: int, body: bytes):
        pkt = ascii_build(UNIT_ID, fn, body)
        if self.debug:
            print(f"[TX] {hexdump(pkt)}")
        self.ser.write(pkt)

    def _handle_pdu(self, fn: int, body: bytes):
        global current_req
        # ---------- EXT phase-1 ----------
        if fn == 0x03 and len(body) == 4:
            start = (body[0] << 8) | body[1]
            qty   = (body[2] << 8) | body[3]
            if start == EXT_BASE and qty == 3:
                with queue_lock:
                    if current_req is None and req_queue:
                        current_req = req_queue.popleft()
                    req = current_req
                if self.debug:
                    print("[SER] EXT phase-1 from WDC")
                if not req:
                    EXTFU, EXTADDR, EXTNOREG = 0x10, 0x0000, 0x0000
                else:
                    if req.op == "read":
                        EXTFU, EXTADDR, EXTNOREG = 0x10, req.start, req.qty
                    else:  # write
                        EXTFU, EXTADDR, EXTNOREG = 0x03, req.start, req.qty
                payload = bytes([
                    6,
                    (EXTFU>>8)&0xFF, EXTFU&0xFF,
                    (EXTADDR>>8)&0xFF, EXTADDR&0xFF,
                    (EXTNOREG>>8)&0xFF, EXTNOREG&0xFF
                ])
                self._send(0x03, payload)
                return

            # ---------- WRITE scenarij: WDC bere naše podatke ----------
            with queue_lock:
                req = current_req
            if req and req.op == "write" and start == req.start and qty == req.qty:
                with image_lock:
                    vals = outbox[start:start+qty]
                resp = bytes([qty*2]) + b''.join(bytes([(v>>8)&0xFF, v&0xFF]) for v in vals)
                self._send(0x03, resp)
                # finish write
                with req.cond:
                    req.done = True
                    req.cond.notify_all()
                with queue_lock:
                    with image_lock:
                        now = time.monotonic()
                        for i,v in enumerate(vals):
                            idx = start+i
                            if idx < IMAGE_SIZE:
                                image[idx] = clamp16(v)
                                last_ts[idx] = now
                    current_req = None
                return
            return

        # ---------- READ phase-2: WDC z 0x10 piše rezultate ----------
        if fn == 0x10 and len(body) >= 5:
            start = (body[0] << 8) | body[1]
            qty   = (body[2] << 8) | body[3]
            bc    = body[4]
            if bc == qty*2 and len(body) == 5+bc:
                vals = [ (body[5+2*i] << 8) | body[5+2*i+1] for i in range(qty) ]
                now  = time.monotonic()
                with image_lock:
                    for i,v in enumerate(vals):
                        idx = start+i
                        if idx < IMAGE_SIZE:
                            image[idx] = clamp16(v)
                            last_ts[idx] = now
                if self.debug:
                    print(f"[SER] EXT phase-2 values start={start} qty={qty}")
                # ACK
                ack = bytes([(start>>8)&0xFF, start&0xFF, (qty>>8)&0xFF, qty&0xFF])
                self._send(0x10, ack)
                # zaključek READ pendinga
                with queue_lock:
                    req = current_req
                    if req and req.op == "read" and req.start == start and req.qty == qty:
                        with req.cond:
                            req.done = True
                            req.cond.notify_all()
                        # odstrani iz de-dupe mape
                        pending_reads.pop((req.start, req.qty), None)
                        current_req = None
                return

# =================== Modbus TCP ===================
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore.store import BaseModbusDataBlock
from pymodbus.device import ModbusDeviceIdentification

class ProxyDataBlock(BaseModbusDataBlock):
    def __init__(self, timeout_sec: float, cache_ttl: float):
        super().__init__()
        self.timeout_sec = timeout_sec
        self.cache_ttl = cache_ttl

    def validate(self, address, count=1):
        start = int(address); end = start + int(count)
        return 0 <= start < IMAGE_SIZE and 0 < end <= IMAGE_SIZE

    def _enqueue_and_wait(self, req: Req):
        with queue_lock:
            req_queue.append(req)
            queue_cond.notify_all()
        end_by = time.monotonic() + self.timeout_sec
        with req.cond:
            while not req.done and req.error is None:
                remaining = end_by - time.monotonic()
                if remaining <= 0:
                    break
                req.cond.wait(remaining)
        if not req.done:
            # počisti iz vrste, če še čaka
            with queue_lock:
                try:
                    if req in req_queue:
                        req_queue.remove(req)
                except ValueError:
                    pass
            raise RuntimeError("Timeout waiting WDC (no EXT phase-2)")

    def _read_from_cache(self, start: int, qty: int) -> Optional[List[int]]:
        now = time.monotonic()
        with image_lock:
            for i in range(qty):
                idx = start + i
                if idx >= IMAGE_SIZE or (now - last_ts[idx]) > self.cache_ttl:
                    return None
            return [image[start+i] for i in range(qty)]

    def getValues(self, address, count=1):
        start = int(address); qty = int(count)

        # 1) poskusi iz cache-a
        cached = self._read_from_cache(start, qty)
        if cached is not None:
            return cached

        # 2) de-dupe: če že obstaja pending za isti (start,qty), čakaj nanj
        key = (start, qty)
        with queue_lock:
            existing = pending_reads.get(key)
            if existing is not None:
                req = existing
            else:
                req = Req(op="read", start=start, qty=qty)
                pending_reads[key] = req
                req_queue.append(req)
                queue_cond.notify_all()

        # 3) počakaj na dokončanje (ali timeout)
        end_by = time.monotonic() + self.timeout_sec
        with req.cond:
            while not req.done and req.error is None:
                remaining = end_by - time.monotonic()
                if remaining <= 0:
                    break
                req.cond.wait(remaining)

        # 4) če je to bil “prvotni” req in ni uspel, odstrani iz mape
        with queue_lock:
            if pending_reads.get(key) is req and not req.done:
                pending_reads.pop(key, None)

        if not req.done:
            raise RuntimeError("Timeout waiting WDC (no EXT phase-2)")

        # 5) vrni iz cache-a
        cached2 = self._read_from_cache(start, qty)
        if cached2 is None:
            # v teoriji ne bi smelo, ampak za vsak slučaj
            with image_lock:
                return [image[start+i] for i in range(qty)]
        return cached2

    def setValues(self, address, values):
        if isinstance(values, int):
            values = [values]
        vals  = [clamp16(int(v)) for v in values]
        start = int(address); qty = len(vals)

        # outbox napolnimo vnaprej
        with image_lock:
            for i,v in enumerate(vals):
                idx = start+i
                if idx < IMAGE_SIZE:
                    outbox[idx] = v

        # write nima smisla de-dupat; vsak je lahko drugačen
        req = Req(op="write", start=start, qty=qty, values=vals)
        self._enqueue_and_wait(req)
        # image se posodobi v handlerju

def run_tcp(timeout_sec: float, tcp_port: int, cache_ttl: float):
    block   = ProxyDataBlock(timeout_sec, cache_ttl)
    store   = ModbusSlaveContext(hr=block, zero_mode=True)
    context = ModbusServerContext(slaves=store, single=True)
    identity = ModbusDeviceIdentification()
    identity.VendorName  = "Seltron-Ext-Proxy"
    identity.ProductCode = "WDC-PROXY"
    identity.VendorUrl   = "local"
    identity.ProductName = "WDC RS232 (ASCII) <-> Modbus TCP Transparent Proxy"
    identity.ModelName   = "EXT-Translator [unit=128, cache+dedupe]"
    identity.MajorMinorRevision = "3.0"
    StartTcpServer(context=context, identity=identity, address=(TCP_BIND, tcp_port))

# =================== MAIN ===================
def main():
    ap = argparse.ArgumentParser(description="Seltron WDC <-> Modbus TCP Proxy (ASCII-only, unit=128)")
    ap.add_argument("--serial", default="/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_AE01KJE4-if00-port0",
                    help="RS232 port pot")
    ap.add_argument("--timeout", type=float, default=30.0,
                    help="TCP zahtevek timeout (s) za EXT fazo-2")
    ap.add_argument("--cache-ttl", type=float, default=5.0,
                    help="koliko dolgo se šteje blok kot svež (s)")
    ap.add_argument("--tcp-port", type=int, default=5020,
                    help="TCP port (privzeto 5020)")
    ap.add_argument("--debug", action="store_true", help="izpisi EXT faze in TX hexdump")
    args = ap.parse_args()

    print(f"[INFO] Transparent proxy up (ASCII-only). Serial: {args.serial} UNIT_ID={UNIT_ID}; "
          f"TCP: {TCP_BIND}:{args.tcp_port}; TIMEOUT={args.timeout}s; CACHE_TTL={args.cache_ttl}s; DEBUG={args.debug}")

    ser_slave = SeltronExtSlave(args.serial, debug=args.debug)
    ser_slave.start()
    run_tcp(timeout_sec=args.timeout, tcp_port=args.tcp_port, cache_ttl=args.cache_ttl)

if __name__ == "__main__":
    main()
