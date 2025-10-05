#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Seltron WDC <-> Modbus TCP TRANSPARENT PROXY (ASCII-only) + lokalni "DD2+ K1" SLAVE

- RS-232: WDC je MASTER (Modbus ASCII, 9600-N-8-1; EXT cikel).
- TCP:
  * UNIT 128  → proxy na RS-232 (kot prej).
  * UNIT 4    → lokalna simulacija DD2+ za Krog 1 (K1), z 10 registri 400151..400160
                 (zero_mode address 150..159), auto-checksum in prisilnimi polji.

Odvisnosti: pip3 install pyserial pymodbus==3.6.6
"""

import sys, time, threading, serial, re, argparse
from dataclasses import dataclass, field
from typing import List, Optional, Deque, Tuple, Dict
from collections import deque

# =================== PRIVZETE NASTAVITVE ===================

SCADA_UNIT_ID = 0x80            # 128 (SCADA proxy – kot prej)
LOCAL_UNIT_ID = 4               # <<<< LOKALNI SLAVE UID = 4 >>>>
EXT_BASE       = 0x1000         # EXT okno (phase-1 read start)
SERIAL_BAUD    = 9600
TCP_BIND       = "0.0.0.0"
IMAGE_SIZE     = 8192

# --- DD2+ K1 blok (10 registrov), absolutni naslovi (zero_mode) ---
K1_BASE = 150             # 400151
K1_LEN  = 10              # 400151..400160

# indeksi znotraj bloka (0-based offset od K1_BASE)
IDX_SETPOINT   = 0  # 400151
IDX_ROOMTEMP   = 1  # 400152
IDX_MODE       = 2  # 400153
IDX_INFLUENCE  = 3  # 400154
IDX_OFFSET     = 4  # 400155
IDX_STATUS     = 5  # 400156
IDX_DEMAND     = 6  # 400157
IDX_RESERVED   = 7  # 400158
IDX_IDENT      = 8  # 400159
IDX_CHECKSUM   = 9  # 400160

# privzete/pritrdilne vrednosti
IDENT_DD2      = 0x1003
INFLUENCE_K1   = 0x0001   # K1 (prisilno)
STATUS_OK      = 0x0000
RESERVED_ZERO  = 0x0000

# Parametri EXT cikla
MAX_QTY_PER_REQ               = 12
CHUNK_GAP_SEC                 = 0.03
EXT_QUIET_AFTER_PHASE1_SEC    = 0.40
POST_WRITE_SETTLE_SEC         = 0.20

# =================== GLOBALNO STANJE ===================

image:   List[int]  = [0] * IMAGE_SIZE
last_ts: List[float]= [0.0] * IMAGE_SIZE
outbox:  List[int]  = [0] * IMAGE_SIZE

image_lock = threading.Lock()

@dataclass
class Req:
    op: str                   # "read" ali "write"
    start: int
    qty: int
    values: Optional[List[int]] = None
    done: bool = False
    error: Optional[str] = None
    cond: threading.Condition = field(default_factory=lambda: threading.Condition())

queue_lock = threading.Lock()
queue_cond = threading.Condition(queue_lock)
req_queue: Deque[Req] = deque()
current_req: Optional[Req] = None
pending_reads: Dict[Tuple[int,int], Req] = {}  # (start,qty) -> Req

HEX_RE = re.compile(br'^[0-9A-Fa-f]+$')

def clamp16(x: int) -> int:
    return x & 0xFFFF

def hexdump(b: bytes) -> str:
    return ' '.join(f'{x:02X}' for x in b)

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
            bytesize=serial.EIGHTBITS, parity=serial.PARITY_NONE, stopbits=serial.STOPBITS_ONE,
            timeout=0.05,
        )
        self.rx_buf = b""
        self.debug = debug
        self.quiet_until = 0.0

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
                            self.rx_buf = b""
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

                        if addr == SCADA_UNIT_ID:
                            self._handle_pdu(fn, body)
            except Exception as e:
                print(f"[SER] Error: {e}", file=sys.stderr)
                time.sleep(0.05)

    def _send(self, fn: int, body: bytes):
        now = time.monotonic()
        if now < self.quiet_until:
            time.sleep(self.quiet_until - now)
        pkt = ascii_build(SCADA_UNIT_ID, fn, body)
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

                self.quiet_until = time.monotonic() + EXT_QUIET_AFTER_PHASE1_SEC

                if not req:
                    EXTFU, EXTADDR, EXTNOREG = 0x10, 0x0000, 0x0000
                else:
                    if req.op == "read":
                        EXTFU, EXTADDR, EXTNOREG = 0x10, req.start, req.qty
                    else:
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
            if req and req.op == "write":
                start = (body[0] << 8) | body[1] if len(body) >= 2 else None
                qty   = (body[2] << 8) | body[3] if len(body) >= 4 else None

                if start == req.start and qty == req.qty:
                    with image_lock:
                        vals = outbox[start:start+qty]
                        resp = bytes([qty*2]) + b''.join(bytes([(v>>8)&0xFF, v&0xFF]) for v in vals)
                    self._send(0x03, resp)

                    with req.cond:
                        req.done = True
                        req.cond.notify_all()

                    with image_lock:
                        now = time.monotonic()
                        for i, v in enumerate(vals):
                            idx = start + i
                            if idx < IMAGE_SIZE:
                                image[idx] = clamp16(v)
                                last_ts[idx] = now

                    current_req = None
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
                    for i, v in enumerate(vals):
                        idx = start + i
                        if idx < IMAGE_SIZE:
                            image[idx] = clamp16(v)
                            last_ts[idx] = now

                if self.debug:
                    print(f"[SER] EXT phase-2 values start={start} qty={qty}")

                ack = bytes([
                    (start>>8)&0xFF, start&0xFF,
                    (qty>>8)&0xFF,   qty&0xFF
                ])
                self._send(0x10, ack)

                with queue_lock:
                    req = current_req
                    if req and req.op == "read" and req.start == start and req.qty == qty:
                        with req.cond:
                            req.done = True
                            req.cond.notify_all()
                        pending_reads.pop((req.start, req.qty), None)
                        current_req = None
                return

# =================== Modbus TCP ===================

from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext
from pymodbus.datastore.store import BaseModbusDataBlock
from pymodbus.device import ModbusDeviceIdentification

def _recalc_k1_checksum(img: list):
    s = 0
    for i in range(K1_LEN - 1):  # 0..8
        s = (s + (img[K1_BASE + i] & 0xFFFF)) & 0xFFFF
    return s

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

    def _blocking_read_once(self, start: int, qty: int) -> Optional[List[int]]:
        cached = self._read_from_cache(start, qty)
        if cached is not None:
            return cached

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

        end_by = time.monotonic() + self.timeout_sec
        with req.cond:
            while not req.done and req.error is None:
                remaining = end_by - time.monotonic()
                if remaining <= 0:
                    break
                req.cond.wait(remaining)

        with queue_lock:
            if pending_reads.get(key) is req and not req.done:
                pending_reads.pop(key, None)

        if not req.done:
            return None

        return self._read_from_cache(start, qty)

    def getValues(self, address, count=1):
        start = int(address)
        total_qty = int(count)
        if total_qty <= MAX_QTY_PER_REQ:
            vals = self._blocking_read_once(start, total_qty)
            if vals is not None:
                return vals
            with image_lock:
                return [image[start+i] for i in range(total_qty)]

        out: List[int] = []
        done = 0
        while done < total_qty:
            chunk_qty   = min(MAX_QTY_PER_REQ, total_qty - done)
            chunk_start = start + done
            vals = self._blocking_read_once(chunk_start, chunk_qty)
            if vals is None:
                with image_lock:
                    vals = [image[chunk_start+i] for i in range(chunk_qty)]
            out.extend(vals)
            done += chunk_qty
            time.sleep(CHUNK_GAP_SEC)
        return out

    def setValues(self, address, values):
        if isinstance(values, int):
            values = [values]
        vals  = [clamp16(int(v)) for v in values]
        start = int(address)
        qty   = len(vals)

        with image_lock:
            for i, v in enumerate(vals):
                idx = start + i
                if idx < IMAGE_SIZE:
                    outbox[idx] = v

        req = Req(op="write", start=start, qty=qty, values=vals)
        self._enqueue_and_wait(req)
        time.sleep(POST_WRITE_SETTLE_SEC)

class LocalMirrorBlock(BaseModbusDataBlock):
    """
    UID 4: simulacija DD2+ za Krog 1 (K1) – izključno blok 400151..400160
    - Dovolimo branje/zapis le v range [K1_BASE .. K1_BASE + K1_LEN - 1]
    - Ob vsakem zapisu:
        * prisilimo INFLUENCE=K1, IDENT=0x1003, STATUS=0, RESERVED=0
        * preračunamo CHECKSUM (zadnji register v bloku)
        * enqueuamo WRITE (cel blok), da WDC prebere “cel paket”
    """
    def __init__(self, timeout_sec: float):
        super().__init__()
        self.timeout_sec = timeout_sec

    def validate(self, address, count=1):
        start = int(address)
        end   = start + int(count)
        return (start >= K1_BASE) and (end <= K1_BASE + K1_LEN)

    def _enqueue_and_wait_write(self, start: int, qty: int, vals: List[int]):
        req = Req(op="write", start=start, qty=qty, values=vals)
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
        # če WDC ne prebere v timeoutu, vrednosti ostanejo v image/outbox

    def _fix_pinned_fields_and_checksum(self):
        now = time.monotonic()
        with image_lock:
            image[K1_BASE + IDX_INFLUENCE] = INFLUENCE_K1
            image[K1_BASE + IDX_IDENT]     = IDENT_DD2
            image[K1_BASE + IDX_STATUS]    = STATUS_OK
            image[K1_BASE + IDX_RESERVED]  = RESERVED_ZERO
            chk = _recalc_k1_checksum(image)
            image[K1_BASE + IDX_CHECKSUM] = chk
            for i in range(K1_LEN):
                idx = K1_BASE + i
                outbox[idx]   = image[idx] & 0xFFFF
                last_ts[idx]  = now

    def getValues(self, address, count=1):
        start = int(address); qty = int(count)
        with image_lock:
            return [image[start+i] if (start+i) < IMAGE_SIZE else 0 for i in range(qty)]

    def setValues(self, address, values):
        if isinstance(values, int):
            values = [values]
        vals  = [clamp16(int(v)) for v in values]
        start = int(address); qty = len(vals)

        now = time.monotonic()
        with image_lock:
            for i, v in enumerate(vals):
                idx = start + i
                if idx < IMAGE_SIZE:
                    image[idx]  = v
                    outbox[idx] = v
                    last_ts[idx]= now

        self._fix_pinned_fields_and_checksum()

        k1_vals = []
        with image_lock:
            for i in range(K1_LEN):
                k1_vals.append(outbox[K1_BASE + i])
        self._enqueue_and_wait_write(K1_BASE, K1_LEN, k1_vals)

# -------------------- TCP strežnik --------------------

def run_tcp(timeout_sec: float, tcp_port: int, cache_ttl: float):
    block128 = ProxyDataBlock(timeout_sec, cache_ttl)
    store128 = ModbusSlaveContext(hr=block128, zero_mode=True)

    block4 = LocalMirrorBlock(timeout_sec)
    store4 = ModbusSlaveContext(hr=block4, zero_mode=True)

    context = ModbusServerContext(slaves={
        SCADA_UNIT_ID: store128,
        LOCAL_UNIT_ID: store4,
    }, single=False)

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Seltron-Ext-Proxy"
    identity.ProductCode = "WDC-PROXY+LOCAL4"
    identity.VendorUrl = "local"
    identity.ProductName = "WDC RS232 (ASCII) <-> Modbus TCP Proxy + Local UID4 (DD2+ K1)"
    identity.ModelName = f"EXT-Translator [128 proxy + 4 local K1@{K1_BASE}+]"
    identity.MajorMinorRevision = "4.1"

    StartTcpServer(context=context, identity=identity, address=(TCP_BIND, tcp_port))

# =================== MAIN ===================

def main():
    ap = argparse.ArgumentParser(description="Seltron WDC <-> Modbus TCP Proxy (ASCII-only, unit=128) + Local UID4 (DD2+ K1)")
    ap.add_argument("--serial",
                    default="/dev/serial/by-id/usb-FTDI_FT232R_USB_UART_AE01KJE4-if00-port0",
                    help="RS232 port pot")
    ap.add_argument("--timeout", type=float, default=30.0, help="TCP timeout (s) za EXT faze")
    ap.add_argument("--cache-ttl", type=float, default=5.0, help="cache TTL (s) za READ proxya")
    ap.add_argument("--tcp-port", type=int, default=5020, help="TCP port (privzeto 5020)")
    ap.add_argument("--debug", action="store_true", help="debug izpis (EXT faze, TX)")

    args = ap.parse_args()

    print(
        "[INFO] Transparent proxy + lokalni DD2+ K1 up.\n"
        f"Serial: {args.serial} SCADA_UNIT={SCADA_UNIT_ID}; LOCAL_UNIT={LOCAL_UNIT_ID} "
        f"(K1 block {K1_BASE}-{K1_BASE+K1_LEN-1})\n"
        f"TCP: {TCP_BIND}:{args.tcp_port}; TIMEOUT={args.timeout}s; "
        f"CACHE_TTL={args.cache_ttl}s; DEBUG={args.debug}"
    )

    ser_slave = SeltronExtSlave(args.serial, debug=args.debug)
    ser_slave.start()

    run_tcp(timeout_sec=args.timeout, tcp_port=args.tcp_port, cache_ttl=args.cache_ttl)

if __name__ == "__main__":
    main()
