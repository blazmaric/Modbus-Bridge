# DD2+ #1 — fizična enota (UID 3, Krog 1)

**Blok:** 400151–400160 (zero-mode naslovi 150–159)  
**Vir:** odsnifani paketi `:03 10 00 96 00 0A …` (write 10 registrov od 150 naprej).

| #  | Register (Modbus 1-based) | Zero-addr | Ime / namen                           | Tip   | Merilo   | Tipične vrednosti iz sniffa      | Pomen                                               |
|----|---------------------------|-----------|---------------------------------------|-------|----------|-----------------------------------|-----------------------------------------------------|
| 1  | 400151                    | 150       | Setpoint sobne temperature            | R/W   | °C ×100  | 0x0D65 = 34,29 °C; 0x0C9B = 32,27 °C | Želena T prostora.                                 |
| 2  | 400152                    | 151       | Trenutna sobna temperatura            | R/W   | °C ×100  | 0x0C9B = 32,27 °C                 | Izmerjena T prostora.                              |
| 3  | 400153                    | 152       | Način delovanja                       | R/W   | enum     | 0x0002 = URNIK                    | 0=OFF, 1=ROČNO, 2=URNIK (v sniffu pogosto 2).       |
| 4  | 400154                    | 153       | Vpliv sobne enote na mešalni krog     | R/W   | enum     | 0x0001 = K1                       | 0=brez, 1=K1 (radiatorji). Ta DD2+ poroča kot Krog 1. |
| 5  | 400155                    | 154       | Korekcija (offset)                    | R/W   | °C ×100  | 0x000C = +1,2 °C                  | Umerjanje/kompenzacija tipala.                      |
| 6  | 400156                    | 155       | Status tipala/komunikacije            | R/W   | enum     | 0x0000 = OK                       | 0=OK, ≠0 napaka.                                   |
| 7  | 400157                    | 156       | Zahteva za ogrevanje (K1)             | R/W   | bool     | 0x0000                            | 1=ogrevanje aktivno, 0=ne (v tistem ciklu 0).        |
| 8  | 400158                    | 157       | Rezervirano / servis                  | R/W   | —        | 0x0000                            | Trenutno neuporabljeno.                             |
| 9  | 400159                    | 158       | Identifikacija / verzija              | R     | —        | 0x1003                            | ID/revizija DD2+.                                   |
| 10 | 400160                    | 159       | Checksum (integriteta bloka)          | R     | 16-bit   | 0x00DC                            | Vsota prvih 9 registrov & 0xFFFF; WDC preveri veljavnost.|

---

# DD2+ #2 — simulirana enota (UID 4, Krog 1)

**Blok:** 400151–400160 (zero-mode 150–159) — isti razpon kot zgoraj, vendar ga polni tvoja Python skripta (UID 4) in Node-RED.

## Kaj moraš pisati iz Node-RED-a

- **Setpoint** → 400151 (°C×100)
- **Trenutna sobna** → 400152 (°C×100)
- **Način** → 400153 (0=OFF, 1=ROČNO, 2=URNIK)
- **Zahteva** → 400157 (0/1)

## Kaj skripta sama “pritegne”

- 400154 = 1 (influence = K1)
- 400159 = 0x1003 (ident)
- 400156 = 0 (status OK), 400158 = 0 (rezervirano)
- 400160 = auto-checksum (sum prvih 9 registrov & 0xFFFF)

---

| #  | Register (Modbus 1-based) | Zero-addr | Ime / namen            | Tip   | Merilo   | Kdo nastavlja         | Opomba                        |
|----|---------------------------|-----------|------------------------|-------|----------|-----------------------|-------------------------------|
| 1  | 400151                    | 150       | Setpoint sobne T       | R/W   | °C ×100  | Node-RED              | npr. 3000 = 30,00 °C          |
| 2  | 400152                    | 151       | Trenutna sobna T       | R/W   | °C ×100  | Node-RED              | npr. 2875 = 28,75 °C          |
| 3  | 400153                    | 152       | Način delovanja        | R/W   | enum     | Node-RED              | 0=OFF, 1=ROČNO, 2=URNIK       |
| 4  | 400154                    | 153       | Vpliv (Krog)           | R/W   | enum     | skripta               | vedno 1 (K1)                  |
| 5  | 400155                    | 154       | Korekcija (offset)     | R/W   | °C ×100  | Node-RED ali pusti 0  | privzeto 0                    |
| 6  | 400156                    | 155       | Status                 | R/W   | enum     | skripta               | vedno 0 (OK)                  |
| 7  | 400157                    | 156       | Zahteva za ogrevanje   | R/W   | bool     | Node-RED              | 0/1                           |
| 8  | 400158                    | 157       | Rezervirano            | R/W   | —        | skripta               | vedno 0                       |
| 9  | 400159                    | 158       | Identifikacija         | R     | —        | skripta               | 0x1003                        |
| 10 | 400160                    | 159       | Checksum               | R     | 16-bit   | skripta               | izračuna po vsakem zapisu     |