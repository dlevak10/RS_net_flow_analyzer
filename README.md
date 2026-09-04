# NetFlow Analyzer

Cilj projekta je napraviti backend aplikaciju za prikupljanje, spremanje i analizu mreznog prometa u NetFlow formatu. Aplikacija je zamisljena kao FastAPI servis koji prima NetFlow zapise s MikroTik routera, sprema ih u bazu te omogucava pregled statistike prometa, detekciju anomalija itd.

## Rad Sustava

1. MikroTik routeri salju NetFlow podatke prema backend servisu.
2. UDP collector na portu 2055 prima NetFlow/IPFIX pakete s MikroTik routera, parsira ih i sprema flow zapise u JSONL format.
2. REST endpoint `/ingest` prima JSON zapise u NetFlow formatu (izvorna IP adresa, odredisna IP adresa, protokol, broj bajtova i vrijeme zapisa)
3. Zaprimljeni zapisi ce se spremati u NoSQL bazu podataka (MongoDB ili DynamoDB)
4. Spark nodovi ce paralelno obradivati spremljene podatke.
5. Endpoint `/alerts` vraca detektirane anomalije u prometu.
6. Endpoint `/stats` vracaa statistiku prometa (npr. najcesce IP adrese, protokole i nekakav trend bandwidtha)
7. Endpoint `/login` sluzi za prijavu usera i izdavanje JWT tokena.

## Endpointi

- `POST /ingest` - primanje NetFlow zapisa
- `GET /alerts` - dohvat detektiranih alerata
- `GET /stats` - dohvat statistike prometa
- `POST /login` - autentifikaciju korisnika pomocu JWT-a

## Struktura Projekta

```text
app/
  main.py
  api/
    routes/
      ingest.py
      alerts.py
      stats.py
      login.py
  db/
  templates/
    login.html
  static/
    css/
      main.css
  models/
    netflow.py
    alert.py
    token.py
  services/
    netflow_parser.py
    alert_detector.py
    stats_calculator.py
    auth_service.py
```

## Opis Strukture

- `app/main.py` - glavna FastAPI app i registracija ruta
- `app/api/routes/` - API endpointi odvojeni po funkcionalnosti
- `app/templates/` - HTML stranice
- `app/static/` - CSS iS
- `app/models/` - definiranje oblika podataka koje aplikacija prima i vraca (izgled netflow zapisa koji dolazi na /ingest, struktura alerta koji dolazi na /alert, info vezan za JWT tokene)
- `app/services/` - parsiranje NetFlow zapisa, detekcija anomalija, racunanje statistike i autentifikacija
- `app/db/` - logika za povezivanje s bazom podataka


## Lokalno Pokretanje

```bash
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Basic NetFlow Collector Bez Baze

Pokretanje UDP collectora:

```bash
python -m app.services.udp_netflow_collector
```

MikroTik target:

```text
Dst. Address: IP adresa laptopa
Port: 2055
Version: 9 ili IPFIX
```

Collector sprema dvije datoteke:

- `logs/netflow-udp.jsonl` - raw UDP paketi, payload je spremljen kao Base64
- `logs/flows.jsonl` - parsirani flow zapisi (`src_ip`, `dst_ip`, `src_port`, `dst_port`, `protocol`, `bytes`, `packets`)

pracenje logova kroz drugi terminal:

```bash
Get-Content -Wait .\logs\flows.jsonl
```
