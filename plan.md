# mcprotocol.c hardening e test-suite readiness

Questo documento traduce la specifica operativa in una sequenza di modifiche
incrementali. La regola di distribuzione resta invariabile: il runtime pubblico
e privato della libreria vive soltanto in `api.h` e `api.c`; ogni altro file è
tooling, test, fixture, corpus o documentazione.

## Contesto congelato

- Branch di lavoro: `feat/hardening-test-suite-readiness`.
- Baseline: `0c015e34299593d71ecc93be173be1fdb6770029`.
- Baseline test: `make test` verde il 2026-08-31.
- Toolchain locale: macOS arm64, Apple Clang 21.0.0, Python 3.14.6,
  Node.js 26.7.0 e zlib di sistema.
- Benchmark di caratterizzazione, eseguito su una copia temporanea con tre
  ripetizioni e senza modificare gli artefatti versionati:

  | workload | mediana baseline |
  | --- | ---: |
  | login offline sequenziali | 1.816,530 operazioni/s |
  | stream keepalive | 38.536,091 operazioni/s |
  | keepalive concorrenti | 62.647,691 operazioni/s |

Questi numeri sono una fotografia locale, non ancora un gate: le soglie del
5% e 10% saranno abilitate solo dopo benchmark codec riproducibili e più run.

## Invarianti non negoziabili

- Nessun nuovo file `.c` o `.h` di produzione.
- `api.c` include localmente soltanto `api.h`; gli altri include sono header di
  sistema o zlib.
- Tutti i simboli non pubblici sono `static`; tabelle e cataloghi sono
  immutabili.
- Nessun JSON, Python, Node.js, manifest o file generated è richiesto a runtime.
- Reader, writer e decoder puri usano storage borrowed/caller-owned; la heap è
  riservata a stream accumulation, decompressione e lifecycle.
- Ogni limite è controllato prima dell'allocazione o della moltiplicazione che
  dipende da input wire.
- Le API esistenti restano disponibili; le nuove API sono additive salvo bug di
  memory safety dimostrati da characterization test.
- Ogni fase termina con build e test verdi. Una famiglia non viene marcata
  typed/canonical se conserva una tail opaca non validata.

## Stato di avanzamento

- [x] Creata branch dalla baseline esatta e verificata working tree pulita.
- [x] Eseguiti test e benchmark di caratterizzazione.
- [x] Fase 0: guardrail di distribuzione, generazione ed export.
- [x] Fase 1: error model strutturato e reader strict/exact.
- [x] Fase 2: parser stream incrementale puro e riuso nel networking.
- [x] Fase 3: embedding deterministico del generated code.
- [ ] Fase 4: codec Tier A e packet-family mapping.
- [ ] Fase 5: canonical IR lossless.
- [ ] Fase 6: replay, differential testing e fuzzing.
- [ ] Fase 7: Tier B e chunk envelope.
- [ ] Fase 8: hardening prestazionale e regression gates.

## Fase 0 — Characterization e guardrail

Obiettivo: rendere misurabile il comportamento corrente prima di cambiare il
framing e i decoder.

Interventi:

1. Aggiungere `make generate-check` in modalità read-only. Con
   `MINECRAFT_DATA_ROOT` disponibile rigenera in memoria e confronta tutti gli
   output; senza il checkout esterno verifica almeno hash, overlay e integrità
   degli artefatti committed, dichiarando esplicitamente il controllo ridotto.
2. Aggiungere `make test-amalgamation`: copia soltanto `api.c` e `api.h` in una
   directory temporanea, verifica gli include locali e compila un consumer con
   `cc -std=c11 consumer.c api.c -lz`.
3. Aggiungere `make test-exports`: compila `api.o`, legge `nm -g` e confronta i
   simboli definiti con una allowlist versionata.
4. Separare i target `test-unit`, `test-codec` e `test-stream`, mantenendo
   `make test` come aggregatore compatibile.
5. Rafforzare la build warnings-as-errors senza introdurre flag non portabili
   nella toolchain base.

Exit criteria:

- `make`, `make shared`, `make test`, `make test-amalgamation` e
  `make test-exports` verdi.
- `make generate-check` non scrive file e rileva qualunque differenza quando il
  checkout minecraft-data configurato è presente.
- Nessun nuovo oggetto di produzione oltre `api.o`.

## Fase 1 — Error model e strict reader

Interventi:

1. Aggiungere `McErrorCode`, `McError`, `McDecodeMode`, `mc_error_name()` e
   inizializzazione deterministica del contesto sconosciuto.
2. Estendere `McReader` in modo additivo con mode/error sink. La vecchia
   `mc_reader_init()` resta compat e senza error sink; una nuova init abilita
   strict decoding e codici strutturati.
3. In strict mode accettare booleani solo `0/1` e VarInt/VarLong soltanto nella
   forma canonica. Overflow, input parziale, lunghezze negative e trailing byte
   ricevono codici distinti e offset stabili.
4. Aggiungere string reader bounded e un helper exact che richiede consumo
   completo. Nessuna primitive alloca.
5. Testare min/max, overflow, ogni troncamento, malformed terminal byte,
   sticky failure e differenze strict/compat.

Exit criteria:

- I test non identificano più gli errori nuovi tramite testo localizzato.
- Dopo failure nessuna lettura successiva avanza il reader.
- I decoder exact rifiutano tail `00`, `ff` e byte arbitrari.

## Fase 2 — Incremental stream decoder

Interventi:

1. Esporre un `McStreamDecoder` opaque con configurazione esplicita per frame,
   output decompresso, input buffered e output retained per feed.
2. Supportare feed arbitrari, zero o più frame, drain con feed vuoto, reset ed
   EOF/finalize con rilevamento di partial frame.
3. Usare crescita geometrica bounded, compaction e riuso dei buffer. I payload
   restituiti sono borrowed e validi fino al feed/reset successivo.
4. Validare outer VarInt e compression VarInt prima delle allocazioni.
5. Per zlib richiedere declared size bounded, output esatto e
   `Z_STREAM_END`; strict mode verifica soglia, forma canonica e trailing
   compressed garbage.
6. Coprire split a ogni offset, one-byte feed, header/body separati, frame
   coalesced, frame più prefisso del successivo, reset partial ed EOF partial.

Exit criteria:

- Ogni strategia di frammentazione produce la stessa sequenza di packet ID e
  payload del feed monolitico.
- ASan/UBSan non rilevano errori e la memoria retained resta entro config.
- Il parser non dipende da socket o global mutable state.

`McClient` usa lo stesso parser: il socket produce soltanto chunk decifrati e il
decoder conserva frame coalesced prima della readiness successiva. Il raw
accept legge ancora il solo handshake iniziale con un reader bounded, poi il
peer restituito prosegue attraverso `McClient` e il parser condiviso.

Benchmark post-slice con la stessa configurazione locale a tre ripetizioni:

| workload | baseline | post-slice | variazione |
| --- | ---: | ---: | ---: |
| login offline sequenziali | 1.816,530/s | 2.120,188/s | +16,72% |
| stream keepalive | 38.536,091/s | 38.544,558/s | +0,02% |
| keepalive concorrenti | 62.647,691/s | 61.988,755/s | -1,05% |

Le differenze sono entro i gate proposti; i dati sono di caratterizzazione e
non sostituiscono ancora una baseline CI calibrata.

## Fase 3 — Generated embedding

1. Introdurre in `api.h` i marker `MC_GENERATED_PUBLIC_BEGIN/END` e in `api.c`
   i marker `MC_GENERATED_PRIVATE_BEGIN/END`.
2. Far produrre al compiler due regioni deterministiche in memoria e sostituire
   soltanto il testo compreso tra marker, con errore su marker duplicati o
   mancanti.
3. Portare costanti, struct e prototipi generated nella regione pubblica;
   cataloghi, tabelle e codec nella regione privata con internals `static` dove
   non esportati.
4. Modificare i test affinché includano soltanto `api.h` e compilino soltanto
   `api.c`.
5. Rimuovere `generated/*.c` e `generated/*.h` dalla build, quindi eliminare
   gli artefatti quando la characterization è equivalente.

Exit criteria: il consumer completo usa esclusivamente `api.c`, `api.h` e
zlib; due esecuzioni di generate producono byte identici.

## Fase 4 — Vertical slice Tier A

Protocol bucket iniziali: 47, 340, 754, 763, 768 e 776.

Famiglie iniziali:

- movimento client (base, position, look e position_look);
- entity action, abilities e attack/use_entity;
- block dig, block place/use item on e use item;
- server position/correction, entity velocity e block change;
- held item slot e teleport confirm.

Per ogni famiglia si aggiungono insieme: mapping ID/name, `McPacketFamily`,
struct pubblica con presence bits, decoder caller-owned, exact consumption,
golden fixture, truncation-every-byte, malformed/trailing cases, fuzz seed,
differential case e benchmark. Gli stessi decoder vengono poi estesi agli
altri protocolli dichiarati senza duplicare struct quando la wire shape è
condivisa.

## Fase 5 — Canonical IR

- Aggiungere `McCanonicalHeader` con raw payload borrowed e metadata wire.
- Aggiungere normalizzatori per famiglia, non una mega-union.
- Conservare raw flags, presence, stance/wire Y, teleport ID e delta quando
  storicamente presenti.
- Vietare fisica, collisioni, plausibility repair o inferenza applicativa.
- Provare con fixture cross-version che eventi semanticamente equivalenti
  convergano, lasciando esplicite le differenze raw.

## Fase 6 — Replay, differential e fuzz

- Definire trace binaria versionata e bounded; il replay usa solo API pubbliche.
- Integrare node-minecraft-protocol soltanto in `test-differential`, mai in
  `make test` o nel runtime.
- Creare target fuzz separati che linkano esclusivamente target + `api.c`.
- Aggiungere ASan/UBSan, deterministic seed e doppia esecuzione dello stesso
  input per verificare errori deterministici.

## Fase 7 — Tier B e chunk envelope

Implementare envelope bounded per explosion, attributes/effects, metadata,
passengers, inventory complesso, respawn/game state e chunk. Il chunk path
espone view/iterator borrowed e valida count, palette header, packed arrays,
heightmap, block entities e light boundaries senza materializzare un mondo 3D.

## Fase 8 — Performance hardening

- Aggiungere benchmark puri per VarInt, movement, position/look, attack, NBT,
  framing, compressione e canonical normalization.
- Aggiungere replay 1/32/256 stream e corpus misto.
- Misurare ns/op, packet/s, byte/s, allocazioni/op e peak retained buffer.
- Ottimizzare riuso, lookup e copie soltanto dopo profili riproducibili.
- Attivare gate 5% per primitive e 10% per path complessi dopo calibrazione CI.

## CI e Definition of Done

La matrice finale comprende GCC e Clang su Linux x86_64, Clang su macOS arm64,
poi Linux arm64 e compile/test 32-bit quando disponibili. Job distinti coprono
warnings-as-errors, test, generate-check, ASan/UBSan, fuzz smoke, differential,
coverage e benchmark non-gating iniziale.

La libreria è completa solo quando:

- `api.c` e `api.h` sono gli unici file runtime e non esistono generated C/H
  necessari alla build;
- framing socket e parser puro condividono un'unica implementazione;
- errori strutturati, strict mode, Tier A, canonical IR, golden, replay,
  differential, sanitizer e fuzz smoke sono verdi;
- la coverage matrix dichiara onestamente `PASS`, `N/A`, `PARTIAL` o `BLOCKED`;
- `make check` e il consumer `cc -O3 -std=c11 app.c api.c -lz -o app`
  passano da un checkout pulito.

## Sequenza commit prevista

1. `docs: add hardening implementation plan`
2. `test: add two-file distribution guardrails`
3. `feat: add structured decode errors and strict reader`
4. `feat: add bounded incremental stream decoder`
5. `test: add stream fragmentation and compression matrix`

I commit successivi seguiranno le fasi 3–8; ogni commit deve essere compilabile
e non deve dichiarare copertura non ancora dimostrata.
