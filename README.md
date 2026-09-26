# notary

Two scripts: one captures a web page as evidence, the other lets anyone verify the capture later.

Project page: <https://witness.directcase.ai/>

```bash
./create.sh URL [--id NAME] [--expect TEXT ...] [--timestamp] [--eidas]
./verify.sh captures/<domain>/<page>/<time> [--timestamp] [--eidas] [--online] [--json]
```

## What a capture contains

Every capture gets its own folder, grouped by domain and page:

```
captures/
  example.org/                      domain
    index/                          page path ("/" -> index), or --id NAME
      2026-09-26T104713Z/           one capture (UTC time)
        evidence.zip
        evidence.zip.ots            --timestamp
        report.pdf
        report_signed.pdf           --eidas
  lawrenceai.cz/
    faq/
      2026-09-26T…/
```

| File | Made by | What it proves |
|---|---|---|
| `evidence.zip` | always | The evidence package (below) |
| `report.pdf` | always | Readable summary with the screenshot, naming the zip's SHA-256 |
| `evidence.zip.ots` | `--timestamp` | [OpenTimestamps](https://opentimestamps.org): the zip existed no later than a Bitcoin block |
| `report_signed.pdf` | `--eidas` | Your eIDAS signature (PAdES-B-LT) over the report, and so over the zip's hash |

Inside the zip:

| File | What it is |
|---|---|
| `screenshot.png`, `page.html`, `page.txt` | Full-page screenshot, rendered DOM and text (headless Chromium) |
| `browser.har.zip` | Every request and response the browser made, with bodies and server IPs |
| `traffic.warc.gz`, `traffic.cdx` | Raw HTTP exchange of the page and its requisites (`wget --warc-file`) |
| `tlsn/receipt.json` | TLSNotary receipt signed by the notary; it contains the full request and response |
| `tlsn/transcript-*.bin`, `tlsn/tlsn.json`, `tlsn/notary-*.json` | Transcript bytes, receipt checks, and the notary's identity at capture time |
| `manifest.json` | Step results, expected-phrase checks and the SHA-256 of every file |

Who signs what:

- **The notary** (`https://pavoltravnik.witness.directcase.ai`, key `73a6bdba645a59e4`) signs `tlsn/receipt.json`. It states that the server sent these bytes at this time. The notary itself opened the TLS connection to the site (TLSNotary proxy mode).
- **You**, with your eID card, sign `report_signed.pdf`. It states that you made this capture and that the package has this SHA-256. This is the legally recognised signature (a QES is equivalent to a handwritten signature in the EU).
- **Nobody** has to be trusted for `.ots`: it is anchored in Bitcoin through public calendars.

## Setup (once)

```bash
docker build -t witness witness/        # done automatically on first use
```

eIDAS signing is part of this repo, in `eidas/`. `create.sh --eidas` creates its venv on first use. Configure your card once:

```bash
cp eidas/.env.example eidas/.env && chmod 600 eidas/.env    # ESIGN_CARD=ee|sk|opensc, optional ESIGN_TSA, ESIGN_PIN
eidas/.venv/bin/python eidas/esign.py list                  # insert the card: should show your certificate as QES
```

`eidas/.env` is git-ignored, because it may contain your PIN.

## Create

```bash
./create.sh https://example.org/ \
    --expect "This domain is for use in documentation examples" --timestamp --eidas
```

```
Created captures/example.org/index/2026-09-26T104713Z/
  evidence.zip
  evidence.zip.ots
  report.pdf
  report_signed.pdf
Verify:  ./verify.sh captures/example.org/index/2026-09-26T104713Z
```

The steps, in order:

1. **Screenshot:** Chromium loads the page, scrolls it, clicks the cookie banner's accept button (the label is recorded), and saves the screenshot, HTML, text and HAR.
2. **Traffic:** `wget` records the page and its requisites into `traffic.warc.gz`.
3. **TLSNotary:** the notary connects to the site, the prover proves the TLS session, and the notary returns a signed receipt. The receipt is checked at once: signature, key window, and that the signed bytes equal the transcript.
4. **Package:** everything is zipped, and `report.pdf` is written with the zip's SHA-256.
5. **`--timestamp`:** the zip's SHA-256 is submitted to four public OpenTimestamps calendars.
6. **`--eidas`:** the report is signed with your card on the host. You enter the PIN in the macOS dialog, on the reader, or via `ESIGN_PIN`.

### All option combinations

`--id` and `--expect` are optional. Without them the whole page is captured, and the folder is named after the URL (`captures/example.org/index/<time>/`). `--id NAME` replaces the page part.

| Command | Files in the capture folder | `./verify.sh <folder>` checks |
|---|---|---|
| `./create.sh https://example.org/` | `evidence.zip`, `report.pdf` | files, TLSNotary receipt, report; timestamp and eIDAS shown as `--` |
| `./create.sh https://example.org/ --timestamp` | + `evidence.zip.ots` | the above + OpenTimestamps (pending, then the Bitcoin block) |
| `./create.sh https://example.org/ --eidas` | + `report_signed.pdf` | the above + PAdES signature |
| `./create.sh https://example.org/ --timestamp --eidas` | + `evidence.zip.ots` + `report_signed.pdf` | everything |

Run `./verify.sh <folder> --timestamp --eidas` to require the proofs. A plain capture then fails:

```
[FAIL] timestamp      --timestamp: no evidence.zip.ots in the capture folder
[FAIL] eIDAS          --eidas: no report_signed.pdf in the capture folder
RESULT: NOT VALID
```

To add a signature to an existing capture later: `eidas/.venv/bin/python eidas/esign.py sign captures/<domain>/<page>/<time>/report.pdf`. A timestamp can only be made at creation time, because it proves when the zip existed.

For many URLs: `./create.sh --urls urls.json --timestamp --eidas`. The file is `[{"id", "url", "expect": [...]}]`, and all the reports are signed with a single PIN entry at the end.

### Where the eID card signing is implemented

In [`eidas/esign.py`](eidas/esign.py), in this repo. `create.sh --eidas` runs `eidas/.venv/bin/python eidas/esign.py sign <report.pdf> …`:

- `find_candidates()` finds certificates with the non-repudiation key usage, over PKCS#11 (Estonian card through OpenSC, or any `ESIGN_LIB`) or through the macOS keychain (Slovak eID).
- `keychain_sign.swift` is a small helper, compiled on first use, that lets macOS keychain cards sign a digest.
- `sign_files()` asks for the PIN. `CardSigner` hashes the PDF locally, and the card signs only the digest. pyHanko then embeds a PAdES signature with an RFC 3161 timestamp and OCSP/CRL data (PAdES-B-LT).

## Verify

```bash
./verify.sh captures/example.org/index/2026-09-26T104713Z --online
```

```
Capture   https://example.org/
          captured 2026-09-26T10:41:53+00:00   zip sha256 4e9da9301c36d7…
[OK  ] files          15 files match manifest.json
[OK  ] tlsn receipt   example.org verified by https://pavoltravnik.witness.directcase.ai at 2026-09-26T10:41:59Z
                      signature=True key-window=True transcript=True notary /verify=True
[OK  ] timestamp      Bitcoin block 91xxxx at 2026-09-26T…  (merkle root matches)
[OK  ] report.pdf     names this zip
[OK  ] eIDAS          signed by <you>; intact=True valid=True names-zip=True; TSA time …
                      EU DSS: TOTAL_PASSED level=QESig (Qualified Electronic Signature)
[OK  ] phrase (tlsn   ) This domain is for use in documentation examples
RESULT: VALID
```

The exit code is `0` only if every check passes.

| Check | When | What it does |
|---|---|---|
| files | always | Every file in the zip matches `manifest.json`; no unlisted files |
| tlsn receipt | always | ECDSA/secp256k1 signature against the key published at `<notary>/keys.json`; `verified_at` inside the key's active window; signed request/response bytes equal `tlsn/transcript-*.bin`; the notary's own `POST /verify` agrees |
| report.pdf | if present | The report names this zip's SHA-256 |
| timestamp | if `.ots` is present, and required with `--timestamp` | Retrieves the Bitcoin proof from the calendars once it is ready (`ots upgrade`, in place), then checks the block's merkle root against blockstream.info. `pending` means the proof isn't anchored yet; this takes 1–6 hours after `create`. Re-run `verify` later. |
| eIDAS | if `report_signed.pdf` is present, and required with `--eidas` | PAdES signature intact and valid, signer, RFC 3161 time, and that the signed report names this zip |
| eIDAS qualified status | `--online` | Sends the signed report to the European Commission's DSS validator (EU Trusted Lists). It must return `TOTAL_PASSED`, and the level shows `QESig` for a qualified signature. |

Changing any byte breaks verification. Replacing the screenshot inside the zip fails both the manifest hash and the OpenTimestamps proof.

### Checking by hand, without these scripts

- **TLSNotary receipt, online:** paste the output of `unzip -p evidence.zip '*/tlsn/receipt.json'` into the form at <https://pavoltravnik.witness.directcase.ai>, or `curl -X POST --data-binary @receipt.json …/verify`.
- **TLSNotary receipt, offline:** the signature is ECDSA/secp256k1 over SHA-256 of the exact UTF-8 `payload`, as r‖s hex. Convert it to DER and run `openssl dgst -sha256 -verify notary.pem -signature sig.der payload.txt`, with `notary.pem` taken from `/keys.json`.
- **OpenTimestamps:** drop `evidence.zip` and `evidence.zip.ots` on <https://opentimestamps.org>.
- **eIDAS:** upload `report_signed.pdf` to <https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation>, then compare `shasum -a 256 evidence.zip` with the hash printed in the report.

## Testing eIDAS without a card

A SoftHSM token with a self-signed certificate exercises the same path. `esign` shows it as `AdES (not a qualified certificate)`, and `verify --online` fails it, as it should (`NO_CERTIFICATE_CHAIN_FOUND`):

```bash
SOFTHSM2_CONF=/tmp/softhsm/softhsm2.conf ESIGN_CARD=opensc \
ESIGN_LIB=/opt/homebrew/lib/softhsm/libsofthsm2.so ESIGN_PIN=1234 \
  ./create.sh <url> --timestamp --eidas
```

## Limits

- **TLSNotary scope.** It covers one HTTPS GET, sent with `Accept-Encoding: identity`. The TLS client supports TLS 1.2 only. What it proves is the server's HTML or PDF, not content added later by JavaScript; the HAR and screenshot cover that.
- **Non-UTF-8 responses.** The notary currently resets the session when the response bytes aren't valid UTF-8. That covers PDFs and HTML where chunked encoding splits a multi-byte character. This is a server-side bug.
- **Notary `/verify` body limit.** Receipts over about 2 MB get HTTP 413 from `/verify`. The local signature check still covers them.
- **Consent banners.** The click happens only in Chromium. The WARC and TLSNotary captures are taken without it.
