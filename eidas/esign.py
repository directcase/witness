"""esign - sign PDFs (PAdES-B-LT) with an EU eID card or other qualified signature device.

    python esign.py list                     show signing certificates found on inserted cards
    python esign.py sign a.pdf [b.pdf ...]   sign; writes <name>_signed.pdf next to each file

Configuration comes from environment variables or a .env file next to this script (see .env.example).
"""
import argparse
import datetime
import getpass
import hashlib
import os
import platform
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pkcs11
from asn1crypto import algos, cms, core, pem, x509
from pkcs11 import Attribute, Mechanism, ObjectClass, TokenFlag
from pyhanko.keys import load_certs_from_pemder_data
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields, signers, timestamps
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.registry import SimpleCertificateStore

HERE = Path(__file__).resolve().parent
HELPER = HERE / 'keychain_sign'
DEFAULT_TSA = 'http://timestamp.digicert.com'

OPENSC = [
    '/Library/OpenSC/lib/opensc-pkcs11.so',
    '/opt/homebrew/lib/opensc-pkcs11.so',
    '/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so',
    '/usr/lib/aarch64-linux-gnu/opensc-pkcs11.so',
    r'C:\Windows\System32\opensc-pkcs11.dll',
]
# Card presets: which PKCS#11 modules to try, or the macOS keychain.
CARDS = {
    'ee': {'libs': ['/Applications/qdigidoc4.app/Contents/MacOS/opensc-pkcs11.so', *OPENSC]},
    # The Slovak module only offers its own PIN dialog, which hangs on recent macOS; the keychain route works.
    'sk': {'keychain': True} if platform.system() == 'Darwin' else {'libs': []},
    'opensc': {'libs': OPENSC},
}

QC_STATEMENTS = '1.3.6.1.5.5.7.1.3'
QC_COMPLIANCE = '0.4.0.1862.1.1'  # issued as a qualified certificate
QC_SSCD = '0.4.0.1862.1.4'  # private key lives on a qualified signature creation device (QSCD)


class QcStatement(core.Sequence):
    _fields = [('id', core.ObjectIdentifier), ('info', core.Any, {'optional': True})]


class QcStatementList(core.SequenceOf):
    _child_spec = QcStatement


def load_env():
    env_file = HERE / '.env'
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            key, sep, value = line.partition('=')
            if sep and not key.strip().startswith('#'):
                os.environ.setdefault(key.strip(), value.strip().strip('"\''))


def qualification(cert):
    ext = next((e for e in cert['tbs_certificate']['extensions'] if e['extn_id'].dotted == QC_STATEMENTS), None)
    ids = {s['id'].dotted for s in QcStatementList.load(ext['extn_value'].contents)} if ext else set()
    if {QC_COMPLIANCE, QC_SSCD} <= ids:
        return 'QES'
    if QC_COMPLIANCE in ids:
        return 'AdES-QC (qualified certificate, key not on a certified QSCD - not a QES)'
    return 'AdES (not a qualified certificate)'


def digest_for(cert):
    key = cert.public_key
    if key.algorithm == 'ec':
        return {'secp384r1': 'sha384', 'secp521r1': 'sha512'}.get(key.curve[1], 'sha256')
    return 'sha256'


@dataclass
class Candidate:
    cert: x509.Certificate
    source: str  # human-readable origin
    lib: str | None = None  # PKCS#11 module path, or None for the macOS keychain
    token_label: str | None = None
    cert_id: bytes | None = None
    sha1: str | None = None

    def describe(self):
        c = self.cert
        return (f'{c.subject.native.get("common_name")} | issuer {c.issuer.native.get("common_name")} | '
                f'valid until {c.not_valid_after.date()} | {qualification(c)} | {self.source}')


def is_signing_cert(cert):
    ku = cert.key_usage_value
    return ku is not None and 'non_repudiation' in ku.native


def pkcs11_candidates(libs):
    for path in libs:
        if not Path(path).exists():
            continue
        lib = pkcs11.lib(path)
        for slot in lib.get_slots(token_present=True):
            token = slot.get_token()
            try:
                with token.open() as session:
                    objects = session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})
                    raw = [(obj[Attribute.ID], obj[Attribute.VALUE]) for obj in objects]
            except pkcs11.PKCS11Error:
                continue  # uninitialised or unreadable token
            for cert_id, der in raw:
                try:
                    cert = x509.Certificate.load(der)
                    cert.native  # force full parse
                except ValueError:
                    continue  # empty or malformed certificate object
                if is_signing_cert(cert):
                    yield Candidate(cert, f'PKCS#11 {token.label.strip()}', path, token.label, cert_id)


def build_helper():
    src = HERE / 'keychain_sign.swift'
    if not HELPER.exists() or HELPER.stat().st_mtime < src.stat().st_mtime:
        subprocess.run(['swiftc', '-O', str(src), '-o', str(HELPER)], check=True)


def keychain(*args, data=None):
    return subprocess.run([str(HELPER), *args], input=data, capture_output=True, check=True, timeout=180).stdout


def keychain_candidates():
    build_helper()
    for line in keychain('list').decode().splitlines():
        sha1 = line.split()[0]
        cert = x509.Certificate.load(keychain('cert', sha1))
        if is_signing_cert(cert):
            yield Candidate(cert, 'macOS keychain', sha1=sha1)


def find_candidates():
    card = os.environ.get('ESIGN_CARD', '').lower()
    if card and card not in CARDS:
        sys.exit(f'Unknown ESIGN_CARD={card!r}; use one of {", ".join(CARDS)} or set ESIGN_LIB')
    preset = CARDS.get(card, {})
    libs = [os.environ['ESIGN_LIB']] if os.environ.get('ESIGN_LIB') else preset.get('libs', CARDS['ee']['libs'])
    found = list(pkcs11_candidates(libs))
    if platform.system() == 'Darwin' and (preset.get('keychain') or not found):
        found += keychain_candidates()
    return found


def choose(candidates):
    wanted = os.environ.get('ESIGN_CERT', '').lower()
    if wanted:
        candidates = [c for c in candidates if wanted in (c.sha1 or '') or wanted in c.describe().lower()]
    if not candidates:
        sys.exit('No signing certificate found - is the card inserted? Try: python esign.py list')
    if len(candidates) > 1:
        sys.exit('Several signing certificates found; set ESIGN_CERT to part of the one to use:\n  '
                 + '\n  '.join(c.describe() for c in candidates))
    return candidates[0]


def fetch_issuer(cert):
    """Download the issuing CA certificate via the Authority Information Access extension."""
    urls = [d['access_location'].native for d in (cert.authority_information_access_value or [])
            if d['access_method'].native == 'ca_issuers' and d['access_location'].name == 'uniform_resource_identifier']
    for url in urls:
        data = urllib.request.urlopen(url, timeout=15).read()
        if pem.detect(data):
            data = pem.unarmor(data)[2]
        try:
            certs = [x509.Certificate.load(data)]
            certs[0].native  # force parse
        except ValueError:  # PKCS#7 bundle
            certs = [c.chosen for c in cms.ContentInfo.load(data)['content']['certificates']]
        for issuer in certs:
            if issuer.subject == cert.issuer:
                return issuer
    return None


def chain(cert):
    """Return (intermediates, trust_anchor) by following AIA links up to a self-signed root."""
    path = [cert]
    while path[-1].self_signed == 'no' and len(path) < 6:
        issuer = fetch_issuer(path[-1])
        if issuer is None:
            break
        path.append(issuer)
    return path[1:-1], path[-1]


def system_roots():
    if platform.system() == 'Darwin':
        pem_data = subprocess.run(
            ['security', 'find-certificate', '-a', '-p', '/System/Library/Keychains/SystemRootCertificates.keychain'],
            capture_output=True, check=True,
        ).stdout
    else:
        import certifi
        pem_data = Path(certifi.where()).read_bytes()
    return list(load_certs_from_pemder_data(pem_data))


class CardSigner(signers.Signer):
    """Hashes locally and asks the card to sign only the digest (works with RSA and ECDSA cards)."""

    def __init__(self, cert, intermediates, sign_digest):
        self.sign_digest = sign_digest
        mech = f'{digest_for(cert)}_{"ecdsa" if cert.public_key.algorithm == "ec" else "rsa"}'
        super().__init__(
            signing_cert=cert,
            cert_registry=SimpleCertificateStore.from_certs([cert, *intermediates]),
            signature_mechanism=algos.SignedDigestAlgorithm({'algorithm': mech}),
        )

    async def async_sign_raw(self, data, digest_algorithm, dry_run=False):
        if dry_run:
            return bytes(self.signing_cert.public_key.byte_size * 2 + 16)
        return self.sign_digest(hashlib.new(digest_algorithm, data).digest(), digest_algorithm)


def pkcs11_sign_digest(key, cert):
    def sign(digest, digest_algorithm):
        if cert.public_key.algorithm == 'ec':
            raw = key.sign(digest, mechanism=Mechanism.ECDSA)
            return algos.DSASignature.from_p1363(raw).dump()
        info = algos.DigestInfo({'digest_algorithm': {'algorithm': digest_algorithm}, 'digest': digest})
        return key.sign(info.dump(), mechanism=Mechanism.RSA_PKCS)
    return sign


def sign_files(candidate, files, out):
    cert = candidate.cert
    print('Signing as:', candidate.describe())
    if not qualification(cert).startswith('QES'):
        print('WARNING: this certificate cannot produce a qualified electronic signature (QES).')

    intermediates, anchor = chain(cert)
    vc = ValidationContext(trust_roots=[anchor, *system_roots()], other_certs=intermediates, allow_fetching=True)
    tsa = timestamps.HTTPTimeStamper(os.environ.get('ESIGN_TSA') or DEFAULT_TSA)

    def run(sign_digest):
        signer = CardSigner(cert, intermediates, sign_digest)
        for src in files:
            dst = out or src.with_name(src.stem + '_signed.pdf')
            if dst.exists():
                sys.exit(f'{dst} already exists - not overwriting')
            meta = signers.PdfSignatureMetadata(
                field_name=f'Signature_{datetime.datetime.now():%Y%m%d_%H%M%S}',
                subfilter=fields.SigSeedSubFilter.PADES,
                embed_validation_info=True,
                validation_context=vc,
                md_algorithm=digest_for(cert),
            )
            tmp = dst.with_suffix('.partial')
            try:
                with src.open('rb') as inf, tmp.open('wb') as outf:
                    signers.PdfSigner(meta, signer, timestamper=tsa).sign_pdf(IncrementalPdfFileWriter(inf), output=outf)
                tmp.rename(dst)
            finally:
                tmp.unlink(missing_ok=True)
            print('Signed ->', dst)

    if candidate.lib is None:
        print('Enter the signing PIN in the macOS dialog when asked.')
        run(lambda digest, alg: keychain('sign', candidate.sha1, alg, data=digest))
        return

    token = pkcs11.lib(candidate.lib).get_token(token_label=candidate.token_label)
    if token.flags & TokenFlag.PROTECTED_AUTHENTICATION_PATH:
        print('Enter the signing PIN on the reader / in the card software dialog.')
        pin = pkcs11.PROTECTED_AUTH
    else:
        pin = os.environ.get('ESIGN_PIN') or getpass.getpass(f'Signing PIN for {token.label.strip()}: ')
    # Qualified signing keys are usually CKA_ALWAYS_AUTHENTICATE (e.g. Estonian PIN2): one login allows one
    # signature. Log in again for every signature so a batch needs only one PIN entry.
    def sign_digest(digest, digest_algorithm):
        with token.open(user_pin=pin) as session:
            key = session.get_key(object_class=ObjectClass.PRIVATE_KEY, id=candidate.cert_id)
            return pkcs11_sign_digest(key, cert)(digest, digest_algorithm)

    run(sign_digest)


def main():
    load_env()
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list', help='show signing certificates on inserted cards')
    sign = sub.add_parser('sign', help='sign PDF files')
    sign.add_argument('files', nargs='+', type=Path)
    sign.add_argument('-o', '--out', type=Path, help='output path (only with a single input file)')
    args = parser.parse_args()

    candidates = find_candidates()
    if args.command == 'list':
        for c in candidates:
            print(c.describe())
        if not candidates:
            print('No signing certificates found - is the card inserted?')
        return
    if args.out and len(args.files) > 1:
        sys.exit('--out works only with a single input file')
    sign_files(choose(candidates), args.files, args.out)


if __name__ == '__main__':
    main()
