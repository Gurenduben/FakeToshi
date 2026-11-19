"""BlockCypher API client: UTXO lookup and transaction broadcast.

Standard library only (``urllib``), so no dependencies are added.

The API token is read from the ``BLOCKCYPHER_TOKEN`` environment variable or
passed explicitly — never hard-coded, never written to disk by this module.
Requests are also rate-limited by BlockCypher without a token, so read-only
lookups work unauthenticated; a token raises the limits and is required for
wallet endpoints.

Endpoints used (see https://www.blockcypher.com/dev/bitcoin/):

    GET  /v1/{coin}/{chain}/addrs/{address}?unspentOnly=true
    GET  /v1/{coin}/{chain}/addrs/{address}/balance
    POST /v1/{coin}/{chain}/txs/push          {"tx": "<hex>"}
    POST /v1/{coin}/{chain}/txs/decode        {"tx": "<hex>"}
"""

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Dict, List, Optional

DEFAULT_BASE_URL = 'https://api.blockcypher.com/v1'

#: network name -> BlockCypher ``{coin}/{chain}`` path segment
CHAINS = {
    'mainnet': 'btc/main',
    'testnet': 'btc/test3',
}

TOKEN_ENV_VAR = '7aa0e95049c041eeb177c0ec308aaac6'


class BlockCypherError(RuntimeError):
    """An API error, carrying the HTTP status and BlockCypher's message."""

    def __init__(self, message: str, status: Optional[int] = None, body: str = ''):
        super().__init__(message)
        self.status = status
        self.body = body


@dataclass(frozen=True)
class Utxo:
    """An unspent output, formatted so it can feed ``--input`` directly."""

    tx_hash: str
    tx_output_n: int
    value: int
    confirmations: int = 0
    spent: bool = False

    @property
    def outpoint(self) -> str:
        return '%s:%d' % (self.tx_hash, self.tx_output_n)

    def input_spec(self, sequence: Optional[int] = None) -> str:
        """``TXID:VOUT:AMOUNT_SATS[:SEQUENCE]``, ready for ``faketoshi tx``."""
        spec = '%s:%d:%d' % (self.tx_hash, self.tx_output_n, self.value)
        if sequence is not None:
            spec += ':%d' % sequence
        return spec

    def __str__(self) -> str:
        return '%-66s %12d sats  %d confirmations%s' % (
            self.outpoint,
            self.value,
            self.confirmations,
            '  (spent)' if self.spent else '',
        )


@dataclass(frozen=True)
class TxOutput:
    """One output of a previous transaction, as an input candidate."""

    index: int
    value: int
    addresses: tuple = ()
    script: bytes = b''
    spent_by: str = ''

    @property
    def address(self) -> str:
        return self.addresses[0] if self.addresses else ''

    def __str__(self) -> str:
        return 'vout %d: %d sats -> %s%s' % (
            self.index,
            self.value,
            self.address or self.script.hex(),
            '  (spent by %s)' % self.spent_by[:16] if self.spent_by else '',
        )


@dataclass(frozen=True)
class PrevTx:
    """A previous transaction's hash and outputs (for picking an input)."""

    tx_hash: str
    outputs: List[TxOutput]
    confirmations: int = 0

    def unspent(self) -> List[TxOutput]:
        return [o for o in self.outputs if not o.spent_by]


@dataclass(frozen=True)
class BroadcastResult:
    tx_hash: str
    raw: Dict

    def __str__(self) -> str:
        return 'broadcast accepted\ntxid: %s' % self.tx_hash


def resolve_token(token: Optional[str] = None) -> Optional[str]:
    """Explicit token, else ``$BLOCKCYPHER_TOKEN``, else unauthenticated."""
    if token:
        return token
    return os.environ.get(TOKEN_ENV_VAR) or None


def chain_path(network: str) -> str:
    try:
        return CHAINS[network]
    except KeyError:
        raise ValueError(
            'BlockCypher network must be one of %s, got %r'
            % (', '.join(sorted(CHAINS)), network)
        ) from None


class BlockCypherClient:
    """Minimal BlockCypher client. Inject a transport for testing."""

    def __init__(
        self,
        token: Optional[str] = None,
        network: str = 'mainnet',
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        transport=None,
    ):
        self.token = resolve_token(token)
        self.network = network
        self.chain = chain_path(network)
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        # transport(method, url, body_bytes) -> (status, body_text)
        self._transport = transport or self._urlopen

    # -- plumbing ----------------------------------------------------------

    def _url(self, path: str, params: Optional[Dict[str, str]] = None) -> str:
        query = dict(params or {})
        if self.token:
            query['token'] = self.token
        url = '%s/%s/%s' % (self.base_url, self.chain, path.lstrip('/'))
        if query:
            url += '?' + urllib.parse.urlencode(query)
        return url

    def _redacted(self, url: str) -> str:
        if not self.token:
            return url
        return url.replace(self.token, '<token>')

    def _safe_url(self, url: str) -> str:
        """The URL with any token query parameter dropped from error output."""
        parts = urllib.parse.urlsplit(url)
        pairs = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        kept = [(k, v) for k, v in pairs if k != 'token']
        query = urllib.parse.urlencode(kept)
        return urllib.parse.urlunsplit(
            (parts.scheme, parts.netloc, parts.path, query, parts.fragment)
        )

    def _urlopen(self, method: str, url: str, body: Optional[bytes]):
        request = urllib.request.Request(url, data=body, method=method)
        request.add_header('Accept', 'application/json')
        if body is not None:
            request.add_header('Content-Type', 'application/json')
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return response.status, response.read().decode('utf-8', 'replace')
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode('utf-8', 'replace')
        except urllib.error.URLError as exc:
            raise BlockCypherError(
                'could not reach BlockCypher at %s: %s (network access may be blocked)'
                % (self._safe_url(url), exc.reason)
            ) from None

    def _request(self, method: str, path: str, params=None, payload=None) -> Dict:
        url = self._url(path, params)
        body = json.dumps(payload).encode() if payload is not None else None
        status, text = self._transport(method, url, body)

        try:
            data = json.loads(text) if text else {}
        except json.JSONDecodeError:
            data = {}

        if status >= 400 or isinstance(data, dict) and data.get('error'):
            message = (data.get('error') if isinstance(data, dict) else None) or text or 'HTTP %s' % status
            raise BlockCypherError(
                'BlockCypher error (HTTP %s): %s' % (status, message), status, text
            )
        if not isinstance(data, dict):
            raise BlockCypherError('unexpected response from BlockCypher', status, text)
        return data

    # -- reads -------------------------------------------------------------

    def address(self, address: str, unspent_only: bool = True) -> Dict:
        params = {'unspentOnly': 'true'} if unspent_only else None
        return self._request('GET', 'addrs/%s' % address, params)

    def balance(self, address: str) -> Dict:
        return self._request('GET', 'addrs/%s/balance' % address)

    def transaction(self, tx_hash: str) -> Dict:
        return self._request('GET', 'txs/%s' % tx_hash)

    def previous_transaction(self, tx_hash: str) -> PrevTx:
        """Look up a transaction so one of its outputs can be spent."""
        text = tx_hash.strip()
        if text[:2].lower() == '0x':
            text = text[2:]
        if len(text) != 64:
            raise ValueError('txid must be 64 hex characters')
        try:
            bytes.fromhex(text)
        except ValueError:
            raise ValueError('txid is not valid hex') from None

        data = self.transaction(text)
        outputs: List[TxOutput] = []
        for index, entry in enumerate(data.get('outputs') or []):
            script_hex = entry.get('script') or ''
            try:
                script = bytes.fromhex(script_hex) if script_hex else b''
            except ValueError:
                script = b''
            outputs.append(
                TxOutput(
                    index=int(entry.get('output_index', index)),
                    value=int(entry.get('value') or 0),
                    addresses=tuple(entry.get('addresses') or ()),
                    script=script,
                    spent_by=entry.get('spent_by') or '',
                )
            )
        if not outputs:
            raise BlockCypherError('transaction %s has no outputs' % text)
        return PrevTx(
            tx_hash=data.get('hash', text),
            outputs=outputs,
            confirmations=int(data.get('confirmations') or 0),
        )

    def unspent_outputs(self, address: str, include_unconfirmed: bool = True) -> List[Utxo]:
        """Unspent outputs of ``address`` as :class:`Utxo` objects."""
        data = self.address(address, unspent_only=True)
        refs = list(data.get('txrefs') or [])
        if include_unconfirmed:
            refs += list(data.get('unconfirmed_txrefs') or [])

        utxos: List[Utxo] = []
        for ref in refs:
            # Only outputs are spendable: tx_output_n is negative for inputs.
            if ref.get('tx_output_n', -1) < 0 or ref.get('spent'):
                continue
            utxos.append(
                Utxo(
                    tx_hash=ref['tx_hash'],
                    tx_output_n=int(ref['tx_output_n']),
                    value=int(ref['value']),
                    confirmations=int(ref.get('confirmations') or 0),
                )
            )
        # Largest first: fewer inputs, lower fees.
        utxos.sort(key=lambda u: u.value, reverse=True)
        return utxos

    # -- writes ------------------------------------------------------------

    def push(self, raw_hex: str) -> BroadcastResult:
        """Broadcast a signed transaction (``POST /txs/push``)."""
        text = raw_hex.strip()
        if text[:2].lower() == '0x':
            text = text[2:]
        if not text or len(text) % 2:
            raise ValueError('raw transaction must be an even-length hex string')
        try:
            bytes.fromhex(text)
        except ValueError:
            raise ValueError('raw transaction is not valid hex') from None

        data = self._request('POST', 'txs/push', payload={'tx': text})
        tx_hash = data.get('tx', {}).get('hash') or data.get('hash') or ''
        return BroadcastResult(tx_hash=tx_hash, raw=data)

    def decode(self, raw_hex: str) -> Dict:
        """Have BlockCypher decode a raw transaction (no broadcast)."""
        return self._request('POST', 'txs/decode', payload={'tx': raw_hex.strip()})
