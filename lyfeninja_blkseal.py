import base64
import hashlib
import json
import time
import urllib.parse
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional, Dict, Any, Union


class BlkSealError(Exception):
    pass


class BlkSealAuthError(BlkSealError):
    pass


class BlkSealAPIError(BlkSealError):
    pass


class BlkSealInputError(BlkSealError):
    pass


@dataclass
class OAuthToken:
    access_token: str
    token_type: str
    expires_at: float
    scope: Optional[str] = None

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        return time.time() >= self.expires_at - buffer_seconds


class BlkSealClient:
    def __init__(
        self,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        token_url: str = "https://lyfe.ninja/oauth/token/",
        api_base_url: str = "https://signatures.lyfe.ninja",
        default_scope: Optional[str] = "sign:content verify:content",
        timeout: int = 15,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.token_url = token_url.rstrip("/")
        self.api_base_url = api_base_url.rstrip("/")
        self.default_scope = default_scope
        self.timeout = timeout
        self._token: Optional[OAuthToken] = None

    # -------------------------
    # Canonicalization / hashing
    # -------------------------

    def canonical_validate(self, text: str) -> bytes:
        """
        Canonicalization v1:
        - Input must be a Python str
        - No trimming
        - No line-ending normalization
        - No whitespace changes
        - Encode exactly as UTF-8 bytes
        """
        if not isinstance(text, str):
            raise BlkSealInputError("text must be a str")

        try:
            return text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise BlkSealInputError("text must be UTF-8 encodable") from exc

    def hash_text(self, text: str) -> str:
        data = self.canonical_validate(text)
        return hashlib.sha256(data).hexdigest()

    def hash_bytes(self, data: bytes) -> str:
        if not isinstance(data, (bytes, bytearray)):
            raise BlkSealInputError("data must be bytes or bytearray")

        return hashlib.sha256(bytes(data)).hexdigest()

    def hash_url(
        self,
        url: str,
        timeout: Optional[Union[int, float]] = None,
        max_bytes: int = 25 * 1024 * 1024,
        chunk_size: int = 1024 * 1024,
    ) -> str:
        """
        Download bytes from a public URL and return their SHA-256 hex digest.

        Intended for signing/verifying external media assets such as images,
        PDFs, audio, video, or other downloadable files. The response is streamed
        and capped by max_bytes to avoid loading large files into memory.
        """
        if not isinstance(url, str) or not url.strip():
            raise BlkSealInputError("url must be a non-empty str")

        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise BlkSealInputError("url must use http or https")

        if not parsed.netloc:
            raise BlkSealInputError("url must include a host")

        if not isinstance(max_bytes, int) or max_bytes <= 0:
            raise BlkSealInputError("max_bytes must be a positive integer")

        if not isinstance(chunk_size, int) or chunk_size <= 0:
            raise BlkSealInputError("chunk_size must be a positive integer")

        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "Accept": "*/*",
                "User-Agent": "lyfeninja-blkseal-python-sdk/1.0",
            },
        )

        digest = hashlib.sha256()
        total_bytes = 0
        request_timeout = self.timeout if timeout is None else timeout

        try:
            with urllib.request.urlopen(request, timeout=request_timeout) as response:
                content_length = response.headers.get("Content-Length")

                if content_length is not None:
                    try:
                        if int(content_length) > max_bytes:
                            raise BlkSealInputError(
                                f"URL content exceeds max_bytes ({max_bytes})"
                            )
                    except ValueError:
                        # Ignore malformed Content-Length and enforce during read.
                        pass

                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break

                    total_bytes += len(chunk)
                    if total_bytes > max_bytes:
                        raise BlkSealInputError(
                            f"URL content exceeds max_bytes ({max_bytes})"
                        )

                    digest.update(chunk)

        except BlkSealInputError:
            raise
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise BlkSealAPIError(
                f"URL fetch failed with HTTP {exc.code}: {error_body}"
            ) from exc
        except Exception as exc:
            raise BlkSealAPIError(f"URL fetch failed: {exc}") from exc

        return digest.hexdigest()

    # -------------------------
    # OAuth
    # -------------------------

    def get_token(self, force_refresh: bool = False) -> str:
        if force_refresh or self._token is None or self._token.is_expired():
            self._token = self._request_token()

        return self._token.access_token

    def refresh_token_if_needed(self) -> str:
        return self.get_token(force_refresh=False)

    def _request_token(self) -> OAuthToken:
        if not self.client_id or not self.client_secret:
            raise BlkSealAuthError(
                "client_id and client_secret are required for authenticated requests"
            )

        form_data = {
            "grant_type": "client_credentials",
        }

        if self.default_scope:
            form_data["scope"] = self.default_scope

        body = urllib.parse.urlencode(form_data).encode("utf-8")

        basic_auth = base64.b64encode(
            f"{self.client_id}:{self.client_secret}".encode("utf-8")
        ).decode("ascii")

        request = urllib.request.Request(
            self.token_url + "/",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Basic {basic_auth}",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")
            raise BlkSealAuthError(
                f"Token request failed with HTTP {exc.code}: {error_body}"
            ) from exc
        except Exception as exc:
            raise BlkSealAuthError(f"Token request failed: {exc}") from exc

        access_token = payload.get("access_token")
        token_type = payload.get("token_type", "Bearer")
        expires_in = int(payload.get("expires_in", 3600))
        scope = payload.get("scope")

        if not access_token:
            raise BlkSealAuthError("Token response did not include access_token")

        return OAuthToken(
            access_token=access_token,
            token_type=token_type,
            expires_at=time.time() + expires_in,
            scope=scope,
        )

    # -------------------------
    # API request helpers
    # -------------------------

    def _url(self, path: str) -> str:
        return f"{self.api_base_url}/{path.lstrip('/')}"

    def _request_json(
        self,
        method: str,
        url: str,
        payload: Dict[str, Any],
        authenticated: bool = False,
        retry_on_unauthorized: bool = True,
    ) -> Dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        if authenticated:
            token = self.get_token()
            headers["Authorization"] = f"Bearer {token}"

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url,
            data=data,
            method=method.upper(),
            headers=headers,
        )

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8")
                return json.loads(raw) if raw else {}

        except urllib.error.HTTPError as exc:
            error_body = exc.read().decode("utf-8", errors="replace")

            if authenticated and exc.code == 401 and retry_on_unauthorized:
                self.get_token(force_refresh=True)
                return self._request_json(
                    method=method,
                    url=url,
                    payload=payload,
                    authenticated=True,
                    retry_on_unauthorized=False,
                )

            raise BlkSealAPIError(
                f"API request failed with HTTP {exc.code}: {error_body}"
            ) from exc

        except Exception as exc:
            raise BlkSealAPIError(f"API request failed: {exc}") from exc

    # -------------------------
    # Signing
    # -------------------------

    def sign_text(
        self,
        lease_id: str,
        text: str,
        data_type: str = "string",
    ) -> Dict[str, Any]:
        self.canonical_validate(text)

        return self._request_json(
            "POST",
            self._url("/v1/sign"),
            {
                "lease_id": lease_id,
                "data": text,
                "data_type": data_type,
            },
            authenticated=True,
        )

    def sign_bytes(
        self,
        lease_id: str,
        data: bytes,
    ) -> Dict[str, Any]:
        hashed = self.hash_bytes(data)

        return self._request_json(
            "POST",
            self._url("/v1/sign"),
            {
                "lease_id": lease_id,
                "data": hashed,
                "data_type": "hash",
            },
            authenticated=True,
        )

    def sign_url(
        self,
        lease_id: str,
        url: str,
        timeout: Optional[Union[int, float]] = None,
        max_bytes: int = 25 * 1024 * 1024,
        data_type: str = "hash",
    ) -> Dict[str, Any]:
        hashed = self.hash_url(
            url,
            timeout=timeout,
            max_bytes=max_bytes,
        )

        return self._request_json(
            "POST",
            self._url("/v1/sign"),
            {
                "lease_id": lease_id,
                "data": hashed,
                "data_type": data_type,
            },
            authenticated=True,
        )

    # -------------------------
    # Verification
    # -------------------------

    def verify_text(
        self,
        text: str,
        signature_b64: str,
        private: bool = False,
    ) -> Dict[str, Any]:
        self.canonical_validate(text)

        endpoint = "/v1/verify-private" if private else "/v1/verify"

        return self._request_json(
            "POST",
            self._url(endpoint),
            {
                "signature_b64": signature_b64,
                "data": text,
                "data_type": "string",
            },
            authenticated=private,
        )

    def verify_bytes(
        self,
        data: bytes,
        signature_b64: str,
        private: bool = False,
    ) -> Dict[str, Any]:
        hashed = self.hash_bytes(data)

        endpoint = "/v1/verify-private" if private else "/v1/verify"

        return self._request_json(
            "POST",
            self._url(endpoint),
            {
                "signature_b64": signature_b64,
                "data": hashed,
                "data_type": "hash",
            },
            authenticated=private,
        )

    def verify_url(
        self,
        url: str,
        signature_b64: str,
        private: bool = False,
        timeout: Optional[Union[int, float]] = None,
        max_bytes: int = 25 * 1024 * 1024,
        data_type: str = "hash",
    ) -> Dict[str, Any]:
        hashed = self.hash_url(
            url,
            timeout=timeout,
            max_bytes=max_bytes,
        )

        endpoint = "/v1/verify-private" if private else "/v1/verify"

        return self._request_json(
            "POST",
            self._url(endpoint),
            {
                "signature_b64": signature_b64,
                "data": hashed,
                "data_type": data_type,
            },
            authenticated=private,
        )

