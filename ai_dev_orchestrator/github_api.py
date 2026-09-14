"""Minimal stdlib GitHub REST boundary. No mutation retry or token logging."""
import json
import re
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler


class GitHubError(RuntimeError):
    def __init__(self, status=None, *, unknown_mutation=False, retry_after=None):
        self.status = status
        self.unknown_mutation = unknown_mutation
        self.retry_after = retry_after
        # Never include a server body, URL parameters, credentials or chained exception.
        super().__init__(f"GitHub request failed: status={status}; mutation_unknown={unknown_mutation}")


class DryRunViolation(GitHubError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class GitHubAPI:
    """Only the selected repository is reachable, including pagination links."""
    def __init__(self, repository, token, *, dry_run=False, opener=None, timeout=20):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("invalid repository")
        if not isinstance(token, str) or not token:
            raise ValueError("authentication unavailable")
        self.repository = repository
        self._token = token
        self.dry_run = dry_run
        self._open = opener or build_opener(_NoRedirect()).open
        self.timeout = timeout
        self.base = f"https://api.github.com/repos/{repository}/"
        self._repository_id = None

    def __repr__(self):
        return f"GitHubAPI(repository={self.repository!r}, dry_run={self.dry_run!r})"

    def _url(self, route):
        url = urljoin(self.base, route)
        parts = urlparse(url)
        prefix = urlparse(self.base).path
        if (parts.scheme != "https" or parts.netloc != "api.github.com"
                or parts.username or parts.fragment
                or any(x in parts.path for x in ("..", "%", "\\"))):
            raise ValueError("cross-repository/unsafe API route")
        allowed = parts.path.startswith(prefix) or parts.path == prefix.rstrip("/")
        if not allowed and parts.path.startswith("/repositories/"):
            # GitHub pagination can canonicalize owner/name to a numeric repo ID.
            # Resolve that ID through our already-approved alias before allowing it.
            if self._repository_id is None:
                metadata, _ = self.request("GET", self.base.rstrip("/"))
                if (type(metadata) is not dict or metadata.get("full_name") != self.repository
                        or type(metadata.get("id")) is not int):
                    raise ValueError("repository identity could not be verified")
                self._repository_id = metadata["id"]
            allowed = parts.path.startswith(f"/repositories/{self._repository_id}/")
        if not allowed:
            raise ValueError("cross-repository/unsafe API route")
        return url

    def request(self, method, route, payload=None):
        method = method.upper()
        if method not in ("GET", "POST", "PATCH", "PUT", "DELETE"):
            raise ValueError("unsupported method")
        if self.dry_run and method != "GET":
            raise DryRunViolation()
        url = self._url(route)
        data = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("utf-8")
        headers = {"Authorization": "Bearer " + self._token, "Accept": "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json"}
        for attempt in range(2 if method == "GET" else 1):
            try:
                with self._open(Request(url, data=data, headers=headers, method=method),
                                timeout=self.timeout) as response:
                    body = response.read()
                    result = None if not body else json.loads(body.decode("utf-8"))
                    return result, dict(response.headers)
            except HTTPError as exc:
                status = exc.code
                retry = exc.headers.get("Retry-After") if exc.headers else None
                if method == "GET" and status >= 500 and attempt == 0:
                    continue
                raise GitHubError(status, unknown_mutation=method != "GET" and status >= 500,
                                  retry_after=retry if retry and retry.isdigit() else None) from None
            except (URLError, TimeoutError, OSError, ValueError):
                if method == "GET" and attempt == 0:
                    continue
                raise GitHubError(unknown_mutation=method != "GET") from None

    def get(self, route):
        return self.request("GET", route)[0]

    def pages(self, route):
        seen = set()
        while route:
            url = self._url(route)
            if url in seen:
                raise GitHubError()
            seen.add(url)
            body, headers = self.request("GET", url)
            if not isinstance(body, list):
                raise GitHubError()
            yield from body
            link = next((v for k, v in headers.items() if k.lower() == "link"), "")
            match = re.search(r'<([^>]+)>;\s*rel="next"', link)
            route = match.group(1) if match else None

    def mutate_once(self, method, route, payload, reconcile):
        """On unknown outcome query once; only adopt a unique confirmed object.

        Missing objects after a timeout are not proof of absence. No blind retry.
        """
        try:
            return self.request(method, route, payload)[0]
        except GitHubError as exc:
            if not exc.unknown_mutation:
                raise
            candidates = list(reconcile())
            if len(candidates) == 1:
                return candidates[0]
            raise GitHubError(unknown_mutation=True) from None
