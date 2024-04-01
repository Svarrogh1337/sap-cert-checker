from urllib3.contrib import pyopenssl as rm
from urllib3.util import parse_url
from datetime import datetime
from socket import gaierror, timeout
from warnings import warn


def verify_protocol(url: str, port: int = 443) -> str | None:
    # Verify validity of the supplied URL schema.
    # Automatically switch to https if no schema is provided by the user.
    parsed = parse_url(url)
    if parsed.scheme is None:
        warn(f' Verifying {url}:{port} - no protocol was specified. Switching to HTTPS', UserWarning)
        return parsed.host
    if parsed.scheme == 'https':
        return parsed.host
    return warn(f'{url}:{port} parsing failed. Non-https protocol detected.', UserWarning)


def get_expiry_date(host: str, port: int = 443) -> datetime | None:
    cert_type = rm.OpenSSL.crypto.FILETYPE_PEM
    verified_url = verify_protocol(host)
    if verified_url is None:
        return warn(f'Supplied URL is invalid, '
                    f'please use protocol://host:port or host:port', UserWarning)
    # Retrieve the certificate from the server and handle the common errors gracefully.
    try:
        buffer = rm.ssl.get_server_certificate((verified_url, port))
    except gaierror:
        return warn(f'{verified_url}:{port}’s DNS address could not be found.', UserWarning)
    except timeout:
        return warn(f'{verified_url}:{port} is not available. Connection timeout', UserWarning)
    except Exception as err:
        return warn(f'{verified_url}:{port} is not available. Unknown error {err}', UserWarning)
    # Parse the certificate into X509 Object and retrieve expiration date
    parsed_cert = rm.OpenSSL.crypto.load_certificate(cert_type, str.encode(buffer))
    expiry_date = parsed_cert.get_notAfter()
    if expiry_date is None:
        return warn(f'{verified_url}:{port} Invalid certificate data', UserWarning)
    return datetime.strptime(expiry_date.decode('ascii'), '%Y%m%d%H%M%SZ')


if __name__ == '__main__':
    web_page = 'https://example.com'
    web_port = 443
    print(f'Certificate expiry for {web_page}:{web_port} is {get_expiry_date(host=web_page, port=web_port)}')
