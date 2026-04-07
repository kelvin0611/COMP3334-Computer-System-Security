import os
import uvicorn


def env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def main():
    host = os.environ.get("IM_HOST", "127.0.0.1")
    https_port = int(os.environ.get("IM_HTTPS_PORT", "8443"))
    http_port = int(os.environ.get("IM_HTTP_PORT", "8000"))
    cert_file = os.environ.get("IM_TLS_CERT_FILE", "cert.pem")
    key_file = os.environ.get("IM_TLS_KEY_FILE", "key.pem")
    allow_insecure = env_bool("IM_ALLOW_INSECURE_HTTP", False)
    reload_on = env_bool("IM_RELOAD", True)

    cert_exists = os.path.exists(cert_file)
    key_exists = os.path.exists(key_file)

    if cert_exists and key_exists:
        print(f"Starting TLS server on https://{host}:{https_port}")
        uvicorn.run(
            "server:app",
            host=host,
            port=https_port,
            reload=reload_on,
            ssl_certfile=cert_file,
            ssl_keyfile=key_file,
        )
        return

    if not allow_insecure:
        raise RuntimeError(
            "TLS is default. Missing cert.pem/key.pem (or IM_TLS_CERT_FILE/IM_TLS_KEY_FILE). "
            "Generate certs or set IM_ALLOW_INSECURE_HTTP=1 for local HTTP testing."
        )

    print(f"WARNING: Starting insecure HTTP server on http://{host}:{http_port}")
    uvicorn.run("server:app", host=host, port=http_port, reload=reload_on)


if __name__ == "__main__":
    main()

