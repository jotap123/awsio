"""SSO OIDC helper functions used to obtain short-lived access tokens.

Provides a tiny cache layer and a device-code authorization flow that interacts
with AWS SSO OIDC service.
"""
import os
import json
import time
import boto3
import webbrowser

from datetime import datetime, timezone, timedelta
from awsio.config import CACHE_FILE


def load_cache():
    """
    Load the token cache from disk.

    Returns:
        dict: Parsed cache content or empty dict if file missing or invalid.
    """
    if os.path.isfile(CACHE_FILE):
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_cache(data):
    """
    Save token/cache data to disk.

    Args:
        data (dict): Data to persist (e.g., {'access_token': str, 'expires_at': isoformat_str}).
    """
    os.makedirs(os.path.dirname(CACHE_FILE), exist_ok=True)
    with open(CACHE_FILE, 'w') as f:
        json.dump(data, f)


def authentication(sso_oidc, use_cache=True):
    """
    Perform device-flow authentication against AWS SSO OIDC and return an access token.

    This function will:
      - Read a cached token if available and not expired (when use_cache=True).
      - Run the device authorization flow, opening the verification URL in the user's browser.
      - Poll the sso-oidc service until the token is available or a timeout occurs.
      - Cache the token (when use_cache=True).

    Args:
        sso_oidc (boto3 sso-oidc client): Pre-created boto3 client for the sso-oidc service.
        use_cache (bool): Whether to attempt using and updating the local cache.

    Returns:
        str: The access token string.

    Raises:
        Exception: For authentication failures or timeouts.
    """
    try:
        now = datetime.now(timezone.utc)

        # Reutilizar access_token se ainda válido e cache habilitado
        if use_cache:
            cache = load_cache()
            if 'access_token' in cache and 'expires_at' in cache:
                expires_at = datetime.fromisoformat(cache['expires_at'])
                if now < expires_at - timedelta(seconds=60):
                    print("🔄 Usando access token em cache. Expira em", expires_at)
                    return cache['access_token']

        # Fluxo de device authorization
        register = sso_oidc.register_client(
            clientName=os.getenv('OIDC_APP_NAME', ''),
            clientType='public'
        )
        client_id = register['clientId']
        client_secret = register['clientSecret']

        start = sso_oidc.start_device_authorization(
            clientId=client_id,
            clientSecret=client_secret,
            startUrl=os.getenv('START_URL', '')
        )
        device_code = start['deviceCode']
        verification_uri = start['verificationUriComplete']

        print("🔑 Abra no navegador e faça login:", verification_uri)
        webbrowser.open(verification_uri)

        max_attempts = 60  # 5 minutos máximo
        attempts = 0
        while attempts < max_attempts:
            try:
                resp = sso_oidc.create_token(
                    clientId=client_id,
                    clientSecret=client_secret,
                    grantType='urn:ietf:params:oauth:grant-type:device_code',
                    deviceCode=device_code
                )
                break
            except sso_oidc.exceptions.AuthorizationPendingException:
                time.sleep(start['interval'])
                attempts += 1
            except Exception as e:
                raise Exception(f"Erro na autenticação: {e}")
        else:
            raise Exception("Timeout na autenticação - tente novamente")

        access_token = resp['accessToken']
        expires_in = resp['expiresIn']
        expires_at = now + timedelta(seconds=expires_in)

        # Salvar em cache se habilitado
        if use_cache:
            save_cache({
                'access_token': access_token,
                'expires_at': expires_at.isoformat()
            })
            print("✅ Token obtido e salvo em cache. Expira em", expires_at)
        else:
            print("✅ Token obtido (cache desabilitado)")
        
        return access_token
    except Exception as e:
        print(f"❌ Erro na autenticação: {e}")
        raise
