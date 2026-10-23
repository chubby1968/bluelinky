import got from 'got';
import { CookieJar } from 'tough-cookie';
import { constants, createHmac, createPublicKey, publicEncrypt, randomBytes } from 'crypto';
import { URLSearchParams } from 'url';
import { EULanguages, EuropeanBrandEnvironment } from '../../constants/europe';
import { uuidV4 } from '../../tools/common.tools';
import logger from '../../logger';

// OneApp/CCI login for EU Kia/Hyundai, modeled after evcc vehicle/bluelink/cci.go.
//
// The legacy IDPConnect authorize endpoint is WAF-blocked since 2026-08, so
// a new session has to be obtained via the OneApp client_id:
//   1. GET authorize (OneApp client_id)  → session cookies
//   2. GET /auth/api/v1/accounts/certs   → RSA public key
//   3. POST /auth/account/signin         → auth code in 302 Location
//   4. POST cci-api/auth/token           → CCI token set
//   5. POST cci-api/auth/token-exchange  → CCS token
// The CCS token is accepted unchanged by the legacy ccapi:8080 endpoints.

const CCI_CLIENT_VERSION = '1.3.3';
const MOBILE_USER_AGENT =
  'Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/535.19 (KHTML, like Gecko) Chrome/18.0.1025.166 Mobile Safari/535.19_CCS_APP_AOS';

// Android OneApp build identity the X-Fingerprint is validated against (see evcc cci.go)
const FP_CLIENT_VERSION = '1.4.0';
const FP_OS_VERSION = '14';
const FP_DEVICE_MODEL = 'SM-S918B';
const FP_USER_AGENT = 'okhttp/4.12.0';

const CCS_EXPIRY_FALLBACK = 60 * 60; // seconds, used when expiresTime is missing or implausible
const CCS_EXPIRY_MAX_VALIDITY = 24 * 60 * 60; // seconds, upper bound of a plausible expiry

export interface CCIBundle {
  accessToken: string; // CCS token (no "Bearer " prefix)
  expiresAt: number; // CCS token expiry, unix seconds
  refreshToken: string; // CCI refresh token
  deviceId: string; // client-device-id used for all CCI calls
  cciAccessToken: string;
  exchangeableToken: string;
  exchangeableRefreshToken: string;
  nonCcsToken: string;
  nonCcsRefreshToken: string;
  idToken: string;
}

interface CCITokenResponse {
  accessToken?: string;
  refreshToken?: string;
  nonCcsToken?: string;
  exchangeableAccessToken?: string;
  exchangeableRefreshToken?: string;
  nonCcsRefreshToken?: string;
  idToken?: string;
}

export class EuropeanCCIAuthStrategy {
  constructor(
    private readonly environment: EuropeanBrandEnvironment,
    private readonly language: EULanguages
  ) {}

  public get name(): string {
    return 'EuropeanCCIAuthStrategy';
  }

  public async login(user: { username: string; password: string }): Promise<CCIBundle> {
    const { cci, loginFormHost } = this.environment;
    const cookieJar = new CookieJar();

    // 1. authorize — the OneApp client_id is not on the WAF block list
    const authURL =
      `${loginFormHost}/auth/api/v2/user/oauth2/authorize?response_type=code` +
      `&client_id=${cci.oneAppClientID}&redirect_uri=${cci.oneAppRedirectURI}` +
      `&lang=${this.language}&state=ccsp&country=de`;
    const authResponse = await got(authURL, {
      cookieJar,
      headers: { 'User-Agent': MOBILE_USER_AGENT },
      throwHttpErrors: false,
    });
    if (
      String(authResponse.body).toLowerCase().includes('abusing') ||
      String(authResponse.url).includes('/error?status=400')
    ) {
      throw new Error(
        "@EuropeanCCIAuthStrategy.login: authorize rejected as 'abusing request' — server-side WAF block, not a credentials problem"
      );
    }
    if (authResponse.statusCode >= 400) {
      throw new Error(
        `@EuropeanCCIAuthStrategy.login: authorize failed: HTTP ${authResponse.statusCode}`
      );
    }

    // 2. rsa public key used to encrypt the password for signin
    const certResponse = await got(`${loginFormHost}/auth/api/v1/accounts/certs`, {
      cookieJar,
      headers: { 'User-Agent': MOBILE_USER_AGENT, 'Accept': 'application/json' },
      json: true,
    });
    const { kid, n, e } = certResponse.body.retValue;
    const encryptedPassword = encryptPassword(n, e, user.password);

    // 3. signin — the auth code arrives in the Location header
    const formData = new URLSearchParams({
      'client_id': cci.oneAppClientID,
      'encryptedPassword': 'true',
      'password': encryptedPassword,
      'redirect_uri': cci.oneAppRedirectURI,
      'scope': '',
      'nonce': '',
      'state': 'ccsp',
      'username': user.username,
      'connector_session_key': '',
      'kid': kid,
      '_csrf': '',
    });
    const signinResponse = await got.post(`${loginFormHost}/auth/account/signin`, {
      cookieJar,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': MOBILE_USER_AGENT,
      },
      body: formData.toString(),
      followRedirect: false,
      throwHttpErrors: false,
    });
    if (signinResponse.statusCode !== 302) {
      throw new Error(
        `@EuropeanCCIAuthStrategy.login: signin failed: HTTP ${signinResponse.statusCode}`
      );
    }

    const location = new URL(String(signinResponse.headers.location), loginFormHost);
    const code = location.searchParams.get('code');
    if (!code) {
      if (location.pathname.includes('/web/v1/user/authorization')) {
        throw new Error(
          '@EuropeanCCIAuthStrategy.login: account consent required: log in via the manufacturer app once to accept the terms, then retry'
        );
      }
      const errorDescription = location.searchParams.get('error_description');
      if (errorDescription) {
        throw new Error(`@EuropeanCCIAuthStrategy.login: signin rejected: ${errorDescription}`);
      }
      if (location.pathname.includes('authorize')) {
        throw new Error(
          '@EuropeanCCIAuthStrategy.login: redirected back to login page, check username and password'
        );
      }
      throw new Error(
        `@EuropeanCCIAuthStrategy.login: unexpected redirect after signin: ${location.origin}${location.pathname}`
      );
    }
    logger.debug('@EuropeanCCIAuthStrategy.login: auth code received');

    // 4. auth code → CCI token set
    const deviceId = uuidV4();
    const query = `?code=${encodeURIComponent(code)}`;
    const tokenResponse = await this.cciPost<CCITokenResponse>(
      { path: `/auth/v1/token${query}`, headers: this.fpHeaders(deviceId) },
      { path: `/domain/api/v1/auth/token${query}`, headers: this.headers(deviceId) }
    );
    const bundle = applyTokenResponse(emptyBundle(deviceId), tokenResponse);

    // 5. CCI token → CCS token
    return this.exchangeCCSToken(bundle);
  }

  public async refresh(bundle: CCIBundle): Promise<CCIBundle> {
    const body = JSON.stringify({
      accessToken: bundle.cciAccessToken,
      refreshToken: bundle.refreshToken,
      exchangeableAccessToken: bundle.exchangeableToken,
      exchangeableRefreshToken: bundle.exchangeableRefreshToken,
      nonCcsToken: bundle.nonCcsToken,
      nonCcsRefreshToken: bundle.nonCcsRefreshToken,
      idToken: bundle.idToken,
    });
    const tokenResponse = await this.cciPost<CCITokenResponse>(
      {
        path: '/auth/v2/token-refresh',
        headers: { ...this.fpHeaders(bundle.deviceId, body), 'Content-Type': 'application/json' },
        body,
      },
      {
        path: '/domain/api/v2/auth/token-refresh',
        headers: {
          ...this.headers(
            bundle.deviceId,
            bundle.cciAccessToken,
            bundle.nonCcsToken,
            bundle.exchangeableToken
          ),
          'Content-Type': 'application/json',
        },
        body,
      }
    );

    return this.exchangeCCSToken(applyTokenResponse({ ...bundle }, tokenResponse));
  }

  private async exchangeCCSToken(bundle: CCIBundle): Promise<CCIBundle> {
    const response = await this.cciPost<{ accessToken?: string; expiresTime?: number }>(
      {
        path: '/auth/v1/token-exchange?serviceType=CCS',
        headers: {
          ...this.fpHeaders(bundle.deviceId),
          ...tokenHeaders(bundle.cciAccessToken, bundle.nonCcsToken, bundle.exchangeableToken),
        },
      },
      {
        path: '/domain/api/v1/auth/token-exchange?serviceType=CCS',
        headers: this.headers(
          bundle.deviceId,
          bundle.cciAccessToken,
          bundle.nonCcsToken,
          bundle.exchangeableToken
        ),
      }
    );
    if (!response.accessToken) {
      throw new Error('@EuropeanCCIAuthStrategy: ccs token exchange returned no access token');
    }

    return {
      ...bundle,
      accessToken: response.accessToken,
      expiresAt: parseCCSExpiry(response.expiresTime),
    };
  }

  // tries the fingerprint-signed route and falls back to the legacy unsigned one
  // only when the fingerprint gate rejects it, so other errors stay intact
  private async cciPost<T>(signed: CCIRequest, legacy: CCIRequest): Promise<T> {
    const response = await this.send(signed);
    if (response.statusCode === 200) {
      return JSON.parse(response.body) as T;
    }

    const code = gateRejectionCode(response.statusCode, response.body);
    if (code === undefined) {
      throw this.requestError(signed.path, response);
    }
    logger.debug(
      `@EuropeanCCIAuthStrategy: fingerprint gate rejected ${signed.path.split('?')[0]} (code ${code}), using legacy route`
    );

    const legacyResponse = await this.send(legacy);
    if (legacyResponse.statusCode !== 200) {
      throw this.requestError(legacy.path, legacyResponse);
    }
    return JSON.parse(legacyResponse.body) as T;
  }

  private send(req: CCIRequest) {
    return got.post(this.environment.cci.apiURL + req.path, {
      headers: req.headers,
      body: req.body ?? '',
      throwHttpErrors: false,
    });
  }

  private requestError(path: string, response: { statusCode: number; body: unknown }): Error {
    return new Error(
      `@EuropeanCCIAuthStrategy: ${path.split('?')[0]} failed: HTTP ${
        response.statusCode
      } ${String(response.body).slice(0, 200)}`
    );
  }

  // headers of the fingerprint-gated auth endpoints, signed over the exact request body
  private fpHeaders(deviceId: string, body = ''): Record<string, string> {
    const { cci } = this.environment;
    const headers: Record<string, string> = {
      'client-id': cci.packageID,
      'client-name': cci.fingerprintClientName,
      'client-version': FP_CLIENT_VERSION,
      'client-os-code': 'android',
      'client-os-version': FP_OS_VERSION,
      'client-device-id': deviceId,
      'client-device-model': FP_DEVICE_MODEL,
      'client-notification-provider-type': 'FCM',
      'locale': this.language.toUpperCase(),
      'timezone': timezoneOffset(),
      'App-Request-Id': `${randomBytes(12).toString('hex').toUpperCase()}_${deviceId.replace(/-/g, '')}_AOS`,
      'X-Brand': cci.brandLabel,
      'X-Region': 'eu',
      'User-Agent': FP_USER_AGENT,
      'Accept': '*/*',
      'Accept-Language': this.language.toLowerCase(),
      'X-Timestamp': String(Date.now()),
    };
    headers['X-Fingerprint'] = fingerprint(headers, cci.fingerprintKey, body);
    return headers;
  }

  // headers required by the CCI API; token parameters are empty before the initial code exchange
  private headers(
    deviceId: string,
    cciAccessToken = '',
    nonCcsToken = '',
    exchangeableToken = ''
  ): Record<string, string> {
    const { cci } = this.environment;
    const headers: Record<string, string> = {
      'client-id': cci.packageID,
      'client-name': cci.clientName,
      'client-version': CCI_CLIENT_VERSION,
      'client-os-code': 'ios',
      'client-os-version': cci.osVersion,
      'client-device-id': deviceId,
      'client-device-model': 'iPhone',
      'client-notification-provider-type': cci.notificationProvider,
      'locale': this.language.toUpperCase(),
      'timezone': timezoneOffset(),
      'Accept': 'application/json',
      'Accept-Language': this.language,
      'User-Agent': MOBILE_USER_AGENT,
    };

    if (nonCcsToken) {
      headers['Authentication'] = nonCcsToken;
    }
    if (cciAccessToken) {
      headers['authorization'] = `Bearer ${cciAccessToken.trim().replace(/^Bearer /, '')}`;
    }
    if (exchangeableToken) {
      headers['exchangeable-token'] = exchangeableToken;
      headers['non-ccs-token'] = nonCcsToken;
    }

    return headers;
  }
}

interface CCIRequest {
  path: string;
  headers: Record<string, string>;
  body?: string;
}

// adds the CCI token headers, skipping empty tokens
const tokenHeaders = (
  cciAccessToken: string,
  nonCcsToken: string,
  exchangeableToken: string
): Record<string, string> => {
  const headers: Record<string, string> = {};
  if (nonCcsToken) {
    headers['Authentication'] = nonCcsToken;
  }
  if (cciAccessToken) {
    headers['authorization'] = `Bearer ${cciAccessToken.trim().replace(/^Bearer\s+/i, '')}`;
  }
  if (exchangeableToken) {
    headers['exchangeable-token'] = exchangeableToken;
    headers['non-ccs-token'] = nonCcsToken;
  }
  return headers;
};

// fingerprint gate rejections: header missing, bad signature, timestamp out of window
const FP_GATE_CODES = [9035, 9036, 9037];

const gateRejectionCode = (statusCode: number, body: unknown): number | undefined => {
  if (statusCode < 400 || statusCode >= 500) {
    return undefined;
  }
  try {
    const code = JSON.parse(String(body)).code;
    return FP_GATE_CODES.includes(code) ? code : undefined;
  } catch {
    return undefined;
  }
};

// HMAC-SHA256 over client identity, timestamp and body (ASCII whitespace stripped)
const fingerprint = (headers: Record<string, string>, key: string, body: string): string => {
  const identity =
    headers['client-id'] +
    headers['client-name'] +
    headers['client-version'] +
    headers['client-os-code'];
  const msg =
    identity +
    headers['client-os-version'] +
    headers['X-Timestamp'] +
    body.replace(/[ \t\n\v\f\r]/g, '');
  return createHmac('sha256', identity + key).update(msg).digest('hex');
};

const emptyBundle = (deviceId: string): CCIBundle => ({
  accessToken: '',
  expiresAt: 0,
  refreshToken: '',
  deviceId,
  cciAccessToken: '',
  exchangeableToken: '',
  exchangeableRefreshToken: '',
  nonCcsToken: '',
  nonCcsRefreshToken: '',
  idToken: '',
});

// copies the non-empty response fields into bundle, keeping unchanged ones
const applyTokenResponse = (bundle: CCIBundle, res: CCITokenResponse): CCIBundle => {
  bundle.cciAccessToken = res.accessToken || bundle.cciAccessToken;
  bundle.refreshToken = res.refreshToken || bundle.refreshToken;
  bundle.nonCcsToken = res.nonCcsToken || bundle.nonCcsToken;
  bundle.exchangeableToken = res.exchangeableAccessToken || bundle.exchangeableToken;
  bundle.exchangeableRefreshToken = res.exchangeableRefreshToken || bundle.exchangeableRefreshToken;
  bundle.nonCcsRefreshToken = res.nonCcsRefreshToken || bundle.nonCcsRefreshToken;
  bundle.idToken = res.idToken || bundle.idToken;
  return bundle;
};

// interprets the token-exchange expiresTime (unix seconds), falling back to a
// fixed lifetime rather than risking an always-expired token
const parseCCSExpiry = (expiresTime?: number): number => {
  const now = Math.floor(Date.now() / 1000);
  if (expiresTime && expiresTime > now && expiresTime < now + CCS_EXPIRY_MAX_VALIDITY) {
    return expiresTime;
  }
  return now + CCS_EXPIRY_FALLBACK;
};

// local UTC offset as '+HH:MM'
const timezoneOffset = (): string => {
  const offset = -new Date().getTimezoneOffset();
  const abs = Math.abs(offset);
  const pad = (v: number) => String(v).padStart(2, '0');
  return `${offset >= 0 ? '+' : '-'}${pad(Math.floor(abs / 60))}:${pad(abs % 60)}`;
};

// RSA/PKCS1v15-encrypts password using the JWK public key returned by the
// /accounts/certs endpoint and hex-encodes the ciphertext
const encryptPassword = (n: string, e: string, password: string): string => {
  const key = createPublicKey({
    key: { kty: 'RSA', n: n.replace(/=+$/, ''), e: e.replace(/=+$/, '') },
    format: 'jwk',
  });
  return publicEncrypt(
    { key, padding: constants.RSA_PKCS1_PADDING },
    Buffer.from(password, 'utf8')
  ).toString('hex');
};
