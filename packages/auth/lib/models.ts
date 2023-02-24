export interface ProviderConfig {
    id?: number;
    created_at?: Date;
    updated_at?: Date;
    unique_key: string;
    provider: string;
    oauth_client_id: string;
    oauth_client_secret: string;
    oauth_scopes: string;
    account_id: number;
}

export interface ProviderTemplate {
    auth_mode: ProviderAuthModes;
    authorization_url: string;
    authorization_params?: Record<string, string>;
    scope_separator?: string;
    token_url: string;
    token_params?: {
        [key: string]: string;
    };
    redirect_uri_metadata?: Array<string>;
}

export interface Connection {
    id?: number;
    created_at?: Date;
    updated_at?: Date;
    provider_config_key: string;
    connection_id: string;
    credentials: AuthCredentials;
    connection_config: Record<string, string>;
    account_id: number;
    metadata: Record<string, string>;
}

export interface Account {
    id: number;
    email: string;
    secret_key: string;
    public_key: string;
    callback_url: string | null;
}

export interface User {
    id: number;
    email: string;
    name: string;
}

export enum OAuthBodyFormat {
    FORM = 'form',
    JSON = 'json'
}

export enum OAuthAuthorizationMethod {
    BODY = 'body',
    HEADER = 'header'
}

export interface CredentialsCommon {
    type: ProviderAuthModes;
    raw: Record<string, string>; // Raw response for credentials as received by the OAuth server or set by the user
}

export interface OAuth2Credentials extends CredentialsCommon {
    type: ProviderAuthModes.OAuth2;
    access_token: string;

    refresh_token?: string;
    expires_at?: Date;
}

export interface OAuth1Credentials extends CredentialsCommon {
    type: ProviderAuthModes.OAuth1;
    oauth_token: string;
    oauth_token_secret: string;
}

export enum ProviderAuthModes {
    OAuth1 = 'OAUTH1',
    OAuth2 = 'OAUTH2'
}

export type AuthCredentials = OAuth2Credentials | OAuth1Credentials;

export interface ProviderTemplateOAuth1 extends ProviderTemplate {
    auth_mode: ProviderAuthModes.OAuth1;

    request_url: string;
    request_params?: Record<string, string>;
    request_http_method?: 'GET' | 'PUT' | 'POST'; // Defaults to POST if not provided

    token_http_method?: 'GET' | 'PUT' | 'POST'; // Defaults to POST if not provided

    signature_method: 'HMAC-SHA1' | 'RSA-SHA1' | 'PLAINTEXT';
}

export interface ProviderTemplateOAuth2 extends ProviderTemplate {
    auth_mode: ProviderAuthModes.OAuth2;

    disable_pkce?: boolean; // Defaults to false (=PKCE used) if not provided

    token_params?: {
        grant_type?: 'authorization_code' | 'client_credentials';
    };
    authorization_method?: OAuthAuthorizationMethod;
    body_format?: OAuthBodyFormat;

    refresh_url?: string;
}

export type OAuth1RequestTokenResult = {
    request_token: string;
    request_token_secret: string;
    parsed_query_string: any;
};

export interface OAuthSession {
    providerConfigKey: string;
    provider: string;
    connectionId: string;
    callbackUrl: string;
    authMode: ProviderAuthModes;
    id: string;
    connectionConfig: Record<string, string>;
    accountId: number;
    webSocketClientId: string | undefined;

    // Needed for OAuth 2.0 PKCE
    codeVerifier: string;

    // Needed for oAuth 1.0a
    request_token_secret?: string;
}

export interface OAuthSessionStore {
    [key: string]: OAuthSession;
}

export interface CredentialsRefresh {
    providerConfigKey: string;
    connectionId: string;
    promise: Promise<OAuth2Credentials>;
}
