use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::config::{AuthType, Config, Location};

use headers::{
    authorization::{Basic, Bearer},
    Authorization, HeaderMapExt,
};
use http::status::StatusCode;

type HttpRequest = http::Request<hyper::Body>;

#[cfg(feature = "jwt")]
use jsonwebtoken;

#[derive(Clone)]
pub struct Auth {
    config: Arc<Config>,
    #[cfg(feature = "pam")]
    pam_auth: pam_sandboxed::PamAuth,

    #[cfg(feature = "jwt")]
    jwt_decoding_key: Option<jsonwebtoken::DecodingKey>,

    #[cfg(feature = "jwt")]
    jwt_encoding_key: Option<jsonwebtoken::EncodingKey>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct JwtClaims {
    pub sub: String,
    pub exp: u64,
}

#[derive(Debug, Clone)]
pub struct AuthResult {
    pub user: String,
    pub devired_token: bool,
}

impl Auth {
    pub fn new(config: Arc<Config>) -> io::Result<Auth> {
        // initialize pam.
        #[cfg(feature = "pam")]
        let pam_auth = {
            // set cache timeouts.
            if let Some(timeout) = config.pam.cache_timeout {
                crate::cache::cached::set_pamcache_timeout(timeout);
            }
            pam_sandboxed::PamAuth::new(config.pam.threads.clone())?
        };

        #[cfg(feature = "jwt")]
        let jwt_decoding_key = if config.jwt.enabled {
            Some(jsonwebtoken::DecodingKey::from_secret(config.jwt.secret.as_ref()))
        } else {
            None
        };
        #[cfg(feature = "jwt")]
        let jwt_encoding_key = if config.jwt.enabled {
            Some(jsonwebtoken::EncodingKey::from_secret(config.jwt.secret.as_ref()))
        } else {
            None
        };

        Ok(Auth {
            #[cfg(feature = "pam")]
            pam_auth,
            config,
            #[cfg(feature = "jwt")]
            jwt_decoding_key,
            #[cfg(feature = "jwt")]
            jwt_encoding_key,
        })
    }

    // authenticate user.
    pub async fn auth<'a>(
        &'a self,
        req: &'a HttpRequest,
        location: &Location,
        _remote_ip: SocketAddr,
    ) -> Result<AuthResult, StatusCode> {
        #[cfg(feature = "jwt")]
        if let Some(ref decoding_key) = self.jwt_decoding_key {
            if let Ok(r) = self.auth_jwt(req, decoding_key).await {
                return Ok(r);
            }
            // if jwt auth failed, try other auth
        }

        // we must have a login/pass
        let basic = match req.headers().typed_get::<Authorization<Basic>>() {
            Some(Authorization(basic)) => basic,
            _ => return Err(StatusCode::UNAUTHORIZED),
        };
        let user = basic.username();
        let pass = basic.password();

        // match the auth type.
        let auth_type = location
            .accounts
            .auth_type
            .as_ref()
            .or(self.config.accounts.auth_type.as_ref());
        match auth_type {
            #[cfg(feature = "pam")]
            Some(&AuthType::Pam) => self.auth_pam(req, user, pass, _remote_ip).await,
            Some(&AuthType::HtPasswd(ref ht)) => self.auth_htpasswd(user, pass, ht.as_str()).await,
            None => {
                debug!("need authentication, but auth-type is not set");
                Err(StatusCode::UNAUTHORIZED)
            },
        }
    }

    #[cfg(feature = "jwt")]
    async fn auth_jwt<'a>(
        &'a self,
        req: &'a HttpRequest,
        decoding_key: &jsonwebtoken::DecodingKey,
    ) -> Result<AuthResult, StatusCode> {
        let bearer = req
            .headers()
            .typed_get::<headers::Cookie>()
            .and_then(|cookie| {
                self.config
                    .jwt
                    .cookie_name
                    .as_ref()
                    .and_then(|cookie_name| cookie.get(cookie_name))
                    .map(|cookie| cookie.to_owned())
            })
            .or_else(|| {
                req.headers()
                    .typed_get::<Authorization<Bearer>>()
                    .map(|auth| auth.0.token().to_owned())
            });
        if let Some(bearer) = bearer {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                .and_then(|d| {
                    jsonwebtoken::decode::<JwtClaims>(
                        bearer.as_ref(),
                        decoding_key,
                        &jsonwebtoken::Validation::default(),
                    )
                    .map_err(|_| StatusCode::UNAUTHORIZED)
                    .and_then(|token| {
                        if token.claims.exp < d.as_secs() {
                            Err(StatusCode::UNAUTHORIZED)
                        } else {
                            Ok(AuthResult {
                                user: token.claims.sub,
                                devired_token: token.claims.exp
                                    < d.as_secs() + self.config.jwt.tiemout.unwrap_or(600) / 2,
                            })
                        }
                    })
                })
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    }

    pub async fn devired_token(
        &self,
        response: &mut hyper::Response<webdav_handler::body::Body>,
        auth_result: &AuthResult,
    ) -> Result<(), StatusCode> {
        if !auth_result.devired_token {
            // do not devired token
            return Ok(());
        }
        #[cfg(feature = "jwt")]
        if let Some(ref encoding_key) = self.jwt_encoding_key {
            if let Some(ref cookie_name) = self.config.jwt.cookie_name {
                let claims = JwtClaims {
                    sub: auth_result.user.to_owned(),
                    exp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                        .map(|d| d.as_secs() + self.config.jwt.tiemout.unwrap_or(600))?,
                };
                let token = jsonwebtoken::encode(&jsonwebtoken::Header::default(), &claims, encoding_key)
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
                response.headers_mut().append(
                    "Set-Cookie",
                    format!(
                        "{}={}; Path=/; Max-Age={}; HttpOnly",
                        cookie_name,
                        token,
                        self.config.jwt.tiemout.unwrap_or(600)
                    )
                    .parse()
                    .unwrap(),
                );
            }
        }
        Ok(())
    }

    // authenticate user using PAM.
    #[cfg(feature = "pam")]
    async fn auth_pam<'a>(
        &'a self,
        req: &'a HttpRequest,
        user: &'a str,
        pass: &'a str,
        remote_ip: SocketAddr,
    ) -> Result<AuthResult, StatusCode> {
        // stringify the remote IP address.
        let ip = remote_ip.ip();
        let ip_string = if ip.is_loopback() {
            // if it's loopback, take the value from the x-forwarded-for
            // header, if present.
            req.headers()
                .get("x-forwarded-for")
                .and_then(|s| s.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_owned())
        } else {
            Some(match ip {
                std::net::IpAddr::V4(ip) => ip.to_string(),
                std::net::IpAddr::V6(ip) => ip.to_string(),
            })
        };
        let ip_ref = ip_string.as_ref().map(|s| s.as_str());

        // authenticate.
        let service = self.config.pam.service.as_str();
        let pam_auth = self.pam_auth.clone();
        match crate::cache::cached::pam_auth(pam_auth, service, user, pass, ip_ref).await {
            Ok(_) => Ok(AuthResult {
                user: user.to_string(),
                devired_token: true,
            }),
            Err(_) => {
                debug!(
                    "auth_pam({}): authentication for {} ({:?}) failed",
                    service, user, ip_ref
                );
                Err(StatusCode::UNAUTHORIZED)
            },
        }
    }

    // authenticate user using htpasswd.
    async fn auth_htpasswd<'a>(
        &'a self,
        user: &'a str,
        pass: &'a str,
        section: &'a str,
    ) -> Result<AuthResult, StatusCode> {
        // Get the htpasswd.WHATEVER section from the config file.
        let file = match self.config.htpasswd.get(section) {
            Some(section) => section.htpasswd.as_str(),
            None => return Err(StatusCode::UNAUTHORIZED),
        };

        // Read the file and split it into a bunch of lines.
        tokio::task::block_in_place(move || {
            let data = match std::fs::read_to_string(file) {
                Ok(data) => data,
                Err(e) => {
                    debug!("{}: {}", file, e);
                    return Err(StatusCode::UNAUTHORIZED);
                },
            };
            let lines = data
                .split('\n')
                .map(|s| s.trim())
                .filter(|s| !s.starts_with("#") && !s.is_empty());

            // Check each line for a match.
            for line in lines {
                let mut fields = line.split(':');
                if let (Some(htuser), Some(htpass)) = (fields.next(), fields.next()) {
                    if htuser == user && pwhash::unix::verify(pass, htpass) {
                        return Ok(AuthResult {
                            user: user.to_string(),
                            devired_token: true,
                        });
                    }
                }
            }

            debug!("auth_htpasswd: authentication for {} failed", user);
            Err(StatusCode::UNAUTHORIZED)
        })
    }
}
