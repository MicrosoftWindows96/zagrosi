// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::doc_markdown)]
//! `lettre`-backed [`EmailTransport`] implementation.
//!
//! [`LettreTransport`] is the default concrete transport the
//! email-outbox worker calls after dequeuing a row. It speaks SMTP
//! over **implicit TLS** (`smtps://`) only — the design forbids
//! cleartext and opportunistic-STARTTLS schemes, so
//! [`LettreTransport::from_config`] rejects any other URL scheme up
//! front rather than silently downgrading the connection.
//!
//! TLS uses rustls with the `aws-lc-rs` crypto provider. That is
//! selected by the workspace `lettre` feature set
//! (`tokio1-rustls` + `aws-lc-rs`, `default-features = false`); see
//! the pin rationale in the root `Cargo.toml`. The feature choice
//! cannot be re-asserted with a `cfg(feature = ...)` guard from this
//! crate because the features belong to the `lettre` dependency, not
//! `zagrosi-identity` — the workspace pin is the single source of
//! truth and a `cargo tree -e features` check belongs in CI.
//!
//! Per-tenant SMTP routing and HTTP-API providers are out of scope
//! here; they plug in behind the same [`EmailTransport`] trait
//! without touching this module (deferred to the admin layer).

use async_trait::async_trait;
use lettre::message::{Mailbox, MultiPart, SinglePart, header::ContentType};
use lettre::transport::smtp::AsyncSmtpTransport;
use lettre::{AsyncTransport, Message, Tokio1Executor};
use zagrosi_core::{
    EmailMessage, EmailTransport, EmailTransportError, EmailTransportFault, PermanentFaultCategory,
    RedactedString,
};

use crate::config::EmailConfig;
use crate::error::IdentityError;

/// Default SMTP-implicit-TLS scheme. The only scheme accepted by
/// [`LettreTransport::from_config`].
const REQUIRED_SCHEME: &str = "smtps://";

/// `lettre` async-SMTP transport with a built-in connection pool.
///
/// Cloning is cheap and shares the underlying pooled connections, so
/// the worker can hand clones to concurrent row processors.
#[derive(Clone)]
pub struct LettreTransport {
    mailer: AsyncSmtpTransport<Tokio1Executor>,
}

impl std::fmt::Debug for LettreTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The mailer wraps the credentialed URL; never render it.
        f.write_str("LettreTransport(<redacted>)")
    }
}

impl LettreTransport {
    /// Build a transport from [`EmailConfig`].
    ///
    /// Validation performed here (deferred from `IdentityConfig::load`
    /// so non-worker binaries start without SMTP configured):
    ///
    /// - `smtp_url` is non-empty and uses the `smtps://` scheme.
    /// - `smtp_url` parses as a `lettre` connection URL.
    /// - `smtp_from` is non-empty and parses as a mailbox.
    ///
    /// # Errors
    ///
    /// [`IdentityError::EmailTransportConfig`] with an operator-facing
    /// reason that **never** echoes the credentialed URL.
    pub fn from_config(cfg: &EmailConfig) -> Result<Self, IdentityError> {
        if cfg.smtp_url.is_empty() {
            return Err(IdentityError::EmailTransportConfig {
                reason: "ZAGROSI_EMAIL.SMTP_URL is required to run the email worker".into(),
            });
        }
        // Scheme check is a literal prefix test, not a parse, so the
        // credential in the URL is never split out into a value that
        // could later be logged.
        if !cfg.smtp_url.starts_with(REQUIRED_SCHEME) {
            return Err(IdentityError::EmailTransportConfig {
                reason: format!(
                    "ZAGROSI_EMAIL.SMTP_URL must use the `{REQUIRED_SCHEME}` scheme \
                     (implicit TLS); cleartext and opportunistic STARTTLS are refused"
                ),
            });
        }
        if cfg.smtp_from.is_empty() {
            return Err(IdentityError::EmailTransportConfig {
                reason: "ZAGROSI_EMAIL.SMTP_FROM is required to run the email worker".into(),
            });
        }
        // Validate the sender mailbox now so a misconfiguration fails
        // at worker construction, not on the first dequeued row.
        cfg.smtp_from
            .parse::<Mailbox>()
            .map_err(|_| IdentityError::EmailTransportConfig {
                reason: "ZAGROSI_EMAIL.SMTP_FROM is not a valid mailbox \
                         (expected `Name <user@host>` or `user@host`)"
                    .into(),
            })?;

        let builder =
            AsyncSmtpTransport::<Tokio1Executor>::from_url(&cfg.smtp_url).map_err(|_| {
                IdentityError::EmailTransportConfig {
                    // Deliberately generic: the lettre error can echo the
                    // host portion of the URL; keep it out of the reason.
                    reason: "ZAGROSI_EMAIL.SMTP_URL is not a valid SMTP connection URL".into(),
                }
            })?;
        Ok(Self {
            mailer: builder.build(),
        })
    }

    /// Construct directly from an already-built `lettre` mailer.
    /// Used by tests and by future per-tenant routing that builds the
    /// mailer through a different path.
    #[must_use]
    pub const fn from_mailer(mailer: AsyncSmtpTransport<Tokio1Executor>) -> Self {
        Self { mailer }
    }
}

/// Build the `lettre` [`Message`] from the worker's value object.
///
/// A build failure (malformed mailbox or header) is a **permanent**
/// fault: re-sending the identical bytes will fail identically, so
/// the row must dead-letter rather than spin the retry schedule.
fn build_message(msg: &EmailMessage) -> Result<Message, EmailTransportError> {
    let from = msg
        .from
        .parse::<Mailbox>()
        .map_err(|_| permanent(PermanentFaultCategory::InvalidSender, "unparseable From"))?;
    let to = msg
        .to
        .parse::<Mailbox>()
        .map_err(|_| permanent(PermanentFaultCategory::InvalidRecipient, "unparseable To"))?;

    let builder = Message::builder()
        .from(from)
        .to(to)
        .subject(msg.subject.clone());

    let message = match &msg.body_html {
        Some(html) => builder.multipart(MultiPart::alternative_plain_html(
            msg.body_text.clone(),
            html.clone(),
        )),
        None => builder.singlepart(
            SinglePart::builder()
                .header(ContentType::TEXT_PLAIN)
                .body(msg.body_text.clone()),
        ),
    };

    message.map_err(|_| {
        permanent(
            PermanentFaultCategory::ContentRejected,
            "message build failed",
        )
    })
}

/// Helper to construct a redaction-safe permanent fault. `detail` is
/// an operator-facing constant only — never attacker / recipient
/// content (which the wrapper would redact anyway).
fn permanent(category: PermanentFaultCategory, detail: &str) -> EmailTransportError {
    EmailTransportError::Permanent {
        fault: EmailTransportFault {
            category,
            smtp_code: None,
            redacted_detail: RedactedString::new(detail.to_owned()),
        },
    }
}

/// Classify a `lettre` SMTP send error.
///
/// `lettre` distinguishes permanent (5xx-class) from transient
/// (4xx-class / connection / timeout) failures. Permanent → the row
/// dead-letters. Everything else → transient, so the worker's
/// backoff schedule retries until the cap. Fine-grained
/// recipient-vs-content sub-categorisation of 5xx replies is a
/// deferred refinement; v0.1 maps every permanent SMTP failure to
/// [`PermanentFaultCategory::Other`].
///
/// **PII:** `lettre::transport::smtp::Error`'s `Display` appends its
/// source chain, and for a `Response`/`Transient` kind that source is
/// the raw SMTP reply text — which routinely echoes the envelope
/// `RCPT TO` address (`452 4.1.1 <bob@example.com> Mailbox full`).
/// `err.to_string()` is therefore **never** used here; the worker
/// records only a static kind-bucket label in `last_error`. The
/// underlying error is logged once, at the worker call site, behind
/// the redacted-`Debug` boundary.
fn classify(err: &lettre::transport::smtp::Error) -> EmailTransportError {
    if err.is_permanent() {
        permanent(PermanentFaultCategory::Other, "smtp permanent failure")
    } else {
        EmailTransportError::Unavailable("smtp transient failure".to_owned())
    }
}

#[async_trait]
impl EmailTransport for LettreTransport {
    async fn send(&self, message: EmailMessage) -> Result<(), EmailTransportError> {
        let built = build_message(&message)?;
        self.mailer
            .send(built)
            .await
            .map(|_| ())
            .map_err(|e| classify(&e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_impl_all;

    assert_impl_all!(LettreTransport: Send, Sync, Clone, std::fmt::Debug);

    fn cfg(url: &str, from: &str) -> EmailConfig {
        EmailConfig {
            smtp_url: url.into(),
            smtp_from: from.into(),
        }
    }

    #[test]
    fn empty_url_is_rejected() {
        let err = LettreTransport::from_config(&cfg("", "a@b.test")).unwrap_err();
        assert!(matches!(err, IdentityError::EmailTransportConfig { .. }));
    }

    #[test]
    fn non_smtps_scheme_is_rejected() {
        for url in [
            "smtp://user:pw@host:25",
            "smtp://host:587?tls=required",
            "http://host",
        ] {
            let err = LettreTransport::from_config(&cfg(url, "a@b.test")).unwrap_err();
            match err {
                IdentityError::EmailTransportConfig { reason } => {
                    assert!(
                        reason.contains("smtps://"),
                        "reason should name the required scheme, got: {reason}",
                    );
                }
                other => panic!("expected EmailTransportConfig, got {other:?}"),
            }
        }
    }

    #[test]
    fn config_reason_never_echoes_the_credentialed_url() {
        // A bad-but-smtps URL with an embedded password: the failure
        // reason must not leak the secret.
        let err = LettreTransport::from_config(&cfg("smtps://user:sup3rsecret@", "a@b.test"))
            .unwrap_err();
        let IdentityError::EmailTransportConfig { reason } = err else {
            panic!("expected EmailTransportConfig");
        };
        assert!(
            !reason.contains("sup3rsecret"),
            "reason must not echo the SMTP password: {reason}",
        );
    }

    #[test]
    fn empty_from_is_rejected() {
        let err = LettreTransport::from_config(&cfg("smtps://host:465", "")).unwrap_err();
        match err {
            IdentityError::EmailTransportConfig { reason } => {
                assert!(reason.contains("SMTP_FROM"));
            }
            other => panic!("expected EmailTransportConfig, got {other:?}"),
        }
    }

    #[test]
    fn invalid_from_mailbox_is_rejected() {
        let err = LettreTransport::from_config(&cfg("smtps://host:465", "not a mailbox at all"))
            .unwrap_err();
        assert!(matches!(err, IdentityError::EmailTransportConfig { .. }));
    }

    // `#[tokio::test]`: the pooled `lettre` transport's `Drop` needs a
    // tokio runtime in scope (it tears down the async connection
    // pool). A plain `#[test]` aborts with "panic in a destructor".
    // No network I/O happens here — `from_url` only parses and
    // `build()` is infallible.
    #[tokio::test]
    async fn valid_smtps_config_builds_a_transport() {
        let t = LettreTransport::from_config(&cfg(
            "smtps://user:pw@smtp.example.com:465",
            "Zagrosi <no-reply@example.com>",
        ))
        .expect("valid smtps config builds");
        assert_eq!(format!("{t:?}"), "LettreTransport(<redacted>)");
    }

    #[test]
    fn build_message_text_only_is_singlepart() {
        let msg = EmailMessage {
            from: "from@example.com".into(),
            to: "to@example.com".into(),
            subject: "Subject".into(),
            body_text: "Plain body".into(),
            body_html: None,
            idempotency_key: "k".into(),
        };
        build_message(&msg).expect("text-only message builds");
    }

    #[test]
    fn build_message_with_html_is_multipart() {
        let msg = EmailMessage {
            from: "from@example.com".into(),
            to: "to@example.com".into(),
            subject: "Subject".into(),
            body_text: "Plain".into(),
            body_html: Some("<p>HTML</p>".into()),
            idempotency_key: "k".into(),
        };
        build_message(&msg).expect("multipart message builds");
    }

    #[test]
    fn build_message_bad_recipient_is_permanent_invalid_recipient() {
        let msg = EmailMessage {
            from: "from@example.com".into(),
            to: "@@not-an-address@@".into(),
            subject: "S".into(),
            body_text: "B".into(),
            body_html: None,
            idempotency_key: "k".into(),
        };
        match build_message(&msg) {
            Err(EmailTransportError::Permanent { fault }) => {
                assert_eq!(fault.category, PermanentFaultCategory::InvalidRecipient);
            }
            other => panic!("expected Permanent InvalidRecipient, got {other:?}"),
        }
    }

    #[test]
    fn build_message_bad_sender_is_permanent_invalid_sender() {
        let msg = EmailMessage {
            from: "## bogus ##".into(),
            to: "to@example.com".into(),
            subject: "S".into(),
            body_text: "B".into(),
            body_html: None,
            idempotency_key: "k".into(),
        };
        match build_message(&msg) {
            Err(EmailTransportError::Permanent { fault }) => {
                assert_eq!(fault.category, PermanentFaultCategory::InvalidSender);
            }
            other => panic!("expected Permanent InvalidSender, got {other:?}"),
        }
    }
}
