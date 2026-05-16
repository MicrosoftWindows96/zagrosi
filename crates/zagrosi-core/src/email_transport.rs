// SPDX-License-Identifier: AGPL-3.0-or-later

//! Outbound-email transport port.
//!
//! Identity's email-outbox worker calls the active
//! [`EmailTransport`] impl after dequeuing a row. The default impl
//! (`LettreTransport`) ships in `zagrosi-identity`; per-tenant SMTP and
//! HTTP-API providers plug in via the same trait without touching identity.

use async_trait::async_trait;

/// Sink for outbound email messages.
#[async_trait]
pub trait EmailTransport: Send + Sync + 'static {
    /// Deliver the message. Implementations distinguish transient
    /// ([`EmailTransportError::Unavailable`]) from permanent
    /// ([`EmailTransportError::Permanent`]) failures so the worker's
    /// retry loop can treat them appropriately.
    async fn send(&self, message: EmailMessage) -> Result<(), EmailTransportError>;
}

/// Single outbound email value object.
///
/// `idempotency_key` is computed by the identity producer
/// (`sha256(user_id || event_kind || correlation_id)` or equivalent) so
/// the worker dequeue scan is safe under at-least-once delivery.
///
/// The `Debug` impl is custom: every PII-bearing field
/// (`from`, `to`, `subject`, `body_text`, `body_html`) is redacted.
/// Only the opaque `idempotency_key` survives debug output, so
/// `tracing::debug!(?msg)` cannot leak recipient identity or reset-token
/// URLs embedded in the body.
#[derive(Clone)]
pub struct EmailMessage {
    /// `From:` envelope sender.
    pub from: String,
    /// `To:` envelope recipient.
    pub to: String,
    /// Subject line.
    pub subject: String,
    /// Plain-text body.
    pub body_text: String,
    /// Optional HTML body. When `None`, the worker sends text-only.
    pub body_html: Option<String>,
    /// Idempotency key. Producers MUST regenerate the same key on retry.
    pub idempotency_key: String,
}

impl std::fmt::Debug for EmailMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailMessage")
            .field("from", &"<redacted>")
            .field("to", &"<redacted>")
            .field("subject", &"<redacted>")
            .field("body_text", &"<redacted>")
            .field("body_html", &self.body_html.as_ref().map(|_| "<redacted>"))
            .field("idempotency_key", &self.idempotency_key)
            .finish()
    }
}

/// Failure modes a transport may surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EmailTransportError {
    /// Transient failure (network blip, SMTP 4xx). Retry safe.
    ///
    /// The string carries operator-facing diagnostic context only; it
    /// must NOT include recipient addresses or message body fragments.
    /// Producers are expected to scrub before constructing this variant.
    #[error("transport unavailable: {0}")]
    Unavailable(String),
    /// Permanent failure. The categorisation distinguishes 5xx-level
    /// transport rejections (move row to `dead`) from address-level
    /// faults (skip the row but keep the rest of the batch).
    ///
    /// Carries a typed [`EmailTransportFault`] rather than a raw `String`
    /// so the retry loop can branch on the SMTP response class without
    /// regex-parsing log strings — and so a recipient address embedded
    /// in an SMTP response (e.g. `550 5.1.1 <bob@example.com>: User
    /// unknown`) cannot leak to logs via `format!("{e}")`.
    #[error("permanent failure: {fault}")]
    Permanent {
        /// Typed fault categorisation.
        fault: EmailTransportFault,
    },
}

/// Categorised permanent-failure detail.
///
/// The [`std::fmt::Display`] impl never includes the redacted recipient or
/// the upstream message text — only the SMTP response class. Producers
/// can stash diagnostic strings in [`EmailTransportFault::redacted_detail`]
/// for log-side audit, but the field is `RedactedString` so its `Display`
/// renders `"<redacted>"` regardless.
#[derive(Debug, Clone)]
pub struct EmailTransportFault {
    /// SMTP-style response category.
    pub category: PermanentFaultCategory,
    /// Numeric SMTP code, when known (e.g. `550`).
    pub smtp_code: Option<u16>,
    /// Operator-facing detail. Wraps a string in `RedactedString` so the
    /// `Display` impl does not leak recipient identifiers or message
    /// content even if the upstream transport echoes them back.
    pub redacted_detail: RedactedString,
}

impl std::fmt::Display for EmailTransportFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.smtp_code {
            Some(code) => write!(f, "{} (smtp {})", self.category, code),
            None => write!(f, "{}", self.category),
        }
    }
}

/// Closed categorisation of permanent SMTP / HTTP-API failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PermanentFaultCategory {
    /// Recipient address rejected (`5.1.x`).
    InvalidRecipient,
    /// Sender address rejected (`5.1.7`, `5.1.8`).
    InvalidSender,
    /// Message too large or content rejected (`5.3.x`).
    ContentRejected,
    /// Authentication failure to the upstream MTA (`5.7.x`).
    AuthRejected,
    /// Other permanent failure that does not fit a more specific bucket.
    Other,
}

impl std::fmt::Display for PermanentFaultCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            Self::InvalidRecipient => "invalid recipient",
            Self::InvalidSender => "invalid sender",
            Self::ContentRejected => "content rejected",
            Self::AuthRejected => "auth rejected",
            Self::Other => "permanent failure",
        };
        f.write_str(label)
    }
}

/// String wrapper whose [`std::fmt::Display`] renders only `<redacted>`.
///
/// The inner value remains reachable to operator tooling that explicitly
/// asks for it via [`RedactedString::reveal`], but never via interpolation
/// or `format!("{ ... }")`.
#[derive(Clone)]
pub struct RedactedString(String);

impl RedactedString {
    /// Wrap a string. Callers should pass operator-facing diagnostic
    /// detail; PII / secrets must not be passed to this type in the
    /// first place — redaction here is defence-in-depth, not the only
    /// hardening layer.
    #[must_use]
    pub const fn new(detail: String) -> Self {
        Self(detail)
    }

    /// Reveal the underlying string. Restricted call site (operator
    /// tooling, debugger).
    #[must_use]
    pub fn reveal(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RedactedString(<redacted>)")
    }
}

impl std::fmt::Display for RedactedString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_obj_safe};

    assert_obj_safe!(EmailTransport);
    assert_impl_all!(EmailMessage: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(EmailTransportError: Send, Sync, std::error::Error);
    assert_impl_all!(EmailTransportFault: Send, Sync, Clone, std::fmt::Debug);
    assert_impl_all!(RedactedString: Send, Sync, Clone, std::fmt::Debug);
    const _: fn() = || {
        fn require_static<T: 'static + Send + Sync>() {}
        require_static::<EmailTransportError>();
        require_static::<EmailTransportFault>();
        require_static::<RedactedString>();
    };

    #[test]
    fn debug_redacts_pii_fields() {
        let msg = EmailMessage {
            from: "alice@example.com".into(),
            to: "bob@example.com".into(),
            subject: "Reset your password".into(),
            body_text: "Token rst_secret".into(),
            body_html: Some("<a>rst_secret</a>".into()),
            idempotency_key: "key-1".into(),
        };
        let rendered = format!("{msg:?}");
        assert!(!rendered.contains("alice@example.com"));
        assert!(!rendered.contains("bob@example.com"));
        assert!(!rendered.contains("Reset your password"));
        assert!(!rendered.contains("rst_secret"));
        assert!(rendered.contains("key-1"));
        assert!(rendered.contains("redacted"));
    }

    #[test]
    fn permanent_fault_display_redacts_detail() {
        let fault = EmailTransportFault {
            category: PermanentFaultCategory::InvalidRecipient,
            smtp_code: Some(550),
            redacted_detail: RedactedString::new("5.1.1 <bob@example.com>: User unknown".into()),
        };
        let err = EmailTransportError::Permanent { fault };
        let rendered = format!("{err}");
        assert!(rendered.contains("invalid recipient"));
        assert!(rendered.contains("550"));
        assert!(!rendered.contains("bob@example.com"));
    }

    #[test]
    fn redacted_string_display_is_redacted() {
        let secret = RedactedString::new("hunter2".into());
        let rendered = format!("{secret}");
        assert_eq!(rendered, "<redacted>");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn redacted_string_debug_is_redacted() {
        let secret = RedactedString::new("hunter2".into());
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("hunter2"));
    }

    #[test]
    fn redacted_string_reveal_returns_inner() {
        let secret = RedactedString::new("hunter2".into());
        assert_eq!(secret.reveal(), "hunter2");
    }

    /// Compile-only test: a per-tenant SMTP impl satisfies the trait
    /// without breaking the public shape (forward-compat guard).
    #[allow(dead_code)]
    struct PerTenantSmtp;

    #[async_trait]
    impl EmailTransport for PerTenantSmtp {
        async fn send(&self, _message: EmailMessage) -> Result<(), EmailTransportError> {
            Ok(())
        }
    }
}
