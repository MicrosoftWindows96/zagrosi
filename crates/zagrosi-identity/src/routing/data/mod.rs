// SPDX-License-Identifier: AGPL-3.0-or-later

//! Routing-layer data tables.
//!
//! Pure constant tables consumed by the routing decision and the
//! public-domain blocklist. Kept as their own submodule so the
//! curated lists can grow without crowding the logic modules.

pub mod public_domain_extras;
