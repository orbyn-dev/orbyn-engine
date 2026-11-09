//! Calendar feed fetch wire types.

use serde::{Deserialize, Serialize};
use ts_rs::TS;

/// `POST /v1/feeds/fetch`: a calendar feed for a trusted device to read.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FeedFetch {
    /// An `https://` link to a public calendar.
    pub url: String,
}

/// The answer to [`FeedFetch`]: the feed's text as the calendar's server sent it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, TS)]
#[ts(export)]
pub struct FeedFetched {
    pub status: u16,
    pub body: String,
}
