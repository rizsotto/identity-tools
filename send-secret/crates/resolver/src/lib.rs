//! Recipient resolution: sources, ordering, result model.

mod query;

pub use query::{Email, Host, Query, QueryError, parse_query};
