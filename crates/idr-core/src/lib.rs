//! Shared IDR core: errors, session/stream traits, connectors, bounded queues.

pub mod connector;
pub mod error;
pub mod flow;
pub mod queue;
pub mod session;
pub mod stream;

pub use connector::{Connector, ConnectorRegistry, NamedService};
pub use error::{IdrError, IdrErrorKind, Result};
pub use flow::FlowController;
pub use queue::BoundedQueue;
pub use session::{OpenStreamRequest, PeerSession};
pub use stream::{LogicalStream, StreamId};
