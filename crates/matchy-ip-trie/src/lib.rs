//! IP Tree Builder - Binary Trie for IP Address Lookups
//!
//! Builds a binary search tree for IP address lookups with CIDR prefix support.
//! Supports both IPv4 and IPv6 addresses.

use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

// Validation module for IP tree structures
pub mod validation;

// Re-export validation types for convenience
pub use validation::{validate_ip_tree, IpTreeStats, IpTreeValidationResult};
/// Error type for IP tree operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpTreeError {
    /// Invalid pattern or input
    InvalidPattern(String),
    /// Resource limit exceeded
    ResourceLimitExceeded(String),
    /// Other error
    Other(String),
}

impl fmt::Display for IpTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPattern(msg) => write!(f, "Invalid pattern: {msg}"),
            Self::ResourceLimitExceeded(msg) => {
                write!(f, "Resource limit exceeded: {msg}")
            }
            Self::Other(msg) => write!(f, "{msg}"),
        }
    }
}

impl std::error::Error for IpTreeError {}

/// Record size - determines node size in binary format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSize {
    /// 24-bit records (3 bytes per record, 6 bytes per node)
    Bits24 = 24,
    /// 28-bit records (3.5 bytes per record, 7 bytes per node)
    Bits28 = 28,
    /// 32-bit records (4 bytes per record, 8 bytes per node)
    Bits32 = 32,
}

impl RecordSize {
    /// Get the size of a node (2 records) in bytes
    #[must_use]
    pub fn node_bytes(self) -> usize {
        match self {
            Self::Bits24 => 6,
            Self::Bits28 => 7,
            Self::Bits32 => 8,
        }
    }

    /// Return the largest record value representable by this width.
    #[must_use]
    const fn max_record_value(self) -> u32 {
        match self {
            Self::Bits24 => 0x00ff_ffff,
            Self::Bits28 => 0x0fff_ffff,
            Self::Bits32 => u32::MAX,
        }
    }

    /// Select this width or the next wider width that can represent `value`.
    #[must_use]
    const fn widen_for(self, value: u32) -> Self {
        match self {
            Self::Bits24 if value > Self::Bits24.max_record_value() => {
                if value <= Self::Bits28.max_record_value() {
                    Self::Bits28
                } else {
                    Self::Bits32
                }
            }
            Self::Bits28 if value > Self::Bits28.max_record_value() => Self::Bits32,
            _ => self,
        }
    }
}

/// IP tree builder using arena allocation
pub struct IpTreeBuilder {
    /// Record size for the tree
    record_size: RecordSize,
    /// All nodes in the tree (arena)
    nodes: Vec<Node>,
    /// Original prefix attachments retained for all-matches builds.
    prefix_matches: Vec<PrefixMatch>,
    /// IP version (determines tree depth)
    ip_version: IpVersion,
}

/// IP version for the tree
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IpVersion {
    V4,
    V6,
}

/// A node in the IP tree
#[derive(Debug, Clone)]
struct Node {
    /// Left child (bit 0)
    left: NodePointer,
    /// Right child (bit 1)
    right: NodePointer,
}

/// One value attached to an exact prefix.
#[derive(Debug, Clone, Copy)]
struct PrefixMatch {
    bits: u128,
    prefix_len: u8,
    value: u32,
}

/// A temporary logical prefix node used to form cumulative match sets.
#[derive(Debug, Clone)]
struct CompleteNode {
    children: [Option<u32>; 2],
    values: Vec<u32>,
}

/// Node pointer - can point to another node, data, or be empty
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NodePointer {
    /// Points to another node (value is node ID)
    Node(u32),
    /// Points to data section (data offset, prefix length)
    /// Prefix length is tracked to enable proper longest-prefix matching:
    /// - When inserting a less-specific prefix after a more-specific one, we can compare
    /// - More specific (longer prefix) always wins
    /// - This doesn't affect the on-disk format, only the building logic
    Data(u32, u8),
    /// Empty (not found marker)
    Empty,
}

impl IpTreeBuilder {
    /// Create a new IPv4 tree builder
    #[must_use]
    pub fn new_v4(record_size: RecordSize) -> Self {
        let mut builder = Self {
            record_size,
            nodes: Vec::new(),
            prefix_matches: Vec::new(),
            ip_version: IpVersion::V4,
        };
        // Allocate root node
        builder.nodes.push(Node::new_empty());
        builder
    }

    /// Create a new IPv6 tree builder (can include IPv4)
    #[must_use]
    pub fn new_v6(record_size: RecordSize) -> Self {
        let mut builder = Self {
            record_size,
            nodes: Vec::new(),
            prefix_matches: Vec::new(),
            ip_version: IpVersion::V6,
        };
        // Allocate root node
        builder.nodes.push(Node::new_empty());
        builder
    }

    /// Reserve capacity for nodes to avoid reallocation
    ///
    /// # Arguments
    /// * `capacity` - Expected number of nodes
    pub fn reserve_nodes(&mut self, capacity: usize) {
        self.nodes
            .reserve(capacity.saturating_sub(self.nodes.len()));
    }

    /// Insert an IP address or CIDR range with associated data offset
    ///
    /// # Arguments
    /// * `addr` - IP address (v4 or v6)
    /// * `prefix_len` - Network prefix length (netmask)
    /// * `data_offset` - Offset into the data section
    pub fn insert(
        &mut self,
        addr: IpAddr,
        prefix_len: u8,
        data_offset: u32,
    ) -> Result<(), IpTreeError> {
        let (bits, tree_prefix_len) = match addr {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(IpTreeError::InvalidPattern(format!(
                        "IPv4 prefix length {prefix_len} exceeds 32"
                    )));
                }

                if self.ip_version == IpVersion::V6 {
                    // Per MMDB, IPv4 addresses occupy the 96-zero-bit prefix.
                    let bits = u128::from(ipv4_to_bits(v4));
                    (bits, 96 + prefix_len)
                } else {
                    // Pure IPv4 tree
                    let bits = u128::from(ipv4_to_bits(v4));
                    (bits << 96, prefix_len)
                }
            }
            IpAddr::V6(v6) => {
                if self.ip_version == IpVersion::V4 {
                    return Err(IpTreeError::InvalidPattern(
                        "Cannot insert IPv6 address into IPv4-only tree".to_string(),
                    ));
                }
                if prefix_len > 128 {
                    return Err(IpTreeError::InvalidPattern(format!(
                        "IPv6 prefix length {prefix_len} exceeds 128"
                    )));
                }
                let bits = bits_to_u128(ipv6_to_bits(v6));
                (bits, prefix_len)
            }
        };

        self.insert_bits_u128(bits, tree_prefix_len, data_offset)?;
        self.prefix_matches.push(PrefixMatch {
            bits,
            prefix_len: tree_prefix_len,
            value: data_offset,
        });
        Ok(())
    }

    /// Insert bits into tree using iterative approach (avoids borrow checker issues)
    fn insert_bits_u128(
        &mut self,
        bits: u128,
        prefix_len: u8,
        data_offset: u32,
    ) -> Result<(), IpTreeError> {
        let max_depth = match self.ip_version {
            IpVersion::V4 => 32,
            IpVersion::V6 => 128,
        };

        if prefix_len > max_depth {
            return Err(IpTreeError::InvalidPattern(format!(
                "Prefix length {prefix_len} exceeds maximum {max_depth}"
            )));
        }

        if prefix_len == 0 {
            self.backfill_less_specific(0, data_offset, prefix_len);
            return Ok(());
        }

        let mut node_id = 0u32; // Start at root

        for depth in 0..prefix_len {
            // Get bit at current depth
            let bit = ((bits >> (127 - depth)) & 1) as u8;

            // Check what the current node's child pointer is
            let child_ptr_value = {
                let current_node = &self.nodes[node_id as usize];
                if bit == 0 {
                    current_node.left
                } else {
                    current_node.right
                }
            };

            if depth + 1 == prefix_len {
                // Reached target depth - need to set this edge to data
                // BUT: Check if there's already a Node pointer here (more specific routes exist deeper)
                match child_ptr_value {
                    NodePointer::Empty => {
                        // Empty - set to our data
                        let current_node = &mut self.nodes[node_id as usize];
                        if bit == 0 {
                            current_node.left = NodePointer::Data(data_offset, prefix_len);
                        } else {
                            current_node.right = NodePointer::Data(data_offset, prefix_len);
                        }
                        return Ok(());
                    }
                    NodePointer::Data(_existing_offset, existing_prefix_len) => {
                        // Existing data - check if our prefix is more specific
                        if prefix_len >= existing_prefix_len {
                            // Our prefix is more specific (or equal) - replace it
                            let current_node = &mut self.nodes[node_id as usize];
                            if bit == 0 {
                                current_node.left = NodePointer::Data(data_offset, prefix_len);
                            } else {
                                current_node.right = NodePointer::Data(data_offset, prefix_len);
                            }
                        }
                        // Otherwise keep the existing (more specific) data
                        return Ok(());
                    }
                    NodePointer::Node(child_node_id) => {
                        // There's already a node here, meaning more specific prefixes exist deeper.
                        // We're inserting a less specific prefix (e.g., /24) after more specific ones (e.g., /32).
                        // We need to set all EMPTY children of this subtree to point to our data,
                        // while preserving any existing data pointers (the more specific routes).
                        self.backfill_less_specific(child_node_id, data_offset, prefix_len);
                        return Ok(());
                    }
                }
            }

            // Need to go deeper
            match child_ptr_value {
                NodePointer::Empty => {
                    // Allocate new node
                    let new_id = self.allocate_node()?;
                    // Update the parent's pointer
                    let current_node = &mut self.nodes[node_id as usize];
                    if bit == 0 {
                        current_node.left = NodePointer::Node(new_id);
                    } else {
                        current_node.right = NodePointer::Node(new_id);
                    }
                    node_id = new_id;
                }
                NodePointer::Node(child_id) => {
                    // Continue to existing node
                    node_id = child_id;
                }
                NodePointer::Data(existing_data_offset, existing_prefix_len) => {
                    // Hit existing data before reaching target depth.
                    // This means a less specific prefix already exists (e.g., /24)
                    // and we're trying to insert a more specific one (e.g., /32).
                    //
                    // We need to:
                    // 1. Convert this data leaf into a node
                    // 2. Make both children point to the existing data (to preserve less specific match)
                    // 3. Continue down the tree to insert the more specific prefix

                    let new_node_id = self.allocate_node()?;

                    // Make both children of the new node point to the existing data
                    // This preserves the less specific match for all IPs under this prefix
                    self.nodes[new_node_id as usize].left =
                        NodePointer::Data(existing_data_offset, existing_prefix_len);
                    self.nodes[new_node_id as usize].right =
                        NodePointer::Data(existing_data_offset, existing_prefix_len);

                    // Update parent to point to new node instead of data
                    let current_node = &mut self.nodes[node_id as usize];
                    if bit == 0 {
                        current_node.left = NodePointer::Node(new_node_id);
                    } else {
                        current_node.right = NodePointer::Node(new_node_id);
                    }

                    // Continue traversal from the new node
                    node_id = new_node_id;
                }
            }
        }

        Ok(())
    }

    /// Allocate a new node and return its ID
    fn allocate_node(&mut self) -> Result<u32, IpTreeError> {
        let id = u32::try_from(self.nodes.len())
            .map_err(|_| IpTreeError::Other("IP tree node count exceeds u32::MAX".into()))?;
        self.nodes.push(Node::new_empty());
        Ok(id)
    }

    /// Backfill a subtree with less-specific prefix data
    ///
    /// When inserting a less specific prefix (e.g., /24) after more specific ones (e.g., /32),
    /// we need to fill in gaps left by the more specific routes.
    ///
    /// With prefix length tracking, we can now properly distinguish:
    /// - Empty pointers (fill with new data)
    /// - Less-specific data (replace with new, more specific data)
    /// - More-specific data (leave alone)
    ///
    /// # Arguments
    /// * `node_id` - Root of the subtree to backfill
    /// * `data_offset` - Data offset for the less specific prefix
    /// * `prefix_len` - Prefix length of the data we're backfilling
    fn backfill_less_specific(&mut self, node_id: u32, data_offset: u32, prefix_len: u8) {
        let (left_ptr, right_ptr) = {
            let node = &self.nodes[node_id as usize];
            (node.left, node.right)
        };

        // Process left child
        match left_ptr {
            NodePointer::Empty => {
                // Empty - fill with new data
                let node = &mut self.nodes[node_id as usize];
                node.left = NodePointer::Data(data_offset, prefix_len);
            }
            NodePointer::Data(_, existing_prefix_len) => {
                // Replace less-specific data and earlier data for this prefix.
                if prefix_len >= existing_prefix_len {
                    let node = &mut self.nodes[node_id as usize];
                    node.left = NodePointer::Data(data_offset, prefix_len);
                }
                // Otherwise keep the existing data (it's more specific)
            }
            NodePointer::Node(child_id) => {
                // Recurse into subtree
                self.backfill_less_specific(child_id, data_offset, prefix_len);
            }
        }

        // Process right child
        match right_ptr {
            NodePointer::Empty => {
                // Empty - fill with new data
                let node = &mut self.nodes[node_id as usize];
                node.right = NodePointer::Data(data_offset, prefix_len);
            }
            NodePointer::Data(_, existing_prefix_len) => {
                // Replace less-specific data and earlier data for this prefix.
                if prefix_len >= existing_prefix_len {
                    let node = &mut self.nodes[node_id as usize];
                    node.right = NodePointer::Data(data_offset, prefix_len);
                }
                // Otherwise keep the existing data (it's more specific)
            }
            NodePointer::Node(child_id) => {
                // Recurse into subtree
                self.backfill_less_specific(child_id, data_offset, prefix_len);
            }
        }
    }

    /// Build the tree and return serialized bytes
    ///
    /// Returns: (tree_bytes, node_count)
    pub fn build(&self) -> Result<(Vec<u8>, u32), IpTreeError> {
        let (node_count, max_record_value) = self.record_bounds()?;
        self.ensure_width_fits(self.record_size, max_record_value)?;
        let tree_bytes = self.serialize(node_count, self.record_size)?;

        Ok((tree_bytes, node_count))
    }

    /// Build the tree, widening the configured record size when necessary.
    ///
    /// The width supplied to [`Self::new_v4`] or [`Self::new_v6`] remains the
    /// minimum. This means callers that deliberately selected 28- or 32-bit
    /// records keep that representation, while a 24-bit tree whose final node
    /// or data pointer exceeds 24 bits is safely promoted to 28 or 32 bits.
    ///
    /// Returns `(tree_bytes, node_count, selected_record_size)`.
    pub fn build_auto(&self) -> Result<(Vec<u8>, u32, RecordSize), IpTreeError> {
        let (node_count, max_record_value) = self.record_bounds()?;
        let record_size = self.record_size.widen_for(max_record_value);
        self.ensure_width_fits(record_size, max_record_value)?;
        let tree_bytes = self.serialize(node_count, record_size)?;

        Ok((tree_bytes, node_count, record_size))
    }

    /// Build a tree whose lookup value represents every matching prefix.
    ///
    /// `encode_match_set` is called at each prefix that adds a value. It
    /// receives the cumulative values in least-specific to most-specific
    /// order, preserving insertion order among values attached to the same
    /// prefix. Repeated values are omitted. The callback returns the
    /// data-section offset that represents that complete set; callers may
    /// intern equal sets there if desired.
    ///
    /// The resulting bytes use the same longest-prefix MMDB tree encoding as
    /// [`Self::build`]. A normal lookup therefore returns one offset, but that
    /// offset identifies a caller-encoded set containing all matches.
    pub fn build_all_matches<F>(&self, encode_match_set: F) -> Result<(Vec<u8>, u32), IpTreeError>
    where
        F: FnMut(&[u32]) -> Result<u32, IpTreeError>,
    {
        self.materialize_all_matches(encode_match_set)?.build()
    }

    /// Build an all-matches tree, widening the record size when necessary.
    ///
    /// This combines the cumulative-set behavior of
    /// [`Self::build_all_matches`] with the automatic-width behavior of
    /// [`Self::build_auto`].
    pub fn build_all_matches_auto<F>(
        &self,
        encode_match_set: F,
    ) -> Result<(Vec<u8>, u32, RecordSize), IpTreeError>
    where
        F: FnMut(&[u32]) -> Result<u32, IpTreeError>,
    {
        self.materialize_all_matches(encode_match_set)?.build_auto()
    }

    /// Rebuild the inserted prefixes as cumulative match sets.
    fn materialize_all_matches<F>(&self, mut encode_match_set: F) -> Result<Self, IpTreeError>
    where
        F: FnMut(&[u32]) -> Result<u32, IpTreeError>,
    {
        let mut complete_nodes = vec![CompleteNode::new()];
        for prefix_match in &self.prefix_matches {
            Self::insert_complete_node(&mut complete_nodes, *prefix_match)?;
        }

        let mut tree = match self.ip_version {
            IpVersion::V4 => Self::new_v4(self.record_size),
            IpVersion::V6 => Self::new_v6(self.record_size),
        };
        tree.reserve_nodes(self.nodes.len());

        let mut active_values = Vec::new();
        let mut active_value_set = HashSet::new();
        Self::materialize_complete_node(
            &complete_nodes,
            0,
            0,
            0,
            &mut active_values,
            &mut active_value_set,
            &mut encode_match_set,
            &mut tree,
        )?;
        Ok(tree)
    }

    fn insert_complete_node(
        nodes: &mut Vec<CompleteNode>,
        prefix_match: PrefixMatch,
    ) -> Result<(), IpTreeError> {
        let mut node_id = 0u32;

        for depth in 0..prefix_match.prefix_len {
            let bit = ((prefix_match.bits >> (127 - depth)) & 1) as usize;
            let child = nodes[node_id as usize].children[bit];
            node_id = match child {
                Some(child_id) => child_id,
                None => {
                    let child_id = u32::try_from(nodes.len()).map_err(|_| {
                        IpTreeError::ResourceLimitExceeded(
                            "Complete IP tree node count exceeds u32::MAX".into(),
                        )
                    })?;
                    nodes.push(CompleteNode::new());
                    nodes[node_id as usize].children[bit] = Some(child_id);
                    child_id
                }
            };
        }

        let values = &mut nodes[node_id as usize].values;
        if !values.contains(&prefix_match.value) {
            values.push(prefix_match.value);
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_complete_node<F>(
        nodes: &[CompleteNode],
        node_id: u32,
        depth: u8,
        prefix_bits: u128,
        active_values: &mut Vec<u32>,
        active_value_set: &mut HashSet<u32>,
        encode_match_set: &mut F,
        tree: &mut Self,
    ) -> Result<(), IpTreeError>
    where
        F: FnMut(&[u32]) -> Result<u32, IpTreeError>,
    {
        let node = &nodes[node_id as usize];
        let original_len = active_values.len();
        for value in &node.values {
            if active_value_set.insert(*value) {
                active_values.push(*value);
            }
        }

        if active_values.len() != original_len {
            let data_offset = encode_match_set(active_values)?;
            tree.insert_bits_u128(prefix_bits, depth, data_offset)?;
        }

        for (bit, child) in node.children.iter().enumerate() {
            if let Some(child_id) = child {
                let child_bits = prefix_bits | ((bit as u128) << (127 - depth));
                Self::materialize_complete_node(
                    nodes,
                    *child_id,
                    depth + 1,
                    child_bits,
                    active_values,
                    active_value_set,
                    encode_match_set,
                    tree,
                )?;
            }
        }

        while active_values.len() > original_len {
            if let Some(value) = active_values.pop() {
                active_value_set.remove(&value);
            }
        }
        Ok(())
    }

    /// Compute the maximum serialized record without allocating the output tree.
    fn record_bounds(&self) -> Result<(u32, u32), IpTreeError> {
        let node_count = u32::try_from(self.nodes.len()).map_err(|_| {
            IpTreeError::ResourceLimitExceeded("IP tree node count exceeds u32::MAX".into())
        })?;
        let mut max_record_value = node_count;

        for node in &self.nodes {
            let left = Self::pointer_to_value(node.left, node_count)?;
            let right = Self::pointer_to_value(node.right, node_count)?;
            max_record_value = max_record_value.max(left).max(right);
        }

        Ok((node_count, max_record_value))
    }

    /// Verify the complete tree fits before allocating or writing its buffer.
    fn ensure_width_fits(
        &self,
        record_size: RecordSize,
        max_record_value: u32,
    ) -> Result<(), IpTreeError> {
        let limit = record_size.max_record_value();
        if max_record_value > limit {
            return Err(IpTreeError::ResourceLimitExceeded(format!(
                "IP tree record value {max_record_value} exceeds the {}-bit limit {limit}",
                record_size as u8
            )));
        }

        Ok(())
    }

    /// Serialize with a width already proven to hold every record.
    fn serialize(&self, node_count: u32, record_size: RecordSize) -> Result<Vec<u8>, IpTreeError> {
        let node_size = record_size.node_bytes();
        let tree_size = self.nodes.len().checked_mul(node_size).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("IP tree byte size exceeds usize::MAX".into())
        })?;

        let mut tree_bytes = Vec::new();
        tree_bytes.try_reserve_exact(tree_size).map_err(|error| {
            IpTreeError::ResourceLimitExceeded(format!(
                "Unable to allocate {tree_size} bytes for IP tree: {error}"
            ))
        })?;
        tree_bytes.resize(tree_size, 0);

        // Write each node from the arena
        for (node_id, node) in self.nodes.iter().enumerate() {
            self.write_node(&mut tree_bytes, node_id, node, node_count, record_size)?;
        }

        Ok(tree_bytes)
    }

    /// Write a single node to the tree bytes
    fn write_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        node: &Node,
        node_count: u32,
        record_size: RecordSize,
    ) -> Result<(), IpTreeError> {
        let left_value = Self::pointer_to_value(node.left, node_count)?;
        let right_value = Self::pointer_to_value(node.right, node_count)?;

        match record_size {
            RecordSize::Bits24 => self.write_24bit_node(tree, node_id, left_value, right_value),
            RecordSize::Bits28 => self.write_28bit_node(tree, node_id, left_value, right_value),
            RecordSize::Bits32 => self.write_32bit_node(tree, node_id, left_value, right_value),
        }
    }

    /// Convert node pointer to numeric value
    /// Note: prefix_len is discarded here - it's only used during building
    fn pointer_to_value(pointer: NodePointer, node_count: u32) -> Result<u32, IpTreeError> {
        match pointer {
            NodePointer::Empty => Ok(node_count), // "not found" marker
            NodePointer::Node(id) => {
                if id >= node_count {
                    return Err(IpTreeError::Other(format!(
                        "Invalid node ID {id} >= node_count {node_count}"
                    )));
                }
                Ok(id)
            }
            NodePointer::Data(offset, _prefix_len) => {
                node_count
                    .checked_add(16)
                    .and_then(|base| base.checked_add(offset))
                    .ok_or_else(|| {
                        IpTreeError::ResourceLimitExceeded(format!(
                            "Data pointer node_count={node_count} + 16 + offset={offset} exceeds u32::MAX"
                        ))
                    })
            }
        }
    }

    /// Write 24-bit node (6 bytes per node)
    fn write_24bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        Self::ensure_records_fit(RecordSize::Bits24, left, right)?;
        let offset = node_id.checked_mul(6).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("24-bit node offset exceeds usize::MAX".into())
        })?;
        let end = offset.checked_add(6).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("24-bit node end exceeds usize::MAX".into())
        })?;
        if end > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {offset} exceeds tree size"
            )));
        }

        // Left record (3 bytes, big-endian)
        tree[offset] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 2] = (left & 0xFF) as u8;

        // Right record (3 bytes, big-endian)
        tree[offset + 3] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 4] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 5] = (right & 0xFF) as u8;

        Ok(())
    }

    /// Write 28-bit node (7 bytes per node)
    fn write_28bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        Self::ensure_records_fit(RecordSize::Bits28, left, right)?;
        let offset = node_id.checked_mul(7).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("28-bit node offset exceeds usize::MAX".into())
        })?;
        let end = offset.checked_add(7).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("28-bit node end exceeds usize::MAX".into())
        })?;
        if end > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {offset} exceeds tree size"
            )));
        }

        // Layout: [Left 24 bits][Middle 8 bits][Right 24 bits]
        // Middle byte: 4 high bits of left + 4 high bits of right

        // Left low 24 bits
        tree[offset] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 2] = (left & 0xFF) as u8;

        // Middle byte: left high 4 bits in upper nibble, right high 4 bits in lower nibble
        let left_high = ((left >> 24) & 0x0F) as u8;
        let right_high = ((right >> 24) & 0x0F) as u8;
        tree[offset + 3] = (left_high << 4) | right_high;

        // Right low 24 bits
        tree[offset + 4] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 5] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 6] = (right & 0xFF) as u8;

        Ok(())
    }

    /// Write 32-bit node (8 bytes per node)
    fn write_32bit_node(
        &self,
        tree: &mut [u8],
        node_id: usize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        let offset = node_id.checked_mul(8).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("32-bit node offset exceeds usize::MAX".into())
        })?;
        let end = offset.checked_add(8).ok_or_else(|| {
            IpTreeError::ResourceLimitExceeded("32-bit node end exceeds usize::MAX".into())
        })?;
        if end > tree.len() {
            return Err(IpTreeError::Other(format!(
                "Node offset {offset} exceeds tree size"
            )));
        }

        // Left record (4 bytes, big-endian)
        tree[offset] = ((left >> 24) & 0xFF) as u8;
        tree[offset + 1] = ((left >> 16) & 0xFF) as u8;
        tree[offset + 2] = ((left >> 8) & 0xFF) as u8;
        tree[offset + 3] = (left & 0xFF) as u8;

        // Right record (4 bytes, big-endian)
        tree[offset + 4] = ((right >> 24) & 0xFF) as u8;
        tree[offset + 5] = ((right >> 16) & 0xFF) as u8;
        tree[offset + 6] = ((right >> 8) & 0xFF) as u8;
        tree[offset + 7] = (right & 0xFF) as u8;

        Ok(())
    }

    /// Defensively reject values that a compact writer would otherwise truncate.
    fn ensure_records_fit(
        record_size: RecordSize,
        left: u32,
        right: u32,
    ) -> Result<(), IpTreeError> {
        let limit = record_size.max_record_value();
        let value = left.max(right);
        if value > limit {
            return Err(IpTreeError::ResourceLimitExceeded(format!(
                "IP tree record value {value} exceeds the {}-bit limit {limit}",
                record_size as u8
            )));
        }

        Ok(())
    }
}

impl Node {
    fn new_empty() -> Self {
        Self {
            left: NodePointer::Empty,
            right: NodePointer::Empty,
        }
    }
}

impl CompleteNode {
    fn new() -> Self {
        Self {
            children: [None, None],
            values: Vec::new(),
        }
    }
}

/// Convert IPv4 address to 32-bit integer
fn ipv4_to_bits(addr: std::net::Ipv4Addr) -> u32 {
    let octets = addr.octets();
    (u32::from(octets[0]) << 24)
        | (u32::from(octets[1]) << 16)
        | (u32::from(octets[2]) << 8)
        | u32::from(octets[3])
}

/// Convert IPv6 address to 128-bit integer (as two u64s)
fn ipv6_to_bits(addr: std::net::Ipv6Addr) -> (u64, u64) {
    let segments = addr.segments();
    let high = (u64::from(segments[0]) << 48)
        | (u64::from(segments[1]) << 32)
        | (u64::from(segments[2]) << 16)
        | u64::from(segments[3]);
    let low = (u64::from(segments[4]) << 48)
        | (u64::from(segments[5]) << 32)
        | (u64::from(segments[6]) << 16)
        | u64::from(segments[7]);
    (high, low)
}

/// Convert two u64s to u128
fn bits_to_u128(bits: (u64, u64)) -> u128 {
    (u128::from(bits.0) << 64) | u128::from(bits.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_24bit_record(tree: &[u8], node: u32, bit: u8) -> u32 {
        let offset = node as usize * 6 + usize::from(bit) * 3;
        u32::from_be_bytes([0, tree[offset], tree[offset + 1], tree[offset + 2]])
    }

    fn lookup_24bit(tree: &[u8], node_count: u32, bits: u128, depth: u8) -> Option<u32> {
        let mut node = 0;
        for bit_index in 0..depth {
            let bit = ((bits >> (127 - bit_index)) & 1) as u8;
            let record = read_24bit_record(tree, node, bit);
            if record == node_count {
                return None;
            }
            if record < node_count {
                node = record;
            } else {
                return Some(record - node_count - 16);
            }
        }
        None
    }

    #[test]
    fn test_ipv4_to_bits() {
        let addr = std::net::Ipv4Addr::new(192, 168, 1, 1);
        let bits = ipv4_to_bits(addr);
        assert_eq!(bits, 0xC0A80101);
    }

    #[test]
    fn test_new_v4_builder() {
        let builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        assert_eq!(builder.ip_version, IpVersion::V4);
        assert_eq!(builder.nodes.len(), 1); // Should have root node
    }

    #[test]
    fn test_build_empty_tree() {
        let builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let result = builder.build();
        assert!(result.is_ok());
        let (bytes, node_count) = result.unwrap();
        assert_eq!(node_count, 1); // Just root
        assert_eq!(bytes.len(), 6); // One node with 24-bit records
    }

    #[test]
    fn build_rejects_record_that_exceeds_configured_width() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        // One root node plus the 16-byte separator makes this record exactly
        // one greater than the largest 24-bit value.
        builder
            .insert(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                1,
                RecordSize::Bits24.max_record_value() - 16,
            )
            .unwrap();

        let error = builder.build().unwrap_err();
        assert!(matches!(error, IpTreeError::ResourceLimitExceeded(_)));
        assert!(error.to_string().contains("24-bit limit"));
    }

    #[test]
    fn build_auto_widens_24_bit_record_without_truncating_it() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                1,
                RecordSize::Bits24.max_record_value() - 16,
            )
            .unwrap();

        let (bytes, node_count, record_size) = builder.build_auto().unwrap();
        assert_eq!(node_count, 1);
        assert_eq!(record_size, RecordSize::Bits28);
        assert_eq!(bytes.len(), 7);

        let left = (u32::from(bytes[3] >> 4) << 24)
            | (u32::from(bytes[0]) << 16)
            | (u32::from(bytes[1]) << 8)
            | u32::from(bytes[2]);
        assert_eq!(left, RecordSize::Bits24.max_record_value() + 1);
    }

    #[test]
    fn build_auto_keeps_record_at_exact_24_bit_limit() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                1,
                RecordSize::Bits24.max_record_value() - 17,
            )
            .unwrap();

        let (bytes, node_count, record_size) = builder.build_auto().unwrap();
        assert_eq!(node_count, 1);
        assert_eq!(record_size, RecordSize::Bits24);
        assert_eq!(
            u32::from_be_bytes([0, bytes[0], bytes[1], bytes[2]]),
            RecordSize::Bits24.max_record_value()
        );
    }

    #[test]
    fn build_auto_widens_28_bit_record_to_32_bits() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits28);
        builder
            .insert(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                1,
                RecordSize::Bits28.max_record_value() - 16,
            )
            .unwrap();

        let (bytes, node_count, record_size) = builder.build_auto().unwrap();
        assert_eq!(node_count, 1);
        assert_eq!(record_size, RecordSize::Bits32);
        assert_eq!(bytes.len(), 8);
        assert_eq!(
            u32::from_be_bytes(bytes[..4].try_into().unwrap()),
            RecordSize::Bits28.max_record_value() + 1
        );
    }

    #[test]
    fn build_auto_preserves_an_explicitly_wider_minimum() {
        let builder = IpTreeBuilder::new_v4(RecordSize::Bits28);
        let (bytes, node_count, record_size) = builder.build_auto().unwrap();

        assert_eq!(node_count, 1);
        assert_eq!(record_size, RecordSize::Bits28);
        assert_eq!(bytes.len(), 7);
    }

    #[test]
    fn build_auto_preserves_small_tree_bytes() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 1, 100)
            .unwrap();

        let (expected_bytes, expected_node_count) = builder.build().unwrap();
        let (actual_bytes, actual_node_count, record_size) = builder.build_auto().unwrap();

        assert_eq!(record_size, RecordSize::Bits24);
        assert_eq!(expected_node_count, 1);
        // left = node_count + separator + data offset = 117; right = empty = 1
        assert_eq!(expected_bytes, [0, 0, 117, 0, 0, 1]);
        assert_eq!(actual_node_count, expected_node_count);
        assert_eq!(actual_bytes, expected_bytes);
    }

    #[test]
    fn data_pointer_overflow_is_an_error_instead_of_a_panic() {
        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits32);
        builder
            .insert(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 1, u32::MAX)
            .unwrap();

        assert!(matches!(
            builder.build_auto(),
            Err(IpTreeError::ResourceLimitExceeded(_))
        ));
    }

    #[test]
    fn test_insert_single_ipv4() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Insert with /32 prefix (exact host)
        let result = builder.insert(addr, 32, 100); // data offset 100
        assert!(result.is_ok());

        // Should have allocated more nodes
        assert!(builder.nodes.len() > 1);
    }

    #[test]
    fn test_insert_ipv4_cidr() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 0, 0));

        // Insert /16 network
        let result = builder.insert(addr, 16, 200);
        assert!(result.is_ok());

        // Build the tree
        let build_result = builder.build();
        assert!(build_result.is_ok());
        let (bytes, node_count) = build_result.unwrap();

        // Should have some nodes (at least root + 16 levels)
        assert!(node_count > 1);
        assert_eq!(bytes.len(), node_count as usize * 6); // 24-bit records = 6 bytes/node
    }

    #[test]
    fn default_ipv4_route_matches_every_address() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 42)
            .unwrap();
        let (tree, node_count) = builder.build().unwrap();

        for addr in [Ipv4Addr::UNSPECIFIED, Ipv4Addr::new(203, 0, 113, 7)] {
            let bits = u128::from(ipv4_to_bits(addr)) << 96;
            assert_eq!(lookup_24bit(&tree, node_count, bits, 32), Some(42));
        }
    }

    #[test]
    fn reinserting_prefix_replaces_it_without_hiding_more_specific_data() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 10)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 32, 30)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 20)
            .unwrap();
        let (tree, node_count) = builder.build().unwrap();

        let host_bits = u128::from(ipv4_to_bits(Ipv4Addr::new(192, 0, 2, 1))) << 96;
        let network_bits = u128::from(ipv4_to_bits(Ipv4Addr::new(192, 0, 2, 2))) << 96;
        assert_eq!(lookup_24bit(&tree, node_count, host_bits, 32), Some(30));
        assert_eq!(lookup_24bit(&tree, node_count, network_bits, 32), Some(20));
    }

    #[test]
    fn all_matches_build_encodes_cumulative_deduplicated_sets() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        // Insert most-specific first to verify construction order does not
        // control the cumulative prefix order.
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16, 3)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16, 3)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0)), 16, 4)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, 2)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0, 1)
            .unwrap();

        let mut encoded_sets = Vec::new();
        let (tree, node_count) = builder
            .build_all_matches(|values| {
                let offset = u32::try_from(encoded_sets.len()).unwrap();
                encoded_sets.push(values.to_vec());
                Ok(offset)
            })
            .unwrap();

        let lookup_set = |addr: Ipv4Addr| {
            let bits = u128::from(ipv4_to_bits(addr)) << 96;
            let offset = lookup_24bit(&tree, node_count, bits, 32).unwrap();
            encoded_sets[offset as usize].clone()
        };

        assert_eq!(lookup_set(Ipv4Addr::new(203, 0, 113, 7)), [1]);
        assert_eq!(lookup_set(Ipv4Addr::new(10, 2, 0, 1)), [1, 2]);
        assert_eq!(lookup_set(Ipv4Addr::new(10, 1, 2, 3)), [1, 2, 3, 4]);
    }

    #[test]
    fn all_matches_build_uses_existing_tree_encoding() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 7)
            .unwrap();

        let longest = builder.build().unwrap();
        let all_matches = builder
            .build_all_matches(|values| {
                assert_eq!(values.len(), 1);
                Ok(values[0])
            })
            .unwrap();

        assert_eq!(all_matches, longest);
    }

    #[test]
    fn all_matches_build_supports_ipv4_and_ipv6_in_one_tree() {
        use std::net::{Ipv4Addr, Ipv6Addr};

        let mut builder = IpTreeBuilder::new_v6(RecordSize::Bits24);
        builder
            .insert(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0, 1)
            .unwrap();
        builder
            .insert(IpAddr::V6("2001:db8::".parse().unwrap()), 32, 2)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 0)), 24, 3)
            .unwrap();

        let mut encoded_sets = Vec::new();
        let (tree, node_count) = builder
            .build_all_matches(|values| {
                let offset = u32::try_from(encoded_sets.len()).unwrap();
                encoded_sets.push(values.to_vec());
                Ok(offset)
            })
            .unwrap();

        let v6_bits = bits_to_u128(ipv6_to_bits("2001:db8::1".parse().unwrap()));
        let v4_bits = u128::from(ipv4_to_bits(Ipv4Addr::new(192, 0, 2, 7)));
        let v6_offset = lookup_24bit(&tree, node_count, v6_bits, 128).unwrap();
        let v4_offset = lookup_24bit(&tree, node_count, v4_bits, 128).unwrap();

        assert_eq!(encoded_sets[v6_offset as usize], [1, 2]);
        assert_eq!(encoded_sets[v4_offset as usize], [1, 3]);
    }

    #[test]
    fn test_insert_multiple_ipv4() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);

        // Insert multiple addresses
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)), 24, 100)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8, 200)
            .unwrap();
        builder
            .insert(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 0)), 12, 300)
            .unwrap();

        let (bytes, node_count) = builder.build().unwrap();

        // Should have built a non-trivial tree
        assert!(node_count > 3);
        assert_eq!(bytes.len(), node_count as usize * 6);
    }

    #[test]
    fn test_insert_ipv6() {
        use std::net::Ipv6Addr;

        let mut builder = IpTreeBuilder::new_v6(RecordSize::Bits24);
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));

        let result = builder.insert(addr, 64, 100);
        assert!(result.is_ok());

        let (bytes, node_count) = builder.build().unwrap();
        assert!(node_count > 1);
        assert_eq!(bytes.len(), node_count as usize * 6);
    }

    #[test]
    fn test_invalid_prefix_length() {
        use std::net::Ipv4Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));

        // Try to insert with prefix > 32 for IPv4
        let result = builder.insert(addr, 33, 100);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_ipv4_prefix_in_ipv6_tree_is_rejected() {
        let mut builder = IpTreeBuilder::new_v6(RecordSize::Bits24);
        let result = builder.insert(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), u8::MAX, 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_ipv6_in_ipv4_tree_fails() {
        use std::net::Ipv6Addr;

        let mut builder = IpTreeBuilder::new_v4(RecordSize::Bits24);
        let addr = IpAddr::V6(Ipv6Addr::LOCALHOST);

        // Should fail to insert IPv6 into IPv4-only tree
        let result = builder.insert(addr, 128, 100);
        assert!(result.is_err());
    }
}
