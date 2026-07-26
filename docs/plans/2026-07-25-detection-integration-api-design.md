# Matchy Detection Integration API Design

## Status

This document is a planning proposal, not a stable API specification.

It defines the integration boundary that should exist before the detection
compiler and runtime currently being disentangled in Zeek are moved into the
Matchy workspace. The immediate objective is to preserve the existing
Suricata and Zeek behavior while preventing Zeek's packet, connection, and
analyzer model from becoming Matchy's permanent public API.

Names and exact Rust layouts below are illustrative. The semantic boundaries
and performance requirements are the decisions this plan intends to preserve.

## Decision summary

Matchy's detection engine should expose a host-neutral, scope-oriented API:

```text
source frontend ─> logical rules ─> host binding ─> compiled detector
                                                        |
host events ─> adapter ─> detection session ─> candidates/effects
```

The core vocabulary is:

- a **scope** is an independently lived detection context;
- a **channel** is an ordered source of input within a scope;
- a **view** identifies the interpretation of bytes or a typed value;
- a **fact** is typed host-supplied evidence;
- an **event** groups work caused by one host transition;
- a **candidate** is an uncommitted rule result offered to the host; and
- a **commit** accepts a candidate and applies engine-owned state transitions.

Packet, stream, transaction, file, protocol, and direction concepts remain
available through an optional network profile. They are not the primitive
types of the core engine.

Configuration remains an ordered sequence of opaque key/value byte strings at
the frontend boundary. Frontends own key namespaces, value grammars,
duplicates, precedence, and diagnostics. Configuration is resolved while
building an engine and must not cause string or map lookups on the hot path.

The first extraction may retain compatibility types internally, but they
must be behind a Zeek/network adapter and must not be presented as the
long-term Matchy detection API.

## Goals

- Let Zeek integrate without losing any current signature behavior.
- Let another network engine, including Suricata, supply the same semantic
  inputs without emulating Zeek callbacks.
- Support complete files, byte objects, memory regions, and arbitrary
  incremental streams without pretending that they are network connections.
- Keep source-language frontends independent from runtime hosts and physical
  matcher implementations.
- Make input capabilities, lifecycle, identity, completion, and discontinuity
  explicit.
- Keep hot-path dispatch compact, predictable, and allocation-free where the
  current runtime permits it.
- Keep mutable runtime state bounded and attached to explicit lifetimes.
- Preserve a candidate/commit seam so host policy remains outside the
  mechanical matching engine.
- Make it possible to share one immutable compiled detector across many
  independently owned sessions.
- Provide an eventual C-compatible integration layer without designing the
  Rust API around C limitations.

## Non-goals

- A universal untyped event bus.
- Encoding arbitrary host objects in string-keyed maps.
- Requiring every host to implement network concepts.
- Freezing a serialized detection artifact or public ABI during extraction.
- Making frontend configuration part of the per-input runtime API.
- Moving Zeek policy, event emission, analyzer ownership, or connection-table
  behavior into Matchy.
- Replacing the current proven runtime with a speculative generalized engine
  in one step.

## Why the current seam is not the final seam

The extracted crates already contain several appropriately neutral layers:

- byte-oriented source buffers and ordered opaque configuration;
- a resolved logical IR;
- logical graph construction and cost-based planning;
- compiled literal families and compact matcher routing;
- verified program execution and occurrence storage;
- rule candidates, proofs, and explicit commit; and
- immutable build-time options separated from host configuration files and
  process environment variables.

Those are strong extraction boundaries. The current inspection and execution
types, however, still encode the Zeek/Suricata network integration directly:

- `Packet`, `Stream`, `Transaction`, and `File` are fixed domains;
- `Originator` and `Responder` are universal directions;
- application protocols and buffers are closed enums;
- packet generations and packet delivery modes are core identities;
- occurrence families are transaction- and file-specific;
- lifecycle facts such as `established`, `datagram`, and `bare_mode` travel
  beside every inspection request;
- commit requests contain network time, addresses, and ports; and
- names such as `packet_gate` describe one current optimization rather than
  the general admission relationship.

These types are useful as a compatibility profile. Moving them unchanged and
calling them host-neutral would only transfer the coupling from Zeek's
repository into Matchy's repository.

### Current seam inventory

The following inventory is the working ownership decision for the types and
fields already extracted in the Zeek tree:

| Current API element | Long-term owner or replacement |
| --- | --- |
| `Source`, `Span`, ordered `ConfigEntry` | shared frontend-facing types |
| compiler optimization policy | Matchy build-time policy |
| planner dump directory and file writing | host adapter; Matchy returns diagnostics |
| `EventId`, event sequencing | generic session |
| `EventDirection` | network profile; core uses channel/scope identity |
| `PacketGeneration`, `PacketKey`, `PacketDelivery` | network profile mapped to host cause and delivery operations |
| packet-or-event occurrence key | generic event/cause proof identity |
| `InspectionLane` | private compiled dispatch, with generic lane names |
| legacy inspection provenance | network compatibility profile or private adapter state |
| fixed `InspectionDomain` | schema-defined scope kind and delivery capability |
| closed `InspectionBuffer` | schema-defined channel/view; network constants live in the profile |
| `DomainSelector`, `EpochPolicy`, `InspectionTarget` | bound target and channel-epoch policy |
| begin/end match boundaries | channel lifecycle and delivery contract |
| `InspectionKind` and `InspectionRequest` | compatibility adapter translated into lifecycle operations |
| `clear` | begin a new channel epoch |
| `datagram` | network delivery capability or typed fact |
| `bare_mode` | Zeek compatibility policy, bound before matcher execution |
| `established` | network-profile fact |
| transaction number and file instance | scope identity and parentage |
| application protocol activation | typed network-profile fact/event |
| `RuleHandle`, source identity, proof | generic compiled/session identity |
| candidate action and message | frontend metadata plus generic effect intent |
| candidate direction | profile metadata derived from scope/channel |
| candidate match position and captures | generic runtime result |
| borrowed/current versus retained candidate bytes | generic call-borrowed or owned match data |
| buffer-interest bitsets | bound channel-interest set exposed through the profile |
| packet-buffer-interest bitset | network-profile specialization of channel interest |
| payload size | channel/scope observation, not a universal result field |
| commit direction, network time, addresses, and ports | typed profile facts supplied only when compiled effects require them |
| commit accepted/alert result and follow-on candidates | generic commit/effect result |

This table is a movement boundary, not an instruction to delete compatibility
types immediately. Compatibility conversions remain until the generic session
passes the existing Zeek test corpus.

## Architectural layers

### 1. Detection-language frontend

A frontend owns source-language behavior:

- parsing, recovery, and source locations;
- namespaces, includes, and source identity;
- language-specific configuration;
- variable grammar and precedence;
- compatibility analysis;
- exact operator and action semantics; and
- lowering into frontend-neutral logical rules.

For Suricata, the generic configuration input can contain entries such as:

```text
vars.address-groups.HOME_NET = [10.0.0.0/8,192.168.0.0/16]
vars.port-groups.HTTP_PORTS = [80,8080]
```

Arbitrary valid variable names are supported because the Suricata frontend
interprets the namespace. Another frontend can interpret completely different
keys. The common API preserves ordered duplicates and opaque bytes; it does
not impose an environment-variable grammar or silently read the process
environment.

Frontend output contains logical rules, source reports, and diagnostics. It
does not contain a runtime session or host callback behavior.

### 2. Host schema and binding

A host describes the semantic inputs it can provide. The binding stage
resolves symbolic frontend requirements into compact engine identifiers and
rejects unsupported combinations before traffic or objects are inspected.

Illustrative build-time types:

```rust
pub struct DetectionSchema {
    pub scope_kinds: Vec<ScopeKindDefinition>,
    pub channels: Vec<ChannelDefinition>,
    pub views: Vec<ViewDefinition>,
    pub facts: Vec<FactDefinition>,
    pub capabilities: CapabilitySet,
}

pub struct BoundChannel {
    pub scope_kind: ScopeKindId,
    pub channel: ChannelId,
    pub view: ViewId,
    pub delivery: DeliveryCapabilities,
}
```

The schema may use owned strings and maps because it is build-time data.
Successful binding produces compact IDs and precomputed dispatch tables.

Binding is the correct place to answer questions such as:

- Does this host supply a complete value or incremental chunks?
- Is authoritative completion available?
- Are input positions monotonic and contiguous?
- Can the engine retain bounded history?
- Is random access available for complete objects?
- Which transforms or typed facts can the host provide?
- Which scope owns the state and alert lifetime?

Unsupported requirements fail closed with source-aware diagnostics.

### 3. Compiled detector

`CompiledDetector` is immutable and shareable. It owns:

- verified logical and physical plans;
- compiled matcher families;
- compact routing tables;
- bound IDs and capability decisions;
- source identity and reporting metadata;
- resource limits; and
- enough deterministic diagnostics to explain the build.

It contains no connection, object, transaction, or candidate state.

Conceptually:

```rust
pub struct CompiledDetector { /* immutable */ }

impl CompiledDetector {
    pub fn new_session(&self, limits: SessionLimits) -> DetectionSession<'_>;
}
```

The implementation may instead use an `Arc`-owned detector or explicit
partition objects. The invariant is that compiled matcher data can be shared
without locks while mutable inspection state has a clear owner.

### 4. Detection session

A `DetectionSession` owns mutable state for a host-selected partition of work.
It need not mean "one network connection." A session could represent:

- one Zeek connection and its descendants;
- one file scanner worker;
- one document with nested decoded objects;
- one ordered log source;
- one process or memory-inspection job; or
- a host-defined shard containing multiple scopes.

The default concurrency contract should be single-owner mutable state:

- a compiled detector may be shared across threads;
- one session is driven serially unless a future API explicitly partitions
  it; and
- there is no global mutable detection state hidden behind the API.

This keeps synchronization out of the per-byte path and lets hosts choose
their own scheduling model.

## Core runtime model

### Scope

A scope is an independently lived detection context with an opaque host key,
a compact kind, and optional parentage.

```rust
pub struct ScopeKey(u64);
pub struct ScopeKindId(u16);

pub struct OpenScope {
    pub key: ScopeKey,
    pub kind: ScopeKindId,
    pub parent: Option<ScopeKey>,
}
```

Examples:

| Host concept | Scope kind | Possible parent |
| --- | --- | --- |
| network flow | `network.flow` | none |
| HTTP exchange | `network.http.transaction` | flow |
| transferred file | `object.file` | transaction or flow |
| decoded attachment | `object.decoded` | file |
| standalone file | `object.file` | none |
| memory region | `memory.region` | process or scan job |
| generic stream | `stream.ordered` | none |

Parentage lets rules and profiles describe relationships without forcing all
objects into a connection/transaction hierarchy. Cross-scope joins should be
introduced only when their state and completion semantics are explicit.

`ScopeKey` is opaque to Matchy except for equality. If hosts require wider or
generational identities, the final representation may be a pair of integers
or a session-local dense handle returned by `open_scope`.

### Channel

A channel is an ordered producer within one scope. It identifies where data
arrives, not what every possible host in the world calls that data.

```rust
pub struct ChannelId(u16);
pub struct ViewId(u16);
```

Examples include:

- raw file bytes;
- an HTTP request URI;
- a response body;
- a decoded attachment;
- one direction of reassembled transport bytes;
- a complete metadata string; and
- bytes emitted by a non-network streaming source.

Direction is therefore normally represented by channel selection or typed
facts in a profile, not by a mandatory `Originator`/`Responder` field on every
core event.

### View

A view identifies the semantic interpretation or coordinate space of data.
Separating it from the producer channel allows one source to have raw,
normalized, decoded, or derived interpretations while preserving occurrence
identity.

Examples:

- raw bytes;
- normalized bytes;
- URL-decoded URI;
- lowercase-header-name representation;
- Base64-decoded content; and
- a complete scalar text field.

The initial implementation may bind a channel directly to one view and use a
single compact target ID in the hot path. Keeping the concepts separate at the
schema level avoids confusing producer lifetime with transformation.

Matchy should own compiler-known transforms when their semantics and resource
contracts are part of the verified plan. A host-supplied view is appropriate
when the host is the authoritative producer of that semantic value.

### Facts

Facts are typed evidence that is not naturally represented as an ordered byte
feed:

```rust
pub struct FactId(u16);

pub enum FactValue<'a> {
    Bool(bool),
    U64(u64),
    I64(i64),
    Bytes(&'a [u8]),
    Address(AddressValue),
}
```

Examples include protocol classification, endpoint addresses, ports,
establishment state, timestamps, object metadata, or parser results.

The hot path uses a compact `FactId` and a verified expected type. Dynamic
string maps are limited to build-time schema construction and frontend
configuration.

### Event and cause

An event groups outputs caused by one host transition. It provides stable
deduplication and proof identity without requiring that the cause be a packet.

```rust
pub struct EventId(u64);

pub enum Cause {
    None,
    Host(HostCauseId),
}
```

A network profile may map a captured packet generation into `HostCauseId`.
A file scanner may map a read operation or object observation into it. The
core engine does not interpret the cause, but it preserves it where candidate
identity and deduplication require it.

## Input operations and lifecycle

The runtime should expose explicit lifecycle operations:

```rust
session.open_scope(OpenScope { ... })?;
session.feed(scope, channel, position, bytes, event)?;
session.publish_fact(scope, fact, value, event)?;
session.finish_channel(scope, channel, event)?;
session.finish_scope(scope, event)?;
session.abort_scope(scope, reason)?;
```

This sketch is intentionally more explicit than one large request struct.
Implementations may batch operations to reduce call overhead.

### Feeding bytes

`feed` accepts borrowed bytes. The runtime may retain only the bounded windows
or captures required by its verified plan.

The channel contract declares whether:

- positions are monotonic;
- chunks are contiguous;
- empty chunks are meaningful;
- a complete value is delivered in one call;
- the host can replay or provide random access; and
- finish is authoritative.

The input operation must represent a discontinuity explicitly. A gap must
never be inferred as adjacent bytes:

```rust
session.discontinue(scope, channel, new_position, event)?;
```

Depending on the bound plan, discontinuity either resets affected streaming
state, preserves only legal absolute state, or fails the scope closed.

### Complete values and objects

Complete values should not have to masquerade as one-chunk streams. A
convenience operation can express authoritative begin and end in one call:

```rust
session.inspect_value(scope, channel, bytes, event)?;
```

A complete-object profile may additionally provide random access and length
up front, allowing the planner to select different physical operators from an
incremental stream profile.

Files are ordinary object scopes with file-oriented schema definitions. They
may be standalone or children of network transactions. The core API does not
require a transaction number, file instance number, or network direction.

### Finishing and aborting

Completion is semantic evidence. It settles end-anchored, absence, negation,
length, and transform predicates. Therefore:

- finishing a channel is distinct from finishing its scope;
- finishing is explicit and authoritative;
- abort is distinct from successful completion;
- repeated finish/abort operations produce deterministic errors or documented
  idempotence; and
- dropping a session must not accidentally turn incomplete input into
  successful completion.

The plan should define which unfinished child scopes are aborted when a parent
finishes or aborts. The initial recommendation is explicit child completion,
with parent teardown failing remaining children closed.

### Reset and epochs

Some producers reuse a logical channel for multiple values. The generic
operation is a new channel epoch, not a boolean `clear` flag:

```rust
session.begin_epoch(scope, channel, event)?;
```

An epoch has explicit acceptance-retention policy chosen during binding:

- scoped evidence expires at the new epoch;
- profile-defined compatibility evidence may remain at its enclosing scope;
- packet-like atomic channels naturally use one epoch per delivered value.

Zeek's legacy accepted-match behavior belongs in the Zeek compatibility
profile rather than in the universal default.

## Candidate, commit, and effects

The runtime performs mechanical matching and offers candidates. The host owns
policy such as whether a candidate is enabled, rate-limited externally,
logged, converted into an event, or used to alter analyzer behavior.

An engine candidate should contain:

- compact compiled rule handle;
- unforgeable or session-validated proof;
- stable source-language identity;
- source-defined action or generic effect intent;
- scope and event identity;
- match position and relevant captures; and
- owned or explicitly call-borrowed match data.

It should not require network addresses, ports, or network time.

Illustrative shape:

```rust
pub struct Candidate<'input> {
    pub rule: RuleHandle,
    pub proof: CandidateProof,
    pub source: SourceIdentity,
    pub scope: ScopeKey,
    pub event: EventId,
    pub action: ActionId,
    pub matched: MatchData<'input>,
    pub captures: &'input [Capture],
}

pub struct CommitContext<'a> {
    pub candidate: CandidateProof,
    pub facts: &'a dyn CommitFacts,
}
```

Commit-time inputs should be required by compiled effect semantics, not
hard-coded network fields. Prefer prebound typed fact slots or an engine query
for missing commit facts over a general callback on each instruction.

Commit returns explicit engine effects and any follow-on candidates. A host
adapter translates effects into Zeek events, Suricata alerts, file quarantine
requests, counters, or other policy actions.

The candidate proof must prevent:

- committing a candidate from another session;
- committing a stale or already consumed candidate;
- changing the rule or scope named by a candidate; and
- retaining a borrowed candidate past the input call without explicit
  ownership conversion.

## Network compatibility profile

The network profile gives Zeek and similar engines ergonomic, typed mappings
without contaminating the core:

```text
Network profile concept          Core mapping
------------------------------   -----------------------------------
connection                       scope
HTTP transaction                 child scope
file                             child object scope
originator/responder             profile channel/fact convention
packet payload                   atomic channel epoch
reassembled stream               incremental channel
application buffer               typed channel/view
application protocol             typed fact
packet generation                host cause identity
established/datagram             typed facts or bound capabilities
transaction/file occurrence      scope identity
buffer clear                     new channel epoch
end of stream                    finish channel
```

The existing `Packet`, `Stream`, `Transaction`, `File`,
`Originator`/`Responder`, application-buffer, occurrence-family, and packet
delivery types may initially implement this profile.

Legacy Zeek distinctions such as natural packet delivery, exact-only packet
sideband, legacy transport fallback, and accepted-match retention are adapter
or profile policies. They should compile into generic lanes, epochs, and
dispatch eligibility before the matcher hot path.

A Suricata host adapter can use the same profile while supplying Suricata's
own transaction identities, buffer production, direction conventions, and
effect handling.

## Object and generic streaming profiles

The design should be validated with two small non-Zeek integrations before
the public API is stabilized.

### Complete-object scanner

A toy file/object scanner should:

- open an object scope without a network parent;
- provide a complete raw-byte channel;
- publish optional type and metadata facts;
- finish the object authoritatively;
- receive candidates; and
- commit them without addresses, ports, directions, or network time.

### Arbitrary incremental source

A toy stream scanner should:

- open a generic ordered-stream scope;
- feed multiple borrowed chunks with positions;
- express a discontinuity;
- finish the channel independently from the session;
- exercise bounded retained history and end-sensitive predicates; and
- receive candidates without network terminology.

If either integration requires fake connections, fake transaction IDs, or a
special `Originator` direction, the core boundary is still too network-shaped.

## Performance contract

Abstraction at the API boundary must compile away or remain outside the
per-byte loop. The design therefore requires:

- compact IDs such as `ScopeKindId`, `ChannelId`, `ViewId`, and `FactId`;
- build-time name resolution and capability negotiation;
- precomputed target-to-matcher and matcher-to-rule dispatch;
- borrowed input buffers by default;
- no per-feed string construction, hashing, or schema lookup;
- no dynamic map traversal per matched byte;
- no virtual dispatch per byte or per automaton transition;
- dense session-local handles when host keys are wider or expensive;
- bounded retention selected by the planner;
- allocation-free steady-state scanning where candidate/capture production
  does not itself require allocation;
- immutable shared compiled state and single-owner mutable sessions; and
- benchmarks at both the raw matcher layer and the host-adapter boundary.

An ergonomic builder may use strings, maps, trait objects, and owned values.
The builder must lower those into compact verified data before returning a
compiled detector.

Generality must not mean turning typed hot state into `HashMap<String,
Value>`. The schema is dynamic at build time and static within a compiled
detector.

## Error and resource semantics

Errors are divided by phase:

### Build errors

- frontend syntax or compatibility diagnostics;
- unknown configuration keys according to frontend policy;
- unresolved variables;
- host schema mismatch;
- missing completion or delivery capabilities;
- illegal scope relationships;
- unsupported effect requirements; and
- plans that cannot satisfy configured resource bounds.

### Runtime input errors

- unknown or duplicate scope;
- use after finish or abort;
- unknown channel or fact for a scope kind;
- fact type mismatch;
- out-of-order or overlapping feed;
- unannounced discontinuity;
- invalid parentage; and
- invalid lifecycle transition.

### Resource exhaustion

Runtime state remains bounded. Exhaustion fails only the independently owned
match state that can no longer be evaluated correctly, records observable
diagnostics, and never converts uncertainty into a match.

### Host callback failure

The core API should prefer returning candidate and effect values over invoking
host callbacks. Where callbacks are unavoidable, failure behavior and
reentrancy must be explicit. No host callback should run from inside a matcher
transition.

## Naming guidance

Names in Matchy should describe general detection mechanics:

| Current compatibility name | Preferred core concept |
| --- | --- |
| connection engine | detection session |
| packet gate | input gate or admission gate |
| packet generation | host cause ID |
| inspection domain | scope kind or delivery capability |
| inspection buffer | channel/view |
| clear | begin epoch |
| transaction/file instance | scope key |
| originator/responder | network-profile direction |
| application protocol | typed profile fact |

The compatibility layer may keep established Zeek terms when that makes the
adapter easier to understand. The important restriction is that those names
do not determine the core type system.

## Crate boundary

The intended workspace shape is:

```text
matchy-detection-types     small shared IDs, source/config, schema contracts
matchy-detection-ir        frontend-neutral logical rules
matchy-detection-regex     regular-language analysis and backend contracts
matchy-detection-pcre      PCRE translation frontend/helper
matchy-detection-engine    legalization, planning, compiled detector, sessions,
                           matcher/VM execution
matchy-suricata            Suricata syntax, variables, compatibility, lowering
matchy-detection-network   optional network schema/profile and conveniences
```

The exact number of crates should remain pragmatic. In particular:

- shared types must not become a dumping ground for network compatibility;
- `matchy-suricata` stops at logical lowering and diagnostics;
- the engine does not depend on `matchy-suricata`;
- frontends depend on the IR, not the engine's private planner or physical
  operators;
- legalization, planning, and execution remain distinct engine modules, but
  their lockstep private contracts do not become independently versioned
  crates;
- Zeek-specific CXX wire types remain in Zeek; and
- the top-level `matchy` crate need not expose every detection crate
  immediately.

`matchy-detection-network` may begin as a module or private compatibility
crate until another host validates its boundary.

## Zeek ownership after extraction

Zeek should retain:

- conversion from Zeek configuration into frontend config entries and engine
  build options;
- conversion from packets, stream delivery, analyzer callbacks, application
  fields, files, and role flips into profile operations;
- ownership of Zeek connection/analyzer objects;
- source loading policy and Zeek script configuration;
- host enable/disable and dynamic policy checks;
- translation of candidates/effects into Zeek events and actions;
- Zeek logging, reporter integration, and statistics presentation; and
- CXX/FFI lifetime and error containment.

Matchy should own:

- Suricata parsing, variables, compatibility analysis, and lowering;
- common logical IR and validation;
- planner and verified physical plan construction;
- matcher construction and routing;
- occurrence, cursor, capture, transform, and VM state;
- generic scope/channel lifecycle enforcement;
- candidate proof and engine-owned commit transitions;
- deterministic compiler/planner diagnostics; and
- engine resource accounting.

Anything in Zeek that decides how a literal hit advances a rule, how
occurrence state is retained, or how a physical matcher output routes to
logical owners is presumptively mechanical detection code and should move.

Anything that asks a Zeek object for data or turns an accepted result into a
Zeek event is presumptively adapter code and should remain.

## Migration plan

### Phase 0: Freeze behavior and inventory the seam

- Keep the existing Zeek corpus, differential tests, planner snapshots, and
  benchmarks as the behavioral oracle.
- Inventory every field crossing the current request/result boundary.
- Classify each field as core identity, network-profile data, Zeek adapter
  policy, frontend configuration, or temporary compatibility state.
- Do not publish the current inspection types from Matchy as stable APIs.

Exit condition: every crossing field has an owner and there are no unexplained
Zeek object dependencies in extracted crates.

### Phase 1: Establish generic vocabulary beside compatibility types

- Add compact scope, channel/view, fact, event, and host-cause IDs.
- Add build-time schema definitions and binding diagnostics.
- Rename internal `packet_gate` concepts to `input_gate` or `admission_gate`
  where the semantics are genuinely generic.
- Keep lossless conversion from existing network types.

Exit condition: current tests can describe their targets through a bound
schema even if the compatibility adapter still constructs old requests.

### Phase 2: Introduce lifecycle operations

- Add open/feed/value/fact/epoch/finish/abort operations.
- Implement the network compatibility profile as a translation into those
  operations.
- Move occurrence identity from transaction/file number fields to scope
  identity.
- Make completion and discontinuity explicit.

Exit condition: the Matchy runtime can be driven without constructing a
Zeek-shaped `InspectionRequest`.

### Phase 3: Move compiled engine and session ownership

- Wrap the extracted matcher families, routing, occurrence store, and program
  machine in `CompiledDetector` and `DetectionSession`.
- Move event sequencing and candidate proof ownership into the session.
- Keep compiled data shareable and mutable state session-local.
- Preserve current direct paths and avoid adding dynamic dispatch inside
  matcher loops.

Exit condition: Zeek owns only an adapter around a Matchy session for
mechanical execution.

### Phase 4: Generalize candidate commit and effects

- Remove hard-coded addresses, ports, network time, and direction from core
  commit requests.
- Bind effect requirements to typed facts.
- Return generic engine effects for host translation.
- Preserve source actions and threshold/state semantics through profile or
  frontend-owned effect definitions.

Exit condition: a non-network host can commit a candidate without supplying
dummy network data.

### Phase 5: Validate with non-Zeek hosts

- Add a complete-object example and tests.
- Add an arbitrary incremental-stream example and tests.
- Add a small network-profile harness independent of Zeek.
- Compare throughput and allocation profiles with the pre-generalization
  Zeek path.

Exit condition: none of the examples emulates an unrelated host lifecycle,
and network integration has no material performance regression.

### Phase 6: Move standalone crates into Matchy

- Move crates only after their dependencies and public seams match the target
  workspace boundaries.
- Preserve history where practical.
- Add workspace linting, documentation, and targeted tests.
- Keep a temporary Zeek compatibility facade to make the repository move
  mechanical.
- Remove the facade only after the Zeek adapter uses the Matchy APIs directly.

Exit condition: Zeek contains no duplicate planner/runtime implementation and
all behavioral and performance gates pass against Matchy-owned crates.

## Verification and acceptance criteria

The API is ready to stabilize only when:

- all detection crates build and test without Zeek headers or Zeek Rust/CXX
  types;
- the Suricata frontend compiles sources using only generic source and config
  inputs;
- the runtime can inspect a standalone complete file;
- the runtime can inspect an incremental non-network stream with a
  discontinuity;
- the network profile reproduces current Zeek packet, stream, transaction,
  and file behavior;
- completion-sensitive and negative rules fail closed on abort;
- stale, cross-session, and duplicate candidate commits are rejected;
- session memory remains bounded under hostile input;
- steady-state input does not perform string-based schema lookup;
- compiled detector state can be shared safely across independent sessions;
- benchmarked matcher throughput and adapter overhead show no material
  regression; and
- Zeek integration code is limited to configuration, event/fact adaptation,
  policy, effects, and FFI containment.

## Open questions to answer with prototypes

1. Should a host provide `ScopeKey` directly, or should `open_scope` return a
   dense session-local handle associated with an opaque host key?
2. Is `ChannelId` sufficient as the bound target, with `ViewId` retained only
   in build-time schema metadata, or do runtime operations need both?
3. Which facts must be snapshots attached to an event, and which may be
   persistent properties of a scope?
4. How are cross-scope predicates expressed and bounded without introducing
   implicit global joins?
5. Which engine effects are sufficiently universal to standardize, and which
   remain frontend/profile-specific opaque intents?
6. Does candidate commit need a trait-based fact provider, a compact fact
   frame, or fully precomputed effect operands?
7. Which lifecycle operations need batch forms for FFI call amortization?
8. What is the smallest network profile that can represent both Zeek and a
   native Suricata integration without host-specific delivery modes leaking
   into core types?
9. Which current compatibility behaviors should remain configurable profiles
   and which should be retired after extraction?
10. What benchmark threshold constitutes a material adapter regression for
    packet, stream, application-buffer, and complete-object workloads?

## Immediate next steps

Before moving more runtime code out of Zeek:

1. review the current seam inventory with the user and confirm the proposed
   core, network-profile, Zeek-adapter, and compatibility ownership;
2. define the minimal scope/channel/fact ID types and schema binding contract;
3. prototype lossless conversion from the current Zeek inspection request
   into generic lifecycle operations;
4. prototype a standalone complete-object driver using the same runtime
   concepts;
5. measure the conversion layer to confirm it stays outside matcher loops; and
6. use those results to decide the first stable public surface.

This ordering keeps the existing tests useful, makes the repository move
largely mechanical, and gives the API two distinct hosts to resist accidental
Zeek shaping before it is committed as Matchy's long-term detection boundary.
