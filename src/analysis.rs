use crate::capture::CaptureInput;
use crate::json::{self, Value};
use crate::model::*;
use crate::network::*;
use crate::store::ContentStore;
use crate::util::{hex_lower, sha256};
use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;

#[derive(Debug, Clone, Copy)]
struct FragmentSlot {
    event_index: usize,
    timestamp_ns: i64,
    original_index: usize,
    offset: usize,
    length: usize,
    more_fragments: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct FragmentKey {
    source: String,
    destination: String,
    protocol: u8,
    identification: u32,
}

#[derive(Debug, Clone)]
struct FragmentGroup {
    key: FragmentKey,
    slots: Vec<FragmentSlot>,
    payload: Vec<u8>,
    complete: bool,
    quarantine: Option<String>,
    completed_event: Option<(usize, i64, usize)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectionId {
    Zero,
    One,
}

#[derive(Debug, Clone)]
struct ByteSlot {
    byte: u8,
    writer_event: usize,
    writer_original_index: usize,
}

#[derive(Debug, Clone)]
struct DirectionState {
    endpoint: Option<Endpoint>,
    peer: Option<Endpoint>,
    isn: Option<u32>,
    base_seq: Option<u32>,
    syn_seen: bool,
    syn_ack_seen: bool,
    syn_acknowledged: bool,
    fin_seq: Option<u32>,
    fin_acknowledged: bool,
    ack_end: u64,
    rst_seen: bool,
    bytes: BTreeMap<u64, ByteSlot>,
    contiguous_end: u64,
    max_seen_end: u64,
}

impl DirectionState {
    fn new() -> Self {
        Self {
            endpoint: None,
            peer: None,
            isn: None,
            base_seq: None,
            syn_seen: false,
            syn_ack_seen: false,
            syn_acknowledged: false,
            fin_seq: None,
            fin_acknowledged: false,
            ack_end: 0,
            bytes: BTreeMap::new(),
            contiguous_end: 0,
            max_seen_end: 0,
            rst_seen: false,
        }
    }
}

#[derive(Debug, Clone)]
struct SegmentEvent {
    event_index: usize,
    timestamp_ns: i64,
    original_index: usize,
    datagram_id: usize,
    frame_index: usize,
    direction: DirectionId,
    source: Endpoint,
    destination: Endpoint,
    sequence: u32,
    acknowledgment: u32,
    flags: u8,
    payload_hash: String,
    payload_length: usize,
    relative_begin: u64,
    relative_end: u64,
    roles: Vec<String>,
    conflicts: Vec<Value>,
    added: Vec<(u64, u64)>,
    after_close: bool,
}

#[derive(Debug, Clone)]
struct Session {
    id: usize,
    generation: usize,
    key: FlowKey,
    directions: [DirectionState; 2],
    segments: Vec<SegmentEvent>,
    state: String,
    partial: bool,
    opened_event: Option<usize>,
    closed_event: Option<usize>,
    reset_event: Option<usize>,
    timeout_generation: bool,
    fin_rst_race: bool,
    last_event: usize,
    last_timestamp: i64,
}

impl Session {
    fn new(id: usize, generation: usize, key: FlowKey) -> Self {
        Self {
            id,
            generation,
            key,
            directions: std::array::from_fn(|_| DirectionState::new()),
            segments: Vec::new(),
            state: "open".into(),
            partial: false,
            opened_event: None,
            closed_event: None,
            reset_event: None,
            timeout_generation: false,
            fin_rst_race: false,
            last_event: 0,
            last_timestamp: 0,
        }
    }

    fn direction_for(&mut self, source: &Endpoint, destination: &Endpoint) -> (DirectionId, bool) {
        if self.directions[0].endpoint.as_ref() == Some(source)
            && self.directions[0].peer.as_ref() == Some(destination)
        {
            (DirectionId::Zero, false)
        } else if self.directions[1].endpoint.as_ref() == Some(source)
            && self.directions[1].peer.as_ref() == Some(destination)
        {
            (DirectionId::One, false)
        } else if self.directions[0].endpoint.is_none()
            && self.directions[1].endpoint.as_ref() == Some(destination)
        {
            self.directions[0].endpoint = Some(source.clone());
            self.directions[0].peer = Some(destination.clone());
            (DirectionId::Zero, true)
        } else if self.directions[1].endpoint.is_none()
            && self.directions[0].endpoint.as_ref() == Some(destination)
        {
            self.directions[1].endpoint = Some(source.clone());
            self.directions[1].peer = Some(destination.clone());
            (DirectionId::One, true)
        } else if self.directions[0].endpoint.is_none() && self.directions[1].endpoint.is_none() {
            self.directions[0].endpoint = Some(source.clone());
            self.directions[0].peer = Some(destination.clone());
            self.directions[1].endpoint = Some(destination.clone());
            self.directions[1].peer = Some(source.clone());
            (DirectionId::Zero, true)
        } else {
            (DirectionId::Zero, false)
        }
    }
}

pub fn analyze_capture(
    capture: &CaptureInput,
    config: AnalysisConfig,
    store: &dyn ContentStore,
) -> Value {
    let mut ordered_frames: Vec<(i64, usize, usize)> = capture
        .frames
        .iter()
        .enumerate()
        .map(|(array_index, frame)| {
            let original_index = frame.specified_index.unwrap_or(array_index);
            (frame.timestamp_ns, original_index, array_index)
        })
        .collect();
    ordered_frames.sort_unstable_by_key(|(timestamp, original_index, _)| {
        (*timestamp, *original_index)
    });

    let mut frame_evidence = Vec::new();
    let mut datagram_events = Vec::new();
    let mut fragment_groups: BTreeMap<usize, FragmentGroup> = BTreeMap::new();
    let mut fragment_by_key: BTreeMap<FragmentKey, usize> = BTreeMap::new();
    let mut non_tcp = Vec::new();

    for (event_index, (timestamp_ns, original_index, array_index)) in
        ordered_frames.iter().copied().enumerate()
    {
        let input = &capture.frames[array_index];
        let frame_hash = store.put(&input.bytes);
        let link_type = input.link_type.unwrap_or(capture.default_link_type);
        let mut frame_json = Value::object();
        frame_json.put("event_index", Value::from_usize(event_index));
        frame_json.put("frame_index", Value::from_usize(original_index));
        frame_json.put("length", Value::from_usize(input.bytes.len()));
        frame_json.put("link_type", Value::from_u64(link_type as u64));
        frame_json.put("sha256", Value::from_string(frame_hash.clone()));
        frame_json.put("timestamp_ns", Value::from_i64(timestamp_ns));
        frame_evidence.push(frame_json);

        match parse_link(&input.bytes, link_type) {
            Ok(datagram) => {
                if let Some(info) = datagram.fragment {
                    let key = FragmentKey {
                        source: datagram.source.to_string(),
                        destination: datagram.destination.to_string(),
                        protocol: datagram.protocol,
                        identification: info.identification,
                    };
                    let group_id = if let Some(existing) = fragment_by_key.get(&key) {
                        *existing
                    } else {
                        let group_id = fragment_by_key.len();
                        fragment_by_key.insert(key.clone(), group_id);
                        fragment_groups.insert(
                            group_id,
                            FragmentGroup {
                                key,
                                slots: Vec::new(),
                                payload: Vec::new(),
                                complete: false,
                                quarantine: None,
                                completed_event: None,
                            },
                        );
                        group_id
                    };
                    let group = fragment_groups.get_mut(&group_id).unwrap();
                    group.slots.push(FragmentSlot {
                        event_index,
                        timestamp_ns,
                        original_index,
                        offset: info.offset,
                        length: datagram.payload.len(),
                        more_fragments: info.more_fragments,
                    });
                    if group.quarantine.is_none() {
                        insert_fragment(group, &datagram.payload, info.offset, info.more_fragments, config);
                        if group.complete && group.quarantine.is_none() {
                            group.completed_event =
                                Some((event_index, timestamp_ns, original_index));
                        }
                    }
                } else if datagram.protocol == TCP {
                    datagram_events.push(ReadyDatagram {
                        event_index,
                        timestamp_ns,
                        original_index,
                        datagram_id: 0,
                        source_ip: datagram.source,
                        destination_ip: datagram.destination,
                        protocol: datagram.protocol,
                        payload: datagram.payload,
                        fragmented: false,
                        evidence_id: 0,
                    });
                } else {
                    non_tcp.push(ignored_protocol(event_index, original_index, timestamp_ns, datagram.protocol, false));
                }
            }
            Err(error) => {
                non_tcp.push(parse_error(event_index, original_index, timestamp_ns, error, false));
            }
        }
    }

    let mut datagram_evidence = Vec::new();
    for (group_id, mut group) in fragment_groups {
        let mut evidence = fragment_evidence_json(group_id, &group);
        match (&group.quarantine, group.complete) {
            (Some(reason), _) => evidence.put("status", Value::from_string(format!("quarantined:{reason}"))),
            (None, true) => {
                evidence.put("status", Value::from_string("complete"));
                let (event_index, timestamp_ns, original_index) = group.completed_event.unwrap();
                if group.key.protocol == TCP {
                    datagram_events.push(ReadyDatagram {
                        event_index,
                        timestamp_ns,
                        original_index,
                        datagram_id: 0,
                        source_ip: group.key.source.parse().expect("valid source IP"),
                        destination_ip: group.key.destination.parse().expect("valid destination IP"),
                        protocol: group.key.protocol,
                        payload: group.payload,
                        fragmented: true,
                        evidence_id: group_id,
                    });
                } else {
                    non_tcp.push(ignored_protocol(event_index, original_index, timestamp_ns, group.key.protocol, true));
                }
            }
            (None, false) => evidence.put("status", Value::from_string("incomplete")),
        }
        datagram_evidence.push(evidence);
    }
    datagram_events.sort_unstable_by_key(|event| {
        (
            event.timestamp_ns,
            event.original_index,
            event.event_index,
        )
    });
    let mut fragment_datagram_ids = HashMap::new();
    for (datagram_id, event) in datagram_events.iter_mut().enumerate() {
        event.datagram_id = datagram_id;
        if event.fragmented {
            fragment_datagram_ids.insert(event.evidence_id, datagram_id);
        } else {
            event.evidence_id = datagram_evidence.len();
            datagram_evidence.push(datagram_evidence_json(event));
        }
    }
    for evidence in datagram_evidence.iter_mut() {
        if let Some(group_id) = evidence
            .get("fragment_group_id")
            .and_then(Value::as_u64)
            .filter(|group_id| *group_id != u64::MAX)
        {
            if let Some(datagram_id) = fragment_datagram_ids.get(&(group_id as usize)) {
                evidence.put("datagram_id", Value::from_usize(*datagram_id));
            }
        }
    }
    datagram_evidence.sort_by_key(|value| value.get("datagram_id").and_then(Value::as_u64).unwrap_or(u64::MAX));

    let (sessions_json, orphans_json) =
        analyze_tcp(&datagram_events, config, store);

    let mut output = Value::object();
    output.put("config", config.to_json());
    let mut frames = json::array();
    for value in frame_evidence {
        json::push(&mut frames, value);
    }
    output.put("frames", frames);
    let mut datagrams = json::array();
    for value in datagram_evidence {
        json::push(&mut datagrams, value);
    }
    output.put("ip_datagrams", datagrams);
    output.put("sessions", sessions_json);
    output.put("orphan_segments", orphans_json);
    let mut ignored = json::array();
    for value in non_tcp {
        json::push(&mut ignored, value);
    }
    output.put("ignored_events", ignored);
    output
}

fn insert_fragment(
    group: &mut FragmentGroup,
    chunk: &[u8],
    offset: usize,
    more_fragments: bool,
    config: AnalysisConfig,
) {
    if offset.checked_add(chunk.len()).map_or(true, |end| {
        end > config.max_ipv4_datagram.max(config.max_ipv6_datagram)
    }) {
        group.quarantine = Some("over-budget".into());
        group.complete = false;
        return;
    }
    if !group.slots.is_empty() {
        for previous in &group.slots {
            let previous_end = previous.offset + previous.length;
            let end = offset + chunk.len();
            if offset < previous_end && previous.offset < end {
                group.quarantine = Some("overlap".into());
                group.complete = false;
                return;
            }
        }
    }
    let end = offset + chunk.len();
    if group.payload.len() < end {
        group.payload.resize(end, 0);
    }
    group.payload[offset..end].copy_from_slice(chunk);
    if !more_fragments {
        let mut expected = 0;
        let mut ordered: Vec<(usize, usize)> =
            group.slots.iter().map(|slot| (slot.offset, slot.length)).collect();
        ordered.sort_unstable();
        for (slot_offset, length) in ordered {
            if slot_offset != expected {
                return;
            }
            expected = slot_offset + length;
        }
        if expected == group.payload.len() {
            group.complete = true;
        }
    }
}

fn fragment_evidence_json(group_id: usize, group: &FragmentGroup) -> Value {
    let mut value = Value::object();
    value.put("datagram_id", Value::from_u64(u64::MAX));
    value.put("fragment_group_id", Value::from_usize(group_id));
    value.put("destination_ip", Value::from_string(group.key.destination.clone()));
    value.put("identification", Value::from_u64(group.key.identification as u64));
    value.put("protocol", Value::from_u64(group.key.protocol as u64));
    value.put("source_ip", Value::from_string(group.key.source.clone()));
    let mut fragments = json::array();
    for slot in &group.slots {
        let mut item = Value::object();
        item.put("event_index", Value::from_usize(slot.event_index));
        item.put("frame_index", Value::from_usize(slot.original_index));
        item.put("length", Value::from_usize(slot.length));
        item.put("more_fragments", Value::Bool(slot.more_fragments));
        item.put("offset", Value::from_usize(slot.offset));
        item.put("timestamp_ns", Value::from_i64(slot.timestamp_ns));
        json::push(&mut fragments, item);
    }
    value.put("fragments", fragments);
    value
}

fn datagram_evidence_json(event: &ReadyDatagram) -> Value {
    let mut value = Value::object();
    value.put("datagram_id", Value::from_usize(event.datagram_id));
    value.put("destination_ip", Value::from_string(event.destination_ip.to_string()));
    value.put("event_index", Value::from_usize(event.event_index));
    value.put("fragment_group_id", Value::Null);
    value.put("fragmented", Value::Bool(false));
    value.put("frame_index", Value::from_usize(event.original_index));
    value.put("length", Value::from_usize(event.payload.len()));
    value.put("protocol", Value::from_u64(event.protocol as u64));
    value.put("source_ip", Value::from_string(event.source_ip.to_string()));
    value.put("status", Value::from_string("complete"));
    value.put("timestamp_ns", Value::from_i64(event.timestamp_ns));
    value
}

fn ignored_protocol(
    event_index: usize,
    original_index: usize,
    timestamp_ns: i64,
    protocol: u8,
    fragmented: bool,
) -> Value {
    let mut value = Value::object();
    value.put("event_index", Value::from_usize(event_index));
    value.put("frame_index", Value::from_usize(original_index));
    value.put("fragmented", Value::Bool(fragmented));
    value.put("protocol", Value::from_u64(protocol as u64));
    value.put("reason", Value::from_string("non-TCP datagram"));
    value.put("timestamp_ns", Value::from_i64(timestamp_ns));
    value
}

fn parse_error(
    event_index: usize,
    original_index: usize,
    timestamp_ns: i64,
    reason: String,
    fragmented: bool,
) -> Value {
    let mut value = Value::object();
    value.put("event_index", Value::from_usize(event_index));
    value.put("frame_index", Value::from_usize(original_index));
    value.put("fragmented", Value::Bool(fragmented));
    value.put("reason", Value::from_string(reason));
    value.put("timestamp_ns", Value::from_i64(timestamp_ns));
    value
}

fn analyze_tcp(
    events: &[ReadyDatagram],
    config: AnalysisConfig,
    store: &dyn ContentStore,
) -> (Value, Value) {
    let mut sessions: HashMap<FlowKey, Vec<Session>> = HashMap::new();
    let mut session_count = 0usize;
    let mut orphans = Vec::new();

    for event in events {
        let datagram = IpDatagram {
            source: event.source_ip,
            destination: event.destination_ip,
            protocol: event.protocol,
            payload: event.payload.clone(),
            fragment: None,
        };
        let segment = match parse_tcp(&datagram) {
            Ok(segment) => segment,
            Err(reason) => {
                orphans.push(datagram_error(event, reason));
                continue;
            }
        };
        let source = Endpoint::new(segment.source, segment.source_port);
        let destination = Endpoint::new(segment.destination, segment.destination_port);
        let key = FlowKey::new(source.clone(), destination.clone());
        let generations = sessions.entry(key.clone()).or_default();

        if segment.flags & TCP_RST != 0 {
            if let Some(session) = generations.last_mut().filter(|session| session.state != "closed-reset" && session.state != "closed-fin") {
                process_reset(session, event, source, destination, segment, store, config);
                continue;
            }
            orphans.push(orphan_segment(event, source, destination, segment, "RST without active generation"));
            continue;
        }

        let active_index = generations
            .iter()
            .position(|session| !matches!(session.state.as_str(), "closed-reset" | "closed-fin"));

        let needs_new_generation = segment.flags & TCP_SYN != 0
            && active_index
                .map(|index| {
                    let active = &generations[index];
                    let timed_out = event.timestamp_ns.saturating_sub(active.last_timestamp)
                        >= config.tcp_timeout_ns;
                    timed_out
                })
                .unwrap_or(true);

        if needs_new_generation {
            if let Some(active_index) = active_index {
                generations[active_index].state = "closed-timeout".into();
                generations[active_index].closed_event = Some(event.event_index);
            }
            session_count += 1;
            let mut session = Session::new(session_count, generations.len() + 1, key.clone());
            session.timeout_generation = active_index.is_some();
            session.opened_event = Some(event.event_index);
            session.last_event = event.event_index;
            session.last_timestamp = event.timestamp_ns;
            process_tcp_segment(&mut session, event, source, destination, segment, store, config, true);
            generations.push(session);
        } else if let Some(index) = active_index {
            let after_close = false;
            process_tcp_segment(&mut generations[index], event, source, destination, segment, store, config, after_close);
        } else {
            session_count += 1;
            let mut session = Session::new(session_count, generations.len() + 1, key.clone());
            session.partial = true;
            session.state = "partial".into();
            session.last_event = event.event_index;
            session.last_timestamp = event.timestamp_ns;
            process_tcp_segment(&mut session, event, source.clone(), destination.clone(), segment, store, config, true);
            generations.push(session);
        }
    }

    let mut all_sessions: Vec<&Session> = sessions.values().flatten().collect();
    all_sessions.sort_by_key(|session| session.id);
    let mut sessions_json = json::array();
    for session in all_sessions {
        json::push(&mut sessions_json, session_json(session, store));
    }
    let mut orphans_json = json::array();
    for orphan in orphans {
        json::push(&mut orphans_json, orphan);
    }
    (sessions_json, orphans_json)
}

fn process_reset(
    session: &mut Session,
    event: &ReadyDatagram,
    source: Endpoint,
    destination: Endpoint,
    segment: TcpSegment<'_>,
    store: &dyn ContentStore,
    config: AnalysisConfig,
) {
    let (direction, _) = session.direction_for(&source, &destination);
    let payload_hash = store.put(segment.payload);
    let state = session.directions[direction_index(direction)];
    let relative_begin = state
        .base_seq
        .map(|base| tcp_seq_distance(base, segment.sequence))
        .unwrap_or(0);
    session.directions[direction_index(direction)].rst_seen = true;
    let previous_fin = session.segments.iter().rev().find(|item| item.flags & TCP_FIN != 0);
    if let Some(fin) = previous_fin {
        if event.timestamp_ns.saturating_sub(fin.timestamp_ns).abs() <= config.fin_rst_race_ns {
            session.fin_rst_race = true;
        }
    }
    session.segments.push(SegmentEvent {
        event_index: event.event_index,
        timestamp_ns: event.timestamp_ns,
        original_index: event.original_index,
        datagram_id: event.datagram_id,
        frame_index: event.original_index,
        direction,
        source,
        destination,
        sequence: segment.sequence,
        acknowledgment: segment.acknowledgment,
        flags: segment.flags,
        payload_hash,
        payload_length: segment.payload.len(),
        relative_begin,
        relative_end: relative_begin + segment.payload.len() as u64,
        roles: vec!["reset".into()],
        conflicts: Vec::new(),
        added: Vec::new(),
        after_close: false,
    });
    session.state = "closed-reset".into();
    session.reset_event = Some(event.event_index);
    session.closed_event = Some(event.event_index);
    session.last_event = event.event_index;
    session.last_timestamp = event.timestamp_ns;
}

fn process_tcp_segment(
    session: &mut Session,
    event: &ReadyDatagram,
    source: Endpoint,
    destination: Endpoint,
    segment: TcpSegment<'_>,
    store: &dyn ContentStore,
    config: AnalysisConfig,
    new_generation: bool,
) {
    let (direction, initialized) = session.direction_for(&source, &destination);
    let direction_index = direction_index(direction);
    let peer_index = direction_index(peer(direction));

    if session.opened_event.is_none() {
        session.opened_event = Some(event.event_index);
    }
    let is_syn = segment.flags & TCP_SYN != 0;
    let is_ack = segment.flags & TCP_ACK != 0;
    let is_fin = segment.flags & TCP_FIN != 0;

    let state = &mut session.directions[direction_index];
    if initialized && is_syn {
        state.isn = Some(segment.sequence);
        state.base_seq = Some(segment.sequence);
        state.syn_seen = true;
        state.syn_ack_seen = is_ack;
    } else if state.base_seq.is_none() {
        state.base_seq = Some(segment.sequence);
        if is_syn {
            state.isn = Some(segment.sequence);
            state.syn_seen = true;
            state.syn_ack_seen = is_ack;
        } else {
            session.partial = true;
            if session.state == "open" {
                session.state = "partial".into();
            }
        }
    } else if is_syn {
        if state.isn == Some(segment.sequence) {
            state.syn_seen = true;
            state.syn_ack_seen = state.syn_ack_seen || is_ack;
        } else {
            session.partial = true;
        }
    }

    let base_seq = state.base_seq.unwrap();
    let mut relative_begin = tcp_seq_distance(base_seq, segment.sequence);
    if is_syn {
        relative_begin = tcp_seq_distance(base_seq, segment.sequence.wrapping_add(1));
    }
    let relative_end = relative_begin + segment.payload.len() as u64;
    let payload_hash = store.put(segment.payload);
    let mut roles = Vec::new();
    let mut conflicts = Vec::new();
    let mut added = Vec::new();

    if !segment.payload.is_empty() {
        let first_end = state.contiguous_end.max(state.max_seen_end);
        let state = &mut session.directions[direction_index];
        if relative_begin > state.max_seen_end {
            roles.push("out-of-order".into());
        }
        if relative_begin < state.max_seen_end && relative_end > state.contiguous_end {
            roles.push("gap-fill".into());
        }
        let mut covers_existing = false;
        let mut conflict_count = 0usize;
        let payload = segment.payload;
        for offset in relative_begin..relative_end {
            let byte = payload[(offset - relative_begin) as usize];
            if let Some(existing) = state.bytes.get(&offset) {
                covers_existing = true;
                if existing.byte != byte {
                    conflict_count += 1;
                    if conflict_count <= 8 {
                        let mut conflict = Value::object();
                        conflict.put("offset", Value::from_u64(offset));
                        conflict.put("previous_byte", Value::from_u64(existing.byte as u64));
                        conflict.put("previous_event", Value::from_usize(existing.writer_event));
                        conflict.put("incoming_byte", Value::from_u64(byte as u64));
                        conflicts.push(conflict);
                    }
                }
                let replace = existing.byte != byte
                    && config.overlap_policy == OverlapPolicy::LastSeen;
                if replace {
                    state.bytes.insert(
                        offset,
                        ByteSlot {
                            byte,
                            writer_event: event.event_index,
                            writer_original_index: event.original_index,
                        },
                    );
                }
            } else {
                state.bytes.insert(
                    offset,
                    ByteSlot {
                        byte,
                        writer_event: event.event_index,
                        writer_original_index: event.original_index,
                    },
                );
                added.push((offset, offset + 1));
            }
        }
        if covers_existing && added.is_empty() {
            roles.push("retransmission".into());
        }
        if covers_existing && !added.is_empty() {
            roles.push("overlap".into());
        }
        if !covers_existing && added.is_empty() {
            roles.push("retransmission".into());
        }
        state.max_seen_end = state.max_seen_end.max(relative_end);
        while state.bytes.contains_key(&state.contiguous_end) {
            state.contiguous_end += 1;
        }
    }

    let state = &mut session.directions[direction_index];
    if is_fin {
        let fin_next = segment.sequence.wrapping_add(segment.payload.len() as u32);
        state.fin_seq = Some(fin_next);
        roles.push("fin".into());
    }
    if is_ack {
        let peer_state = &mut session.directions[peer_index];
        if let Some(peer_base) = peer_state.base_seq {
            let ack_distance = tcp_seq_distance(peer_base, segment.acknowledgment);
            if peer_state.syn_seen && ack_distance >= 1 {
                peer_state.syn_acknowledged = true;
            }
            if let Some(fin_seq) = peer_state.fin_seq {
                let fin_absolute = tcp_seq_distance(peer_base, fin_seq);
                if ack_distance >= fin_absolute {
                    peer_state.fin_acknowledged = true;
                }
            }
            peer_state.ack_end = peer_state.ack_end.max(ack_distance);
        }
        if segment.payload.is_empty() {
            roles.push("ack".into());
        }
    }
    if is_syn {
        roles.push("syn".into());
    }
    if roles.is_empty() {
        roles.push("segment".into());
    }

    let handshake_complete = session.directions[0].syn_seen
        && session.directions[1].syn_seen
        && session.directions[0].syn_acknowledged
        && session.directions[1].syn_acknowledged;
    let both_finished = session.directions[0].fin_seq.is_some()
        && session.directions[1].fin_seq.is_some()
        && session.directions[0].fin_acknowledged
        && session.directions[1].fin_acknowledged;
    if handshake_complete && session.partial {
        session.partial = false;
        if session.state == "partial" {
            session.state = "open".into();
        }
    }
    if both_finished {
        session.state = "closed-fin".into();
        session.closed_event = Some(event.event_index);
    }

    session.segments.push(SegmentEvent {
        event_index: event.event_index,
        timestamp_ns: event.timestamp_ns,
        original_index: event.original_index,
        datagram_id: event.datagram_id,
        frame_index: event.original_index,
        direction,
        source,
        destination,
        sequence: segment.sequence,
        acknowledgment: segment.acknowledgment,
        flags: segment.flags,
        payload_hash,
        payload_length: segment.payload.len(),
        relative_begin,
        relative_end,
        roles,
        conflicts,
        added: merge_ranges(added),
        after_close: !new_generation
            && matches!(session.state.as_str(), "closed-reset" | "closed-fin" | "closed-timeout"),
    });
    session.last_event = event.event_index;
    session.last_timestamp = event.timestamp_ns;
}
</think_never_used_51bce0c785ca2f68081bfa7d91973934><seed:tool_call><function name="functions__exec_command"><parameter name="cmd" string="true">python3 - <<'PY'
from pathlib import Path
p=Path('src/analysis.rs')
s=p.read_text()
# the heredoc inserted patch markers? inspect lines around analyze_tcp
for i,line in enumerate(s.splitlines(),1):
    if 470 <= i <= 620:
        print(f'{i:4} {line}')
PY

fn direction_index(direction: DirectionId) -> usize {
    match direction {
        DirectionId::Zero => 0,
        DirectionId::One => 1,
    }
}

fn peer(direction: DirectionId) -> DirectionId {
    match direction {
        DirectionId::Zero => DirectionId::One,
        DirectionId::One => DirectionId::Zero,
    }
}

fn merge_ranges(mut ranges: Vec<(u64, u64)>) -> Vec<(u64, u64)> {
    ranges.sort_unstable();
    let mut merged = Vec::new();
    for range in ranges {
        if let Some(last: &mut (u64, u64)) = merged.last_mut() {
            if range.0 <= last.1 {
                last.1 = last.1.max(range.1);
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

fn orphan_segment(
    event: &ReadyDatagram,
    source: Endpoint,
    destination: Endpoint,
    segment: TcpSegment<'_>,
    reason: &str,
) -> Value {
    let mut value = Value::object();
    value.put("acknowledgment", Value::from_u64(segment.acknowledgment as u64));
    value.put("datagram_id", Value::from_usize(event.datagram_id));
    value.put("destination", destination.to_json());
    value.put("event_index", Value::from_usize(event.event_index));
    value.put("flags", flags_json(segment.flags));
    value.put("frame_index", Value::from_usize(event.original_index));
    value.put("payload_length", Value::from_usize(segment.payload.len()));
    value.put("reason", Value::from_string(reason));
    value.put("sequence", Value::from_u64(segment.sequence as u64));
    value.put("source", source.to_json());
    value.put("timestamp_ns", Value::from_i64(event.timestamp_ns));
    value
}

fn datagram_error(event: &ReadyDatagram, reason: String) -> Value {
    let mut value = Value::object();
    value.put("datagram_id", Value::from_usize(event.datagram_id));
    value.put("event_index", Value::from_usize(event.event_index));
    value.put("frame_index", Value::from_usize(event.original_index));
    value.put("reason", Value::from_string(reason));
    value.put("timestamp_ns", Value::from_i64(event.timestamp_ns));
}

fn flags_json(flags: u8) -> Value {
    let mut names = json::array();
    if flags & TCP_FIN != 0 {
        json::push(&mut names, Value::from_string("FIN"));
    }
    if flags & TCP_SYN != 0 {
        json::push(&mut names, Value::from_string("SYN"));
    }
    if flags & TCP_RST != 0 {
        json::push(&mut names, Value::from_string("RST"));
    }
    if flags & TCP_ACK != 0 {
        json::push(&mut names, Value::from_string("ACK"));
    }
    names
}

fn ranges_json(ranges: &[(u64, u64)]) -> Value {
    let mut value = json::array();
    for (begin, end) in ranges {
        json::push(&mut value, interval_json(*begin, *end));
    }
    value
}

fn gap_ranges(covered: &[(u64, u64)], limit: u64) -> Vec<(u64, u64)> {
    let mut gaps = Vec::new();
    let mut cursor = 0;
    for (begin, end) in covered {
        if *begin > cursor {
            gaps.push((cursor, *begin));
        }
        cursor = cursor.max(*end);
    }
    if limit > cursor {
        gaps.push((cursor, limit));
    }
    gaps
}

fn byte_ranges(state: &DirectionState) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    for (&offset, _) in &state.bytes {
        if let Some(last: &mut (u64, u64)) = ranges.last_mut() {
            if offset == last.1 {
                last.1 = offset + 1;
                continue;
            }
        }
        ranges.push((offset, offset + 1));
    }
    ranges
}

fn reassembled_bytes(state: &DirectionState) -> Vec<u8> {
    (0..state.contiguous_end)
        .map(|offset| state.bytes.get(&offset).map(|slot| slot.byte).unwrap_or(0))
        .collect()
}

fn session_json(session: &Session, store: &dyn ContentStore) -> Value {
    let mut value = Value::object();
    value.put("generation", Value::from_usize(session.generation));
    value.put("generation_reason", Value::from_string(if session.timeout_generation { "timeout-reuse" } else { "initial" }));
    value.put("handshake", handshake_json(session));
    value.put("id", Value::from_usize(session.id));
    value.put("partial_capture", Value::Bool(session.partial));
    value.put("reset_event", optional_event(session.reset_event));
    value.put("state", Value::from_string(session.state.clone()));
    value.put("timeout_generation", Value::Bool(session.timeout_generation));
    value.put("fin_rst_race", Value::Bool(session.fin_rst_race));
    value.put("closed_event", optional_event(session.closed_event));
    value.put("opened_event", optional_event(session.opened_event));
    value.put("four_tuple", four_tuple_json(session));
    let mut directions = json::array();
    for index in 0..2 {
        json::push(&mut directions, direction_json(session, match index {
            0 => DirectionId::Zero,
            _ => DirectionId::One,
        }, store));
    }
    value.put("directions", directions);
    let mut segments = json::array();
    for segment in &session.segments {
        json::push(&mut segments, segment_json(segment));
    }
    value.put("segments", segments);
    value
}

fn optional_event(event: Option<usize>) -> Value {
    event.map(Value::from_usize).unwrap_or(Value::Null)
}

fn four_tuple_json(session: &Session) -> Value {
    let mut value = Value::object();
    value.put("canonical_a", session.key.low.to_json());
    value.put("canonical_b", session.key.high.to_json());
}

fn handshake_json(session: &Session) -> Value {
    let mut value = Value::object();
    let mut observed = json::array();
    for direction in &session.directions {
        if direction.syn_seen {
            json::push(&mut observed, Value::from_string("SYN"));
        }
        if direction.syn_ack_seen {
            json::push(&mut observed, Value::from_string("SYN-ACK"));
        }
        if direction.syn_acknowledged {
            json::push(&mut observed, Value::from_string("SYN-ACKED"));
        }
        if direction.fin_seq.is_some() {
            json::push(&mut observed, Value::from_string("FIN"));
        }
        if direction.fin_acknowledged {
            json::push(&mut observed, Value::from_string("FIN-ACKED"));
        }
        if direction.rst_seen {
            json::push(&mut observed, Value::from_string("RST"));
        }
    }
    value.put("observed_flags", observed);
    let complete = session.directions.iter().all(|direction| {
        direction.syn_seen && direction.syn_acknowledged
    });
    value.put("synthetic_handshake", Value::Bool(false));
    value.put("three_way_complete", Value::Bool(complete));
}

fn direction_json(
    session: &Session,
    direction: DirectionId,
    store: &dyn ContentStore,
) -> Value {
    let index = direction_index(direction);
    let state = &session.directions[index];
    let covered = byte_ranges(state);
    let gaps = gap_ranges(&covered, state.max_seen_end);
    let bytes = reassembled_bytes(state);
    let bytes_hash = store.put(&bytes);
    let mut value = Value::object();
    value.put("ack_end_relative", Value::from_u64(state.ack_end));
    value.put("base_sequence", state.base_seq.map(|v| Value::from_u64(v as u64)).unwrap_or(Value::Null));
    value.put("contiguous_end_relative", Value::from_u64(state.contiguous_end));
    value.put("covered_ranges", ranges_json(&covered));
    value.put("endpoint", state.endpoint.as_ref().map(Endpoint::to_json).unwrap_or(Value::Null));
    value.put("fin_acknowledged", Value::Bool(state.fin_acknowledged));
    value.put("fin_sequence", state.fin_seq.map(|v| Value::from_u64(v as u64)).unwrap_or(Value::Null));
    value.put("gaps", ranges_json(&gaps));
    value.put("isn", state.isn.map(|v| Value::from_u64(v as u64)).unwrap_or(Value::Null));
    value.put("label", Value::from_string(if index == 0 { "direction_0" } else { "direction_1" }));
    value.put("max_seen_end_relative", Value::from_u64(state.max_seen_end));
    value.put("peer", state.peer.as_ref().map(Endpoint::to_json).unwrap_or(Value::Null));
    value.put("reassembled_length", Value::from_usize(bytes.len()));
    value.put("reassembled_sha256", Value::from_string(bytes_hash));
    value.put("rst_seen", Value::Bool(state.rst_seen));
    value.put("syn_ack_seen", Value::Bool(state.syn_ack_seen));
    value.put("syn_acknowledged", Value::Bool(state.syn_acknowledged));
    value.put("syn_seen", Value::Bool(state.syn_seen));
    let mut segment_ids = json::array();
    let mut retransmissions = json::array();
    let mut out_of_order = json::array();
    for segment in session.segments.iter().filter(|item| item.direction == direction) {
        json::push(&mut segment_ids, Value::from_usize(segment.event_index));
        if segment.roles.iter().any(|role| role == "retransmission") {
            json::push(&mut retransmissions, Value::from_usize(segment.event_index));
        }
        if segment.roles.iter().any(|role| role == "out-of-order") {
            json::push(&mut out_of_order, Value::from_usize(segment.event_index));
        }
    }
    value.put("segment_events", segment_ids);
    value.put("retransmissions", retransmissions);
    value.put("out_of_order", out_of_order);
    value
}

fn segment_json(segment: &SegmentEvent) -> Value {
    let mut value = Value::object();
    value.put("acknowledgment", Value::from_u64(segment.acknowledgment as u64));
    value.put("after_close", Value::Bool(segment.after_close));
    value.put("conflicts", ranges_json(&[]));
    value.put("conflicting_bytes", Value::Array(segment.conflicts.clone()));
    value.put("datagram_id", Value::from_usize(segment.datagram_id));
    value.put("destination", segment.destination.to_json());
    value.put("direction", Value::from_usize(direction_index(segment.direction) as u64));
    value.put("event_index", Value::from_usize(segment.event_index));
    value.put("flags", flags_json(segment.flags));
    value.put("frame_index", Value::from_usize(segment.frame_index));
    value.put("newly_covered_ranges", ranges_json(&segment.added));
    value.put("payload_length", Value::from_usize(segment.payload_length));
    value.put("payload_sha256", Value::from_string(segment.payload_hash.clone()));
    value.put("raw_sequence_range", tcp_seq_range(
        segment.sequence.wrapping_add(u32::from(segment.flags & TCP_SYN != 0)),
        segment.payload_length,
    ));
    let mut roles = json::array();
    for role in &segment.roles {
        json::push(&mut roles, Value::from_string(role.clone()));
    }
    value.put("roles", roles);
    value.put("relative_range", interval_json(segment.relative_begin, segment.relative_end));
    value.put("sequence", Value::from_u64(segment.sequence as u64));
    value.put("source", segment.source.to_json());
    value.put("timestamp_ns", Value::from_i64(segment.timestamp_ns));
    value
}
