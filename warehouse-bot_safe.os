#! Warehouse-bot dispatcher — untrusted an order can only ever become one of a fixed set of decisions over a
#! closed type, never a tool argument. An injected instruction cannot be represented in the
#! closed type, so it is rejected at the trust boundary (and re-clamped at run time by extract).
#! @requires pick — the warehouse-bot dispatcher sink
#! @effect io
#! @taint bridge — extract<Decision> turns the tainted input into a trusted decision
grant pick

type Bin = BinA | BinB | BinC
type Decision = Pick(Bin) | Hold

let raw = fetch<web>  # UNTRUSTED an order — tainted
quarantined { let d = extract<Decision>(raw) }  # only a fixed Decision (payloads too) crosses
privileged { pick(d) }  # act on the trusted decision only
