#! VULNERABLE warehouse-bot — feeds the untrusted input straight to the tool, no extraction.
#! check -> UNSAFE: tainted data cannot reach a capability.
grant pick

let raw = fetch<web>
privileged { pick(raw) }  # tainted -> tool: REJECTED
