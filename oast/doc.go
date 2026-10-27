// Package oast is the out-of-band interaction (OAST / collaborator) subsystem.
//
// # Why it exists
//
// A large share of web vulnerabilities produce no visible response: blind SSRF,
// blind XXE, blind command injection, blind SQL injection over a database's
// egress function (load_file/UTL_HTTP/dblink), blind SSTI that renders into an
// outbound request, and log4j-style gadget chains all confirm themselves only by
// making the TARGET reach out to an address the attacker controls. Without a
// collaborator these are indistinguishable from "nothing happened", so an agent
// either reports nothing or fabricates a finding from a guess. With one, the same
// probe produces an objective, timestamped, independently-received proof.
//
// What this package provides
//
//   - Payload minting: unique, unguessable subdomains of a base domain, plus a
//     matching HTTP path, tagged with the run that requested them (task /
//     exploration / intent / worker) so a callback can be attributed to the exact
//     probe that planted it.
//   - Listener: DNS A/AAAA/TXT queries and HTTP/HTTPS requests arriving for any
//     minted payload are recorded with their full raw exchange and remote address.
//   - Polling: an agent asks "has anything hit my payload since I last checked"
//     and gets back only the new interactions, drained so a poll is idempotent.
//   - TTL: payloads expire and their interactions expire with them, so a long
//     lived process does not accumulate unbounded state.
//
// No third-party OAST service is contacted: every callback arrives at this
// process's own listeners on a domain the operator owns. That keeps the channel
// free of external dependencies (rate limits, outages, third-party data
// retention) and makes the recorded interaction exactly as trustworthy as the
// listener itself.
package oast
