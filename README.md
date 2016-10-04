# RUST-SNMP
Dependency-free basic SNMPv2 client in Rust.

Suppports:

- GET
- GETNEXT
- GETBULK
- Basic SNMPv2 types
- Synchronous requests
- UDP transport

Currently does not support:

- SNMPv1
- SNMPv3
- MIBs
- Async requests
- Transports other than UDP

## TODO
- Async requests
- Walking function
- Additional ObjectIdentifier utility methods
- Decouple PDU building/parsing from socket handling
- SNMPv3 (would require an external dependency)


# Examples

## GET NEXT
```no_run
use std::time::Duration;
use snmp::{SyncSession, Value};

let sys_descr_oid = [1,3,6,1,2,1,1,1,];
let agent_addr    = "198.51.100.123:161";
let community     = b"f00b4r";
let timeout       = Duration::from_secs(2);

let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).unwrap();
let mut response = sess.getnext(&sys_descr_oid[..]).unwrap();
if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
    println!("myrouter sysDescr: {}", String::from_utf8_lossy(sys_descr));
}
```
## GET BULK
```no_run
use std::time::Duration;
use snmp::SyncSession;

let system_oid      = [1,3,6,1,2,1,1,];
let agent_addr      = "[2001:db8:f00:b413::abc]:161";
let community       = b"f00b4r";
let timeout         = Duration::from_secs(2);
let non_repeaters   = 0;
let max_repetitions = 7; // number of items in "system" OID

let mut sess = SyncSession::new(agent_addr, community, Some(timeout), 0).unwrap();
let response = sess.getbulk(&[&system_oid[..]], non_repeaters, max_repetitions).unwrap();

for (name, val) in response.varbinds {
    println!("{} => {:?}", name, val);
}
```
