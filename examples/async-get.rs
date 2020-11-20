use std::{env, time::Duration};

use snmp::{AsyncSession, Value};

#[tokio::main]
async fn main() {
    if let Some(param) = env::args().nth(1) {
        let sys_descr_oid = &[1, 3, 6, 1, 2, 1, 1, 1, 0];
        let agent_addr = format!("{}:161", param);
        let community = b"public";
        let timeout = Duration::from_secs(2);

        let session = AsyncSession::new(&agent_addr, community, Some(timeout), 0).unwrap();

        let mut response = session.get(&[sys_descr_oid]).await.unwrap();

        if let Some((_oid, Value::OctetString(sys_descr))) = response.varbinds.next() {
            println!("sysDescr: {}", String::from_utf8_lossy(&sys_descr));
        }
    } else {
        eprintln!("usage: {} address", env::current_exe().unwrap().display());
    }
}
