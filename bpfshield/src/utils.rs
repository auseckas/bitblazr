use bpfshield_common::{utils::str_from_buf_nul, BShieldEvent};

pub(crate) fn debug_event(e: &BShieldEvent) -> String {
    format!(
        "BShieldEvent {{ class: {:?}, event_type: {:?}, ppid: {:?}, tgid: {}, pid: {}, uid: {}, gid: {}, action: {:?}, path: {}, argv_count: {}, argv: {:?} }}",
        &e.class,
        &e.event_type,
        &e.ppid,
        &e.tgid,
        &e.pid,
        &e.uid,
        &e.gid,
        &e.action,
        &str_from_buf_nul(&e.path).unwrap_or(""),
        &e.argv_count,
        {
            let mut args = Vec::new();
            for i in 0..e.argv_count {
                if i >= 20 {
                    break;
                }
                args.push(str_from_buf_nul(&e.argv[i as usize]).unwrap_or(""));
            }
            args
        }
    )
}
