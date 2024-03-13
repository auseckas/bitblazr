use super::get_field;
use crate::utils::get_hash;
use crate::BSError;
use aho_corasick::AhoCorasick;
use bitblazr_common::BlazrEvent;
use bitblazr_common::{rules::*, BlazrEventType};
use config::{Config, File, FileFormat};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::env;
use tracing::debug;

#[derive(Debug)]
enum LogVar {
    Numbers(Vec<i64>),
    String((Vec<String>, AhoCorasick)),
}

#[derive(Debug)]
struct LogOp {
    pub target: BlazrRuleTarget,
    pub negate: bool,
    pub command: BlazrRuleCommand,
    pub var: LogVar,
}

#[derive(Debug, Default)]
pub(crate) struct BlazrLogResult {
    pub ignore: bool,
    pub log: bool,
    pub alert: bool,
}

#[derive(Debug)]
pub(crate) struct BlazrRuleEngine {
    ignore: HashMap<i64, Vec<LogOp>>,
    log: HashMap<i64, Vec<LogOp>>,
    alert: HashMap<i64, Vec<LogOp>>,
}

impl BlazrRuleEngine {
    fn get_op_key(&self, class: &BlazrRuleClass, event_type: &BlazrEventType) -> i64 {
        (*class as i64) << 32 | *event_type as i64
    }

    fn check_str_var(
        &self,
        cmd: &BlazrRuleCommand,
        left: &LogVar,
        right: &[u8],
    ) -> Result<bool, anyhow::Error> {
        match left {
            LogVar::String((_, ac)) => {
                for m in ac.find_iter(right) {
                    let right_end = right.len();
                    let m_start = m.start();
                    let m_end = m.end();

                    let matched = match *cmd {
                        BlazrRuleCommand::Eq => m_start == 0 && right_end == m_end,
                        BlazrRuleCommand::StartsWith => m_start == 0,
                        BlazrRuleCommand::EndsWith => right_end == m_end,
                        BlazrRuleCommand::Contains => true,
                        _ => false,
                    };

                    if matched {
                        return Ok(true);
                    }
                }
            }
            _ => (),
        };

        Ok(false)
    }

    fn check_int_var(
        &self,
        cmd: &BlazrRuleCommand,
        left: &LogVar,
        right: i64,
    ) -> Result<bool, anyhow::Error> {
        let r = match left {
            LogVar::Numbers(ns) => {
                let mut matched = false;
                for n in ns {
                    if *n == right {
                        matched = true;
                        break;
                    }
                }
                match *cmd {
                    BlazrRuleCommand::Eq => matched,
                    BlazrRuleCommand::Neq => !matched,
                    _ => false,
                }
            }
            _ => false,
        };

        Ok(r)
    }

    fn check_op(&self, op: &LogOp, e: &BlazrEvent) -> Result<bool, anyhow::Error> {
        let mut result = match op.target {
            BlazrRuleTarget::Path => self.check_str_var(&op.command, &op.var, &e.path)?,
            BlazrRuleTarget::Port => self.check_int_var(&op.command, &op.var, e.port as i64)?,
            BlazrRuleTarget::IpProto => {
                self.check_int_var(&op.command, &op.var, e.protocol as i64)?
            }
            BlazrRuleTarget::Context => {
                if let LogVar::String((patterns, _)) = &op.var {
                    let pats: Vec<i64> = patterns.iter().map(|s| get_hash(s) as i64).collect();
                    let mut matched = false;
                    if !pats.is_empty() {
                        matched = true;
                    }
                    for pat in pats {
                        if !e.labels.contains(&pat) {
                            matched = false;
                            break;
                        }
                    }
                    matched
                } else {
                    false
                }
            }
            _ => false,
        };

        if op.negate {
            result = !result;
        }

        Ok(result)
    }

    fn check_map(
        &self,
        key: i64,
        map: &HashMap<i64, Vec<LogOp>>,
        e: &BlazrEvent,
    ) -> Result<bool, anyhow::Error> {
        if let Some(ops) = map.get(&key) {
            for op in ops {
                if !self.check_op(op, e)? {
                    return Ok(false);
                }
            }
            return Ok(true);
        }

        Ok(false)
    }

    pub fn check_rules(&self, e: &BlazrEvent) -> Result<BlazrLogResult, anyhow::Error> {
        let mut log_result = BlazrLogResult::default();

        debug!(
            "Log class: {:?}, event type: {:?}",
            &e.log_class, &e.event_type
        );
        let key = self.get_op_key(&e.log_class, &e.event_type);
        log_result.ignore = self.check_map(key, &self.ignore, e)?;
        if log_result.ignore {
            return Ok(log_result);
        }

        log_result.log = self.check_map(key, &self.log, e)?;
        log_result.alert = self.check_map(key, &self.alert, e)?;

        Ok(log_result)
    }

    fn parse_dir(
        target: &BlazrRuleTarget,
        labels: &HashMap<String, i64>,
        dir: &mut Value,
    ) -> Result<Vec<LogOp>, anyhow::Error> {
        let mut ops = Vec::new();
        match dir {
            Value::Object(obj) => {
                for (c, v) in obj {
                    let comm = BlazrRuleCommand::from_str(c.trim().to_string().as_mut_str());
                    if comm.is_undefined() {
                        return Err(BSError::InvalidAttribute {
                            attribute: "command",
                            value: c.to_string(),
                        }
                        .into());
                    }

                    if matches!(comm, BlazrRuleCommand::Not) {
                        let mut dirs = BlazrRuleEngine::parse_dir(&target, labels, v)?;
                        dirs = dirs
                            .into_iter()
                            .map(|mut d| {
                                d.negate = true;
                                d
                            })
                            .collect();

                        ops.append(&mut dirs);
                        continue;
                    }

                    let var = match v {
                        Value::Number(n) => LogVar::Numbers(match n.as_i64() {
                            Some(n) => vec![n],
                            None => {
                                return Err(BSError::InvalidAttribute {
                                    attribute: "var not compatible with i64",
                                    value: v.to_string(),
                                }
                                .into());
                            }
                        }),
                        Value::String(s) => LogVar::String((
                            vec![s.to_string()],
                            AhoCorasick::builder()
                                .ascii_case_insensitive(true)
                                .build([s])?,
                        )),
                        Value::Array(a) => {
                            let mut str_vars = Vec::new();
                            let mut int_vars = Vec::new();
                            for vs in a {
                                if let Some(s) = vs.as_str() {
                                    str_vars.push(s.to_string());
                                } else if let Some(n) = vs.as_i64() {
                                    int_vars.push(n);
                                } else {
                                    return Err(BSError::InvalidAttribute {
                                        attribute: "var not an int or a string",
                                        value: v.to_string(),
                                    }
                                    .into());
                                }
                            }

                            if matches!(target, BlazrRuleTarget::Context) {
                                for v in &str_vars {
                                    if !labels.contains_key(v.as_str()) {
                                        return Err(BSError::InvalidAttribute {
                                            attribute: "context",
                                            value: v.to_string(),
                                        }
                                        .into());
                                    }
                                }
                            }

                            if !str_vars.is_empty() {
                                let ac = AhoCorasick::builder()
                                    .ascii_case_insensitive(true)
                                    .build(&str_vars)?;
                                LogVar::String((str_vars, ac))
                            } else if !int_vars.is_empty() {
                                LogVar::Numbers(int_vars)
                            } else {
                                return Err(BSError::InvalidAttributeType {
                                    attribute: "invalid array",
                                    value: v.to_string(),
                                }
                                .into());
                            }
                        }
                        _ => {
                            return Err(BSError::InvalidAttribute {
                                attribute: "var",
                                value: v.to_string(),
                            }
                            .into());
                        }
                    };

                    ops.push(LogOp {
                        target: target.clone(),
                        negate: false,
                        command: comm,
                        var: var,
                    });
                }
            }
            _ => {
                return Err(BSError::InvalidAttributeType {
                    attribute: "rule_ops",
                    value: dir.to_string(),
                }
                .into());
            }
        }
        Ok(ops)
    }

    pub(crate) fn load_rules(
        labels: &HashMap<String, i64>,
        rules: HashMap<String, Value>,
    ) -> Result<BlazrRuleEngine, anyhow::Error> {
        let mut bshield_log_rules = BlazrRuleEngine {
            ignore: HashMap::new(),
            log: HashMap::new(),
            alert: HashMap::new(),
        };
        for (action, mut rs) in rules.into_iter() {
            if let Some(rules) = rs.as_array_mut() {
                for rule in rules.iter_mut() {
                    let mut dirs = Vec::new();
                    let class: BlazrRuleClass = get_field(rule, "class")?;
                    let event: BlazrEventType = get_field(rule, "event")?;

                    for (t, dir) in rule
                        .get_mut("directives")
                        .and_then(|tg| tg.as_object_mut())
                        .unwrap_or(&mut Map::new())
                    {
                        let target: BlazrRuleTarget =
                            BlazrRuleTarget::from_str(t.to_string().as_mut_str());

                        if target.is_undefined() {
                            return Err(BSError::InvalidAttribute {
                                attribute: "target",
                                value: t.to_string(),
                            }
                            .into());
                        }

                        dirs.append(&mut BlazrRuleEngine::parse_dir(&target, labels, dir)?);
                    }
                    let key = bshield_log_rules.get_op_key(&class, &event);
                    match action.as_str() {
                        "ignore" => bshield_log_rules.ignore.insert(key, dirs),
                        "log" => bshield_log_rules.log.insert(key, dirs),
                        "alert" => bshield_log_rules.alert.insert(key, dirs),
                        _ => {
                            return Err(BSError::InvalidAttribute {
                                attribute: "action",
                                value: action,
                            }
                            .into())
                        }
                    };
                }
            } else {
                return Err(BSError::InvalidAttributeType {
                    attribute: "log rules",
                    value: rs.to_string(),
                }
                .into());
            }
        }
        Ok(bshield_log_rules)
    }
}

pub(crate) fn load_rules_from_config(
    labels: &HashMap<String, i64>,
) -> Result<BlazrRuleEngine, anyhow::Error> {
    let mut config_dir = env::var("CONFIG_DIR").unwrap_or_else(|_| "config/".into());
    if !config_dir.ends_with('/') {
        config_dir.push('/');
    }

    let rule_config = Config::builder()
        .add_source(File::new(
            &format!("{}logs.json5", config_dir),
            FileFormat::Json5,
        ))
        .build()?;

    let rules: HashMap<String, Value> = rule_config
        .try_deserialize()
        .map_err(|e| BSError::Deserialize(e.to_string()))?;

    BlazrRuleEngine::load_rules(labels, rules)
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::collections::HashMap;

    use super::BlazrRuleEngine;
    use bitblazr_common::{
        rules::{BlazrRuleClass, BlazrRuleTarget},
        BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType,
    };
    use no_std_net::{IpAddr as NoStdIpAddr, Ipv4Addr};
    use serde_json::Value;

    fn construct_event() -> BlazrEvent {
        BlazrEvent {
            class: BlazrEventClass::Tracepoint,
            event_type: BlazrEventType::Open,
            log_class: BlazrRuleClass::File,
            ppid: None,
            tgid: 1212,
            pid: 1212,
            uid: 1000,
            gid: 1000,
            action: BlazrAction::Allow,
            protocol: 0,
            ip_addr: NoStdIpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
            rule_hits: [0; 5],
            labels: [0; 5],
            p_path: [0; 255],
            path: [0; 255],
            path_len: 0,
            argv_count: 0,
            argv: [[0; 200]; bitblazr_common::ARGV_COUNT],
        }
    }

    #[test]
    fn parse_rules_basic() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        {
            "class": "file",
            "event": "open",
            "directives": {
                "context": {
                    "eq": ["container"]
                },
                "path": {
                    "starts_with": [
                        "/etc/passwd",
                        "/etc/shadow"
                ]}
            }
        }],
        "alert": [
        ]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj);

        assert!(re
            .unwrap()
            .log
            .values()
            .next()
            .unwrap()
            .iter()
            .position(|e| e.target == BlazrRuleTarget::Context)
            .is_some())
    }

    #[test]
    fn parse_rules_negate() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        {
            "class": "file",
            "event": "open",
            "directives": {
                "context": {
                    "not": { "eq": ["container"] }
                },
                "path": {
                    "starts_with": [
                        "/etc/passwd",
                        "/etc/shadow"
                ]}
            }
        }],
        "alert": [
        ]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj);

        if let Some(ctx) = re
            .unwrap()
            .log
            .values()
            .next()
            .unwrap()
            .iter()
            .find(|e| e.target == BlazrRuleTarget::Context)
        {
            assert!(ctx.negate);
        }
    }

    #[test]
    fn check_rule() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        {
            "class": "file",
            "event": "open",
            "directives": {
                "context": {
                    "eq": ["container"]
                },
                "path": {
                    "starts_with": [
                        "/etc/passwd",
                        "/etc/shadow"
                ]}
            }
        }],
        "alert": [
        ]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj).unwrap();

        let mut e = construct_event();
        let path = "/etc/passwd";
        for (i, ch) in path.as_bytes().into_iter().enumerate() {
            if i < e.path.len() {
                e.path[i] = *ch;
            }
        }
        e.event_type = BlazrEventType::Open;
        e.labels[0] = 6027998744940314019;

        let result = re.check_rules(&e).unwrap();
        assert!(result.log);
    }
    #[test]
    fn check_rule_bad_context() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        {
            "class": "file",
            "event": "open",
            "directives": {
                "context": {
                    "eq": ["container1"]
                },
                "path": {
                    "starts_with": [
                        "/etc/passwd",
                        "/etc/shadow"
                ]}
            }
        }],
        "alert": [
        ]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let result = BlazrRuleEngine::load_rules(&labels, rules_obj);

        if let Err(e) = result {
            assert!(e.to_string().contains("Invalid attribute"));
        } else {
            panic!("Expected an error");
        }
    }
    #[test]
    fn check_alert_rules() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        ],
        "alert": [{
            "class": "file",
            "event": "exec",
            "directives": {
                "path": {
                    "starts_with": [
                        "/usr/bin/sudo",
                    ]
                }
            }
        },
        {
            "class": "file",
            "event": "open",
            "directives": {
                "path": {
                    "starts_with": [
                        "/etc/shadow",
                        "/proc/sys",
                        "/usr/bin/sudo"
                ]
            }
        }
        }]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj).unwrap();

        let mut e = construct_event();
        let path = "/etc/shadow";
        for (i, ch) in path.as_bytes().into_iter().enumerate() {
            if i < e.path.len() {
                e.path[i] = *ch;
            }
        }
        e.event_type = BlazrEventType::Open;
        e.labels[0] = 6027998744940314019;

        let result = re.check_rules(&e).unwrap();
        assert!(result.alert);
    }

    #[test]
    fn check_empty_dir() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        ],
        "alert": [{
            "class": "file",
            "event": "exec",
            "directives": {
            }
        }]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj).unwrap();

        let mut e = construct_event();
        let path = "/usr/bin/ls";
        for (i, ch) in path.as_bytes().into_iter().enumerate() {
            if i < e.path.len() {
                e.path[i] = *ch;
            }
        }
        e.event_type = BlazrEventType::Exec;
        e.labels[0] = 6027998744940314019;

        let result = re.check_rules(&e).unwrap();

        assert!(result.alert);
    }

    #[test]
    fn check_socket_connect() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [
        ],
        "log":  [
        ],
        "alert": [{
            "class": "socket",
            "event": "connect",
            "directives": {
               "port": {
                    "neq": [ 53, 80, 123, 443 ]
                }
            }
        }]});

        let rules_obj = match rules {
            Value::Object(rs) => rs
                .into_iter()
                .map(|(k, v)| (k, v))
                .collect::<HashMap<String, Value>>(),
            _ => panic!("Rules test definition is not an object"),
        };

        let re = BlazrRuleEngine::load_rules(&labels, rules_obj).unwrap();

        let mut e = construct_event();

        e.event_type = BlazrEventType::Connect;
        e.log_class = BlazrRuleClass::Socket;
        e.labels[0] = 6027998744940314019;
        e.port = 53;

        let result = re.check_rules(&e).unwrap();

        assert!(!result.alert);
    }
}
