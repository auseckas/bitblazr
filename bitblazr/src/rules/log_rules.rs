use super::get_field;
use crate::tracker::tracker::BSProcess;
use crate::utils::get_hash;
use crate::BSError;
use aho_corasick::AhoCorasick;
use bitblazr_common::utils::str_from_buf_nul;
use bitblazr_common::{rules::*, BlazrEvent, BlazrEventType};
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

#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct BlazrRuleResult {
    pub id: i64,
    pub description: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct BlazrLogResult {
    pub ignore: bool,
    pub log: bool,
    pub alert: bool,
    pub results: Vec<BlazrRuleResult>,
}

#[derive(Debug)]
struct LogRule {
    description: Option<String>,
    ops: Vec<LogOp>,
}

#[derive(Debug)]
pub(crate) struct BlazrRuleEngine {
    ignore: HashMap<i64, Vec<LogRule>>,
    log: HashMap<i64, Vec<LogRule>>,
    alert: HashMap<i64, Vec<LogRule>>,
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

    fn check_int_var(&self, cmd: &BlazrRuleCommand, right: &LogVar, left: i64) -> bool {
        let r = match right {
            LogVar::Numbers(ns) => match *cmd {
                BlazrRuleCommand::Eq | BlazrRuleCommand::Neq => {
                    let mut matched = false;
                    for n in ns {
                        if left == *n {
                            matched = true;
                            break;
                        }
                    }
                    if matches!(*cmd, BlazrRuleCommand::Eq) {
                        matched
                    } else {
                        !matched
                    }
                }
                BlazrRuleCommand::LessThanOrEqual => {
                    let mut matched = false;
                    for n in ns {
                        if left <= *n {
                            matched = true;
                            break;
                        }
                    }
                    matched
                }
                BlazrRuleCommand::GreaterThanOrEqual => {
                    let mut matched = false;
                    for n in ns {
                        if left >= *n {
                            matched = true;
                            break;
                        }
                    }
                    matched
                }
                _ => false,
            },
            _ => false,
        };

        r
    }

    fn check_op(&self, op: &LogOp, p: &BSProcess, path: &str) -> Result<bool, anyhow::Error> {
        let mut result = match op.target {
            BlazrRuleTarget::Path => self.check_str_var(&op.command, &op.var, path.as_bytes())?,
            BlazrRuleTarget::Port => p
                .proto_port
                .iter()
                .map(|pp| pp.port)
                .any(|port| self.check_int_var(&op.command, &op.var, port as i64)),
            BlazrRuleTarget::IpProto => p
                .proto_port
                .iter()
                .map(|pp| pp.proto)
                .any(|proto| self.check_int_var(&op.command, &op.var, proto as i64)),

            BlazrRuleTarget::ExitCode => {
                self.check_int_var(&op.command, &op.var, p.exit_code as i64)
            }
            BlazrRuleTarget::RunTime => self.check_int_var(&op.command, &op.var, p.run_time as i64),
            BlazrRuleTarget::Uid => self.check_int_var(&op.command, &op.var, p.uid as i64),
            BlazrRuleTarget::Gid => self.check_int_var(&op.command, &op.var, p.gid as i64),
            BlazrRuleTarget::Context => {
                if let LogVar::String((patterns, _)) = &op.var {
                    let pats: Vec<i64> = patterns.iter().map(|s| get_hash(s) as i64).collect();
                    let mut matched = false;
                    if !pats.is_empty() {
                        matched = true;
                    }
                    for pat in pats {
                        if !p.context.contains(&pat) {
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
        map: &HashMap<i64, Vec<LogRule>>,
        p: &BSProcess,
        path: &str,
    ) -> Result<Vec<BlazrRuleResult>, anyhow::Error> {
        let mut results = Vec::new();
        if let Some(rules) = map.get(&key) {
            for (i, rule) in rules.iter().enumerate() {
                let mut matched = true;
                for op in rule.ops.iter() {
                    if !self.check_op(op, p, path)? {
                        matched = false;
                        break;
                    }
                }
                if !matched {
                    continue;
                }
                results.push(BlazrRuleResult {
                    id: i as i64,
                    description: rule.description.clone(),
                });
            }
        }

        Ok(results)
    }

    // We want class and type from individual event but actual matching should be against rolled up process record
    pub fn check_rules(
        &self,
        log_class: &BlazrRuleClass,
        event_type: &BlazrEventType,
        p: &BSProcess,
        e: &BlazrEvent,
    ) -> Result<BlazrLogResult, anyhow::Error> {
        let mut log_result = BlazrLogResult::default();

        debug!("Log class: {:?}, event type: {:?}", log_class, event_type);
        let key = self.get_op_key(&log_class, &event_type);
        let path = match event_type {
            BlazrEventType::Open => str_from_buf_nul(&e.path).unwrap_or(""),
            _ => p.path.as_str(),
        };

        log_result.results = self.check_map(key, &self.ignore, p, path)?;
        if !log_result.results.is_empty() {
            log_result.ignore = true;
            return Ok(log_result);
        }

        let mut results = self.check_map(key, &self.log, p, path)?;
        if !results.is_empty() {
            log_result.log = true;
            log_result.results.append(&mut results);
        }

        let mut results = self.check_map(key, &self.alert, p, path)?;
        if !results.is_empty() {
            log_result.alert = true;
            log_result.results.append(&mut results);
        }

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
                    let description = rule.get("description").and_then(|c| c.as_str()).map(|s| {
                        let mut desc = s.to_string();
                        // Truncate description to 25 chars
                        desc.truncate(25);
                        desc
                    });

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
                    let rule_class = match action.as_str() {
                        "ignore" => bshield_log_rules.ignore.entry(key).or_insert(Vec::new()),
                        "log" => bshield_log_rules.log.entry(key).or_insert(Vec::new()),
                        "alert" => bshield_log_rules.alert.entry(key).or_insert(Vec::new()),
                        _ => {
                            return Err(BSError::InvalidAttribute {
                                attribute: "action",
                                value: action,
                            }
                            .into())
                        }
                    };
                    rule_class.push(LogRule {
                        description,
                        ops: dirs,
                    })
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
            &format!("{}alerting_rules.yaml", config_dir),
            FileFormat::Yaml,
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

    use crate::tracker::tracker::{BSProcess, BSProtoPort};

    use super::BlazrRuleEngine;
    use bitblazr_common::{
        rules::{BlazrRuleClass, BlazrRuleTarget},
        BlazrAction, BlazrEvent, BlazrEventClass, BlazrEventType,
    };
    use chrono::Utc;
    use no_std_net::IpAddr as NoStdIpAddr;
    use no_std_net::Ipv4Addr;
    use serde_json::Value;

    fn construct_process() -> BSProcess {
        BSProcess {
            event_type: BlazrEventType::Open,
            created: Utc::now(),
            tgid: 1212,
            pid: 1212,
            ppid: None,
            uid: 1000,
            gid: 1000,
            p_path: String::new(),
            path: String::new(),
            proto_port: Vec::new(),
            action: BlazrAction::Allow,
            rule_hits: Vec::new(),
            children: Vec::new(),
            context: Vec::new(),
            argv: Vec::new(),
            exit_code: 0,
            run_time: 0,
            logged: false,
        }
    }

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
            exit_code: 0,
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
            .next()
            .unwrap()
            .ops
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
            .next()
            .unwrap()
            .ops
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

        let mut p = construct_process();
        p.path = "/etc/passwd".to_string();
        p.event_type = BlazrEventType::Open;
        p.context.push(6027998744940314019);

        let mut e = construct_event();
        e.path[0..p.path.len()].copy_from_slice(&p.path.as_bytes()[0..p.path.len()]);

        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();
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

        let mut p = construct_process();
        p.path = "/etc/shadow".to_string();
        p.event_type = BlazrEventType::Open;
        p.context.push(6027998744940314019);

        let mut e = construct_event();
        e.path[0..p.path.len()].copy_from_slice(&p.path.as_bytes()[0..p.path.len()]);

        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();
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

        let mut p = construct_process();
        p.path = "/usr/bin/ls".to_string();
        p.event_type = BlazrEventType::Exec;
        p.context.push(6027998744940314019);

        let mut e = construct_event();
        e.path[0..p.path.len()].copy_from_slice(&p.path.as_bytes()[0..p.path.len()]);

        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();

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

        let mut p = construct_process();
        p.event_type = BlazrEventType::Connect;
        p.context.push(6027998744940314019);
        p.proto_port.push(BSProtoPort {
            proto: 17,
            port: 53,
            ip: NoStdIpAddr::from([8, 8, 8, 8]),
        });

        let e = construct_event();
        let result = re
            .check_rules(&BlazrRuleClass::Socket, &p.event_type, &p, &e)
            .unwrap();

        assert!(!result.alert);
    }

    #[test]
    fn check_exit_code() {
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
            "event": "exit",
            "directives": {
                "path": {
                    "ends_with": "sshd"
                },
                "exit_code": {
                    "neq": [ 0 ]
                },
                "run_time": {
                    "lte": 1
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

        let mut p = construct_process();
        p.event_type = BlazrEventType::Exit;
        p.context.push(6027998744940314019);
        p.proto_port.push(BSProtoPort {
            proto: 17,
            port: 53,
            ip: NoStdIpAddr::from([8, 8, 8, 8]),
        });
        p.path = "/usr/bin/sshd".to_string();
        p.exit_code = 1;
        p.run_time = 1;

        let e = construct_event();

        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();

        assert!(result.alert);
    }
    #[test]
    fn check_uid() {
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
            "event": "exit",
            "directives": {
                "path": {
                    "ends_with": "sshd"
                },
                "exit_code": {
                    "neq": [ 0 ]
                },
                "run_time": {
                    "lte": 1
                },
                "uid": {
                    "lte": 999
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

        let mut p = construct_process();
        p.event_type = BlazrEventType::Exit;
        p.context.push(6027998744940314019);
        p.proto_port.push(BSProtoPort {
            proto: 17,
            port: 53,
            ip: NoStdIpAddr::from([8, 8, 8, 8]),
        });
        p.path = "/usr/bin/sshd".to_string();
        p.exit_code = 1;
        p.run_time = 1;
        p.uid = 637;

        let e = construct_event();
        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();

        assert!(result.alert);
    }
    #[test]
    fn check_gid() {
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
            "event": "exit",
            "directives": {
                "path": {
                    "ends_with": "sshd"
                },
                "exit_code": {
                    "neq": [ 0 ]
                },
                "run_time": {
                    "lte": 1
                },
                "gid": {
                    "gte": 1000
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

        let mut p = construct_process();
        p.event_type = BlazrEventType::Exit;
        p.context.push(6027998744940314019);
        p.proto_port.push(BSProtoPort {
            proto: 17,
            port: 53,
            ip: NoStdIpAddr::from([8, 8, 8, 8]),
        });
        p.path = "/usr/bin/sshd".to_string();
        p.exit_code = 1;
        p.run_time = 1;
        p.uid = 637;
        p.gid = 1000;

        let e = construct_event();
        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();

        assert!(result.alert);
    }
    #[test]
    fn check_ignore() {
        let mut labels: HashMap<String, i64> = HashMap::new();
        labels.insert("container".to_string(), 6027998744940314019);
        labels.insert("webserver".to_string(), 7887656042122143105);

        let rules = json!({
        "ignore": [{
            "class": "file",
            "event": "exit",
            "directives": {
                "path": {
                    "ends_with": "sshd"
                }
            }
        }],
        "log":  [
        ],
        "alert": [{
            "class": "file",
            "event": "exit",
            "directives": {
                "path": {
                    "ends_with": "sshd"
                },
                "exit_code": {
                    "neq": [ 0 ]
                },
                "run_time": {
                    "lte": 1
                },
                "uid": {
                    "lte": 999
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

        let mut p = construct_process();
        p.event_type = BlazrEventType::Exit;
        p.context.push(6027998744940314019);
        p.proto_port.push(BSProtoPort {
            proto: 17,
            port: 53,
            ip: NoStdIpAddr::from([8, 8, 8, 8]),
        });
        p.path = "/usr/bin/sshd".to_string();
        p.exit_code = 1;
        p.run_time = 1;
        p.uid = 637;

        let e = construct_event();
        let result = re
            .check_rules(&BlazrRuleClass::File, &p.event_type, &p, &e)
            .unwrap();

        assert!(!result.alert && !result.log && result.ignore);
    }
}
