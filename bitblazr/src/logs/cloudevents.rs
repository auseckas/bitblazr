use chrono::Utc;
use cloudevents::{EventBuilder, EventBuilderV10};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::value::Map;
use serde_json::{json, Value};
use std::io::Write;
use tracing::error;
use tracing_appender::non_blocking::NonBlocking;
use tracing_subscriber::Layer;

pub(crate) struct CloudEventsLayer {
    sensor_name: String,
    writer: Mutex<NonBlocking>,
}

impl CloudEventsLayer {
    pub fn new(sensor_name: &str, writer: NonBlocking) -> CloudEventsLayer {
        CloudEventsLayer {
            sensor_name: sensor_name.to_string(),
            writer: Mutex::new(writer),
        }
    }
}

impl<S> Layer<S> for CloudEventsLayer
where
    S: tracing::Subscriber,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut fields = Map::new();
        let mut visitor = JsonVisitor(&mut fields);
        event.record(&mut visitor);
        let mut bytes = [0; 16];
        rand::thread_rng().fill_bytes(&mut bytes);
        let random_id = hex::encode(&bytes);

        let source = format!(
            "/sensors/{}/{}",
            self.sensor_name.as_str(),
            event.metadata().target()
        );

        if let Ok(event) = EventBuilderV10::new()
            .id(random_id)
            .ty("com.ziosec.bitblazr.events")
            .source(source)
            .time(Utc::now().to_rfc3339())
            .data("application/json", Value::Object(fields))
            .build()
        {
            if let Ok(mut s) = serde_json::to_string(&event) {
                s.push('\n');
                if let Err(e) = self.writer.lock().write(s.as_bytes()) {
                    error!("Could not write log message. Err: {}", e);
                }
            }
        }
    }
}

struct JsonVisitor<'a>(&'a mut Map<String, Value>);

impl<'a> tracing::field::Visit for JsonVisitor<'a> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.0
            .insert(field.name().to_string(), serde_json::json!(value));
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.0
            .insert(field.name().to_string(), json!(value.to_string()));
    }

    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().to_string(), json!(format!("{:?}", value)));
    }
}
