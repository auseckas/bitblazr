use crate::config::ShieldLogEntry;
use crate::BSError;
use paho_mqtt::SslOptionsBuilder;
use paho_mqtt::{
    Client, ConnectOptionsBuilder, CreateOptionsBuilder, DisconnectOptions, Message, SslOptions,
    MQTT_VERSION_5,
};
use std::ops::Drop;
use std::time::Duration;
use tracing::error;

pub(crate) struct MqttLogger {
    client: Client,
    topic: String,
}

impl MqttLogger {
    pub fn new(entry: &ShieldLogEntry, sensor_name: &str) -> Result<MqttLogger, anyhow::Error> {
        let ssl_options = match matches!(entry.mqtt_server_cert_auth, Some(false)) {
            true => SslOptionsBuilder::new()
                .enable_server_cert_auth(false)
                .finalize(),
            false => SslOptions::default(),
        };

        let mut options = ConnectOptionsBuilder::new();
        options
            .ssl_options(ssl_options)
            .automatic_reconnect(Duration::from_secs(1), Duration::from_secs(300))
            .clean_start(true);

        let uri = match &entry.mqtt_uri {
            Some(s) => s.as_str(),
            None => return Err(BSError::MissingAttribute("mqtt_uri".to_string()).into()),
        };

        let mut client_opts_builder = CreateOptionsBuilder::new()
            .mqtt_version(MQTT_VERSION_5)
            .send_while_disconnected(true)
            .server_uri(uri);

        if !sensor_name.is_empty() {
            client_opts_builder = client_opts_builder.client_id(sensor_name);
        }
        let client_opts = client_opts_builder.finalize();

        if let Some(user) = &entry.mqtt_user {
            options.user_name(user);
        }

        if let Some(pwd) = &entry.mqtt_pwd {
            options.password(pwd);
        }

        let connect_ops = options.finalize();

        let client = Client::new(client_opts)?;

        if let Err(e) = client.connect(connect_ops) {
            error!(target: "error", "MQTT client could not connect to broker. Err: {}", e);
        }

        Ok(MqttLogger {
            client,
            topic: entry
                .mqtt_topic
                .as_ref()
                .unwrap_or(&String::new())
                .to_string(),
        })
    }
}

impl std::io::Write for MqttLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let buf_len = buf.len();
        if let Err(e) = self
            .client
            .publish(Message::new(self.topic.as_str(), buf, 0))
        {
            error!(target: "error", "Could not publish MQTT message. Err: {}", e);
        }
        Ok(buf_len)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for MqttLogger {
    fn drop(&mut self) {
        self.client
            .disconnect(DisconnectOptions::default())
            .expect("Error disconnecting");
    }
}
