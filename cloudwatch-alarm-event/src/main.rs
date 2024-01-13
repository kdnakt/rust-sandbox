use lambda_runtime::{run, service_fn, Error, LambdaEvent};

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use serde::{
    de::{DeserializeOwned, Visitor},
    ser::Error as SerError,
    Deserialize, Serialize,
};
use serde_json::Value;

/// `CloudWatchAlarm` is the generic outer structure of an event triggered by a CloudWatch Alarm.
/// You probably want to use `CloudWatchMetricAlarm` or `CloudWatchCompositeAlarm` if you know which kind of alarm your function is receiving.
/// For examples of events that come via CloudWatch Alarms,
/// see https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#Lambda-action-payload
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarm<C = Value, R = CloudWatchAlarmStateReasonData>
where
    C: DeserializeOwned,
    C: Serialize,
    R: DeserializeOwned,
    R: Serialize,
{
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub alarm_arn: Option<String>,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub region: Option<String>,
    pub time: DateTime<Utc>,

    #[serde(default, bound = "")]
    pub alarm_data: CloudWatchAlarmData<C, R>,
}

/// `CloudWatchMetricAlarm` is the structure of an event triggered by CloudWatch metric alarms.
#[allow(unused)]
type CloudWatchMetricAlarm<R = CloudWatchAlarmStateReasonData> = CloudWatchAlarm<CloudWatchMetricAlarmConfiguration, R>;

/// `CloudWatchCompositeAlarm` is the structure of an event triggered by CloudWatch composite alarms.
#[allow(unused)]
type CloudWatchCompositeAlarm<R = CloudWatchAlarmStateReasonData> =
    CloudWatchAlarm<CloudWatchCompositeAlarmConfiguration, R>;

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmData<C = Value, R = CloudWatchAlarmStateReasonData>
where
    C: DeserializeOwned,
    C: Serialize,
    R: DeserializeOwned,
    R: Serialize,
{
    pub alarm_name: String,
    #[serde(default, bound = "")]
    pub state: Option<CloudWatchAlarmState<R>>,
    #[serde(default, bound = "")]
    pub previous_state: Option<CloudWatchAlarmState<R>>,
    #[serde(bound = "")]
    pub configuration: C,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmState<R = Value>
where
    R: DeserializeOwned,
    R: Serialize,
{
    #[serde(default)]
    pub value: CloudWatchAlarmStateValue,
    pub reason: String,
    #[serde(default, bound = "")]
    pub reason_data: Option<R>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchMetricAlarmConfiguration {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub metrics: Vec<CloudWatchMetricDefinition>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchMetricDefinition {
    pub id: String,
    #[serde(default)]
    pub return_data: bool,
    pub metric_stat: CloudWatchMetricStatDefinition,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchMetricStatDefinition {
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub stat: Option<String>,
    pub period: u16,
    pub metric: CloudWatchMetricStatMetricDefinition,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchMetricStatMetricDefinition {
    #[serde(default)]
    pub namespace: Option<String>,
    pub name: String,
    pub dimensions: HashMap<String, String>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchCompositeAlarmConfiguration {
    pub alarm_rule: String,
    pub actions_suppressor: String,
    pub actions_suppressor_wait_period: u16,
    pub actions_suppressor_extension_period: u16,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CloudWatchAlarmStateValue {
    #[default]
    Ok,
    Alarm,
    InsufficientData,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CloudWatchAlarmStateReasonData {
    Metric(CloudWatchAlarmStateReasonDataMetric),
    Composite(ClodWatchAlarmStateReasonDataComposite),
    Generic(Value),
}

impl Default for CloudWatchAlarmStateReasonData {
    fn default() -> Self {
        Self::Generic(Value::String(String::new()))
    }
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmStateReasonDataMetric {
    pub version: String,
    #[serde(default)]
    pub query_date: Option<DateTime<Utc>>,
    #[serde(default)]
    pub start_date: Option<DateTime<Utc>>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default)]
    pub statistic: Option<String>,
    pub period: u16,
    #[serde(default)]
    pub recent_datapoints: Vec<f64>,
    #[serde(default)]
    pub recent_lower_thresholds: Vec<f64>,
    #[serde(default)]
    pub recent_upper_thresholds: Vec<f64>,
    pub threshold: f64,
    #[serde(default)]
    pub evaluated_datapoints: Vec<CloudWatchAlarmStateEvaluatedDatapoint>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmStateEvaluatedDatapoint {
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub sample_count: Option<f64>,
    #[serde(default)]
    pub value: Option<f64>,
    #[serde(default)]
    pub threshold: Option<f64>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClodWatchAlarmStateReasonDataComposite {
    #[serde(default)]
    pub triggering_alarms: Vec<CloudWatchAlarmStateTriggeringAlarm>,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmStateTriggeringAlarm {
    pub arn: String,
    pub state: CloudWatchAlarmStateTriggeringAlarmState,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudWatchAlarmStateTriggeringAlarmState {
    pub timestamp: DateTime<Utc>,
    #[serde(default)]
    pub value: CloudWatchAlarmStateValue,
}

impl<'de> Deserialize<'de> for CloudWatchAlarmStateReasonData {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(ReasonDataVisitor)
    }
}

impl Serialize for CloudWatchAlarmStateReasonData {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let r = match self {
            Self::Metric(m) => serde_json::to_string(m),
            Self::Composite(m) => serde_json::to_string(m),
            Self::Generic(m) => serde_json::to_string(m),
        };
        let s = r.map_err(|e| SerError::custom(format!("failed to serialize struct as string {}", e)))?;

        serializer.serialize_str(&s)
    }
}

struct ReasonDataVisitor;

impl<'de> Visitor<'de> for ReasonDataVisitor {
    type Value = CloudWatchAlarmStateReasonData;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a string with the alarm state reason data")
    }

    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        if let Ok(metric) = serde_json::from_str::<CloudWatchAlarmStateReasonDataMetric>(v) {
            return Ok(CloudWatchAlarmStateReasonData::Metric(metric));
        }
        if let Ok(aggregate) = serde_json::from_str::<ClodWatchAlarmStateReasonDataComposite>(v) {
            return Ok(CloudWatchAlarmStateReasonData::Composite(aggregate));
        }
        Ok(CloudWatchAlarmStateReasonData::Generic(Value::String(v.to_owned())))
    }
}

/// This is a made-up example. Requests come into the runtime as unicode
/// strings in json format, which can map to any structure that implements `serde::Deserialize`
/// The runtime pays no attention to the contents of the request payload.
#[derive(Deserialize)]
struct Request {
    command: String,
}

/// This is a made-up example of what a response structure may look like.
/// There is no restriction on what it can be. The runtime requires responses
/// to be serialized into json. The runtime pays no attention
/// to the contents of the response payload.
#[derive(Serialize)]
struct Response {
    req_id: String,
    msg: String,
}

/// This is the main body for the function.
/// Write your code inside it.
/// There are some code example in the following URLs:
/// - https://github.com/awslabs/aws-lambda-rust-runtime/tree/main/examples
/// - https://github.com/aws-samples/serverless-rust-demo/
async fn function_handler(event: LambdaEvent<CloudWatchAlarm>) -> Result<Response, Error> {
    println!("DEBUG: payload=\n{:?}", event.payload);
    // Prepare the response
    let resp = Response {
        req_id: event.context.request_id,
        msg: "Hello from lambda".to_string(),
    };

    // Return `Response` (it will be serialized to JSON automatically by the runtime)
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        // disable printing the name of the module in every log line.
        .with_target(false)
        // disabling time is handy because CloudWatch will add the ingestion time.
        .without_time()
        .init();

    run(service_fn(function_handler)).await
}
