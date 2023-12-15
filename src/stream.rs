use std::sync::Mutex;

use flutter_rust_bridge::StreamSink;
use lazy_static::lazy_static;

use crate::constants::LogEntry;
use crate::spclient::ScanProgress;

lazy_static! {
    static ref LOG_STREAM_SINK: Mutex<Option<StreamSink<LogEntry>>> = Mutex::new(None);
    static ref AMOUNT_STREAM_SINK: Mutex<Option<StreamSink<u64>>> = Mutex::new(None);
    static ref SCAN_STREAM_SINK: Mutex<Option<StreamSink<ScanProgress>>> = Mutex::new(None);
}

pub fn create_log_stream(s: StreamSink<LogEntry>) {
    let mut stream_sink = LOG_STREAM_SINK.lock().unwrap();
    *stream_sink = Some(s);
}

pub fn create_amount_stream(s: StreamSink<u64>) {
    let mut stream_sink = AMOUNT_STREAM_SINK.lock().unwrap();
    *stream_sink = Some(s);
}

pub fn create_scan_progress_stream(s: StreamSink<ScanProgress>) {
    let mut stream_sink = SCAN_STREAM_SINK.lock().unwrap();
    *stream_sink = Some(s);
}

pub(crate) fn loginfo(text: &str) {
    let stream_sink = LOG_STREAM_SINK.lock().unwrap();
    if let Some(stream_sink) = stream_sink.as_ref().clone() {
        stream_sink.add(LogEntry {
            msg: text.to_owned(),
        });
    }
}

pub(crate) fn send_amount_update(amount: u64) {
    let stream_sink = AMOUNT_STREAM_SINK.lock().unwrap();
    if let Some(stream_sink) = stream_sink.as_ref().clone() {
        stream_sink.add(amount);
    }
}

pub(crate) fn send_scan_progress(scan_progress: ScanProgress) {
    let stream_sink = SCAN_STREAM_SINK.lock().unwrap();
    if let Some(stream_sink) = stream_sink.as_ref().clone() {
        stream_sink.add(scan_progress);
    }
}

