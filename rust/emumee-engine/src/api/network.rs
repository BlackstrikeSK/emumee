//! Initial synchronous URLMon profile. Transfers use a supplied broker and
//! guest VFS; no Windows URLMon function or host destination is invoked.
use super::*;
use emumee_core::{
    artifacts::ArtifactKind,
    broker::{Data, Operation},
};
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub api: &'static str,
    pub url: String,
    pub guest_path: String,
    pub status: Option<u16>,
    pub bytes: usize,
    pub result: Option<u32>,
    pub error: Option<String>,
    pub destination_created: bool,
}
#[derive(Clone, Debug, Default, Serialize)]
pub struct Report {
    pub calls: u64,
    pub events: Vec<Event>,
    pub omitted_events: u64,
    pub uploads: Vec<Upload>,
    pub omitted_uploads: u64,
}
#[derive(Clone, Debug, Serialize)]
pub struct Upload {
    pub phase: &'static str,
    pub handle: u64,
    pub url: String,
    pub bytes: usize,
    pub total: Option<usize>,
}
pub(super) fn download(engine: &mut Unicorn<Trace>, args: &[u64], wide: bool) -> Result<u64> {
    ensure!(
        args[0] == 0 && args[3] == 0 && args[4] == 0,
        "URLMon binding context, reserved flags or callback are not modeled"
    );
    ensure!(
        args[1] != 0 && args[2] != 0,
        "URLMon URL/destination is null"
    );
    let url = files::path(engine, args[1], wide)?;
    let path = files::path(engine, args[2], wide)?;
    ensure!(
        !url.is_empty() && url.len() <= 2048 && url.is_ascii(),
        "URLMon URL is outside initial ASCII/2048-byte profile"
    );
    ensure!(
        path.is_ascii(),
        "URLMon destination Unicode path profile is not modeled"
    );
    let path = engine.get_data().apis.files.path(&path)?;
    let mut event = Event {
        api: if wide {
            "URLDownloadToFileW"
        } else {
            "URLDownloadToFileA"
        },
        url: url.clone(),
        guest_path: path.clone(),
        status: None,
        bytes: 0,
        result: None,
        error: None,
        destination_created: false,
    };
    let outcome = (|| -> Result<u64> {
        let client = engine.get_data_mut().apis.broker.as_mut().ok_or_else(|| {
            anyhow::anyhow!("Network broker unavailable; host fallback is disabled")
        })?;
        let reply = client
            .call(Operation::HttpGet { url })
            .map_err(anyhow::Error::msg)?;
        reply.validate(reply.id).map_err(anyhow::Error::msg)?;
        if !reply.ok {
            event.error = reply.error;
            event.result = Some(0x800c0008);
            return Ok(0x800c0008);
        }
        let (status, body) = match reply.value {
            Some(Data::Http { status, body }) => {
                ensure!(
                    body.len() <= 4096,
                    "Initial URLMon broker body bound exceeded"
                );
                (status, body)
            }
            Some(Data::HttpFull { response }) => {
                response.validate().map_err(anyhow::Error::msg)?;
                (response.status, response.body)
            }
            _ => bail!("Broker returned a non-HTTP value for URLMon"),
        };
        event.status = Some(status);
        event.bytes = body.len();
        ensure!(
            status == 200,
            "URLMon non-200 response handling is not modeled"
        );
        ensure!(
            body.len() <= emumee_core::networkfixtures::MAX_BODY,
            "URLMon broker body bound exceeded"
        );
        let opened = engine
            .get_data_mut()
            .apis
            .files
            .open(&path, 0x40000000, 1, 2, 1024);
        let handle = match opened {
            Ok((handle, _)) => handle,
            Err(error) if matches!(error.win32, 3 | 5 | 32) => {
                // Documented URLDownloadToFile behavior: S_OK can accompany
                // destination creation failure/cancellation. No file/capture
                // is invented; the cancellation stays explicit in evidence.
                event.error = Some(format!("Destination creation cancelled: {error}"));
                event.result = Some(0);
                return Ok(0);
            }
            Err(error) => return Err(error.into()),
        };
        event.destination_created = true;
        let write = engine.get_data_mut().apis.files.write(handle, 1024, &body);
        let close = engine.get_data_mut().apis.files.close(handle, 1024);
        ensure!(write? == body.len(), "URLMon virtual write was partial");
        close?;
        engine.get_data_mut().apis.captures.add(
            body,
            ArtifactKind::GuestFile,
            "urlmon_download",
            &path,
        );
        event.result = Some(0);
        Ok(0)
    })();
    if let Err(error) = &outcome {
        event.error = Some(format!("{error:#}"));
    }
    let report = &mut engine.get_data_mut().apis.network;
    report.calls += 1;
    if report.events.len() < 64 {
        report.events.push(event);
    } else {
        report.omitted_events += 1;
    }
    outcome
}
