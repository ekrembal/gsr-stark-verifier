//! Blocking client of the `pr-batcher` HTTP API.
use std::time::Duration;

use anyhow::{bail, Result};
use serde::de::DeserializeOwned;

use crate::api::{ApiError, BatchReport, MerklePath, Notes, SettleResponse, Status, Submission, SubmitResponse};

pub struct Client {
    base: String,
    http: reqwest::blocking::Client,
}

impl Client {
    /// `base` is the batcher's URL, e.g. `http://127.0.0.1:8080`.
    pub fn new(base: &str) -> Result<Client> {
        let http = reqwest::blocking::Client::builder().timeout(Duration::from_secs(600)).build()?;
        Ok(Client { base: base.trim_end_matches('/').to_owned(), http })
    }

    fn read<T: DeserializeOwned>(r: reqwest::blocking::Response) -> Result<T> {
        let status = r.status();
        if !status.is_success() {
            let body = r.text()?;
            let msg = serde_json::from_str::<ApiError>(&body).map(|e| e.error).unwrap_or(body);
            bail!("batcher returned {status}: {msg}");
        }
        Ok(r.json()?)
    }

    pub fn status(&self) -> Result<Status> {
        Self::read(self.http.get(format!("{}/v1/status", self.base)).send()?)
    }

    pub fn submit(&self, submission: &Submission) -> Result<SubmitResponse> {
        Self::read(self.http.post(format!("{}/v1/transactions", self.base)).json(submission).send()?)
    }

    pub fn notes(&self, from_batch: u64) -> Result<Notes> {
        Self::read(self.http.get(format!("{}/v1/notes?from={from_batch}", self.base)).send()?)
    }

    pub fn path(&self, leaf: u64) -> Result<MerklePath> {
        Self::read(self.http.get(format!("{}/v1/paths/{leaf}", self.base)).send()?)
    }

    /// Asks the batcher to settle its pool now.
    pub fn settle(&self) -> Result<SettleResponse> {
        Self::read(self.http.post(format!("{}/v1/batches", self.base)).send()?)
    }

    pub fn batch(&self, batch_number: u64) -> Result<BatchReport> {
        Self::read(self.http.get(format!("{}/v1/batches/{batch_number}", self.base)).send()?)
    }
}
