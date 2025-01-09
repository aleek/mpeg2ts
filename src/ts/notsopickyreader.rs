use crate::ts::payload::{Bytes, Null, Pat};
use crate::ts::{AdaptationField, Pid, TsHeader, TsPacket, TsPayload, ReadTsPacket};
use crate::{ErrorKind, Result};
use std::io::Read;

/// TS packet reader.
#[derive(Debug)]
pub struct TsPacketNotSoPickyReader<R> {
    stream: R,
}
impl<R: Read> TsPacketNotSoPickyReader<R> {
    /// Makes a new `TsPacketNotSoPickyReader` instance.
    pub fn new(stream: R) -> Self {
        TsPacketNotSoPickyReader {
            stream,
        }
    }

    /// Returns a reference to the underlaying byte stream.
    pub fn stream(&self) -> &R {
        &self.stream
    }

    /// Converts `TsPacketReader` into the underlaying byte stream `R`.
    pub fn into_stream(self) -> R {
        self.stream
    }
}
impl<R: Read> ReadTsPacket for TsPacketNotSoPickyReader<R> {
    fn read_ts_packet(&mut self) -> Result<Option<TsPacket>> {
        let mut reader = self.stream.by_ref().take(TsPacket::SIZE as u64);
        let mut peek = [0; 1];
        let eos = track_io!(reader.read(&mut peek))? == 0;
        if eos {
            return Ok(None);
        }

        let (header, adaptation_field_control, payload_unit_start_indicator) =
            track!(TsHeader::read_from(peek.chain(&mut reader)))?;

        let adaptation_field = if adaptation_field_control.has_adaptation_field() {
            track!(AdaptationField::read_from(&mut reader))?
        } else {
            None
        };

        let payload = if adaptation_field_control.has_payload() {
            let payload = match header.pid.as_u16() {
                Pid::PAT => {
                    let pat = track!(Pat::read_from(&mut reader))?;
                    TsPayload::Pat(pat)
                }
                Pid::NULL => {
                    let null = track!(Null::read_from(&mut reader))?;
                    TsPayload::Null(null)
                }
                0x01..=0x1F | 0x1FFB => {
                    // Unknown (unsupported) packets
                    let bytes = track!(Bytes::read_from(&mut reader))?;
                    TsPayload::Raw(bytes)
                }
                _ => {
                    let bytes = track!(Bytes::read_from(&mut reader))?;
                    
                    TsPayload::Raw(bytes) 
                }
            };
            Some(payload)
        } else {
            None
        };

        track_assert_eq!(reader.limit(), 0, ErrorKind::InvalidInput);
        Ok(Some(TsPacket {
            header,
            adaptation_field,
            payload,
        }))
    }
}

#[derive(Debug, Clone)]
enum PidKind {
    Pmt,
    Pes,
}
