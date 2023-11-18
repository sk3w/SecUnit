#![cfg(target_os = "windows")]

use kile::structures::AsReqExt;
use ndisapi::{AsyncNdisapiAdapter, FilterFlags, IntermediateBuffer};
use smoltcp::wire::{
    EthernetFrame, EthernetProtocol, IpProtocol, Ipv4Packet, TcpPacket, UdpPacket,
};
use tracing::{error, info, warn};
use windows::core::Result;

mod etw;

pub fn get_adapter() -> Result<AsyncNdisapiAdapter> {
    todo!()
}

// Main entrypoint to start sensor on a network interface
pub async fn monitor(adapter: &mut AsyncNdisapiAdapter) -> Result<()> {
    adapter.set_adapter_mode(FilterFlags::MSTCP_FLAG_SENT_RECEIVE_LISTEN)?;
    let mut packet = IntermediateBuffer::default();

    let etw_provider = etw::LeoSensorEvents::new();
    etw_provider.sensor_started(None);

    loop {
        let result = adapter.read_packet(&mut packet).await;
        if result.is_err() {
            continue;
        }

        inspect(&mut packet)?;
    }
}

/// Inspect packet for indicators and generate event data
fn inspect(packet: &mut IntermediateBuffer) -> Result<()> {
    let eth_hdr = EthernetFrame::new_unchecked(packet.get_data());
    match eth_hdr.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4_packet = Ipv4Packet::new_unchecked(eth_hdr.payload());
            match ipv4_packet.next_header() {
                IpProtocol::Tcp => {
                    let tcp_packet = TcpPacket::new_unchecked(ipv4_packet.payload());
                    if tcp_packet.dst_port() == 88 {
                        inspect_kdc(tcp_packet.payload())
                    } else {
                        Ok(())
                    }
                }
                IpProtocol::Udp => {
                    let udp_packet = UdpPacket::new_unchecked(ipv4_packet.payload());
                    if udp_packet.dst_port() == 88 {
                        inspect_kdc(udp_packet.payload())
                    } else {
                        Ok(())
                    }
                }
                _ => Ok(()),
            }
        }
        _ => Ok(()),
    }
}

// Inspect kdc messages
fn inspect_kdc<'a>(payload: &'a [u8]) -> Result<()> {
    //warn!("Received: {:#?}", payload.hex_dump());
    if payload.len() == 0 {
        return Ok(());
    }
    match kile::parser::kdc_frame(payload) {
        // Suspicous RC4_MD4 request
        Ok((_, kile::KdcFrame::AsReq(as_req))) if as_req.get_pa_etype() == Some(-128) => {
            warn!(
                "Suspicious AS_REQ with PA ETYPE = RC4_MD4 for CNAME: {:#?}",
                &as_req.get_cname().unwrap_or("<EMPTY>")
            );
            Ok(())
        }
        Ok((_, kile::KdcFrame::AsReq(as_req))) => {
            info!(
                "Received AS_REQ for CNAME: {:#?}",
                &as_req.get_cname().unwrap_or("<EMPTY>")
            );
            Ok(())
        }
        Ok((_, kile::KdcFrame::TgsReq(tgs_req))) => {
            info!(
                "Received TGS_REQ for {:#?}",
                &tgs_req.0.req_body.cname.unwrap()
            );
            Ok(())
        }
        Ok((_, _)) => Ok(()),
        Err(e) => {
            error!("Parser failure: {}", &e);
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {}
