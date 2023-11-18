use win_etw_macros::trace_logging_provider;

#[trace_logging_provider(name = "TerrapinLabs.LeoTest1")]
pub trait LeoSensorEvents {
    #[event(level = "info")]
    fn sensor_started();

    #[event(level = "info")]
    fn as_req(
        client_address: &SocketAddr,
        client_port: u16,
        pa_etypes: &[i32],
        #[event(output = "hex")]
        kdc_options: u64,
        cname: &str,
        realm: &str,
        sname: &str,
        etype: &[i32],
    );
}