fn main() {
    if std::env::var_os("CARGO_CFG_UNIX").is_some() {
        napi_build::setup();
    }
}
