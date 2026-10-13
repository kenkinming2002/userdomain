use std::env;
use std::path::PathBuf;

#[allow(deprecated)]
use bindgen::{Builder, CargoCallbacks, EnumVariation};
use bindgen::callbacks::{EnumVariantValue, ParseCallbacks};

#[derive(Debug)]
pub struct TrimEnumNameParseCallbacks;
impl ParseCallbacks for TrimEnumNameParseCallbacks {
    fn enum_variant_name(&self, enum_name: Option<&str>, original_variant_name: &str, _variant_value: EnumVariantValue) -> Option<String> {
        enum_name
            .and_then(|enum_name| enum_name.strip_prefix("enum"))
            .map(|enum_name| enum_name.trim())
            .and_then(|enum_name| {
                let mut enum_name = enum_name.chars();
                let mut original_variant_name = dbg!(original_variant_name).chars();
                loop {
                    match (enum_name.next(), original_variant_name.next()) {
                        (Some(a), Some(b)) if a.eq_ignore_ascii_case(&b) => continue,
                        (None, Some('_')) => break Some(original_variant_name.collect()),
                        _ => break None,
                    }
                }
            })
    }
}

fn main() {
    let bindings = Builder::default()
        .header("src/nss.h")
        .parse_callbacks(Box::new(CargoCallbacks::new()))
        .default_enum_style(EnumVariation::NewType { is_bitfield: false, is_global: false })
        .parse_callbacks(Box::new(TrimEnumNameParseCallbacks))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("nss.rs"))
        .expect("Couldn't write nss bindings!");

    println!("cargo::rustc-link-arg-cdylib=-Wl,-soname,libnss_userdomain.so.2")
}
