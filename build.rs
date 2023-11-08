use cmake::Config;

fn main() {
    let dst = Config::new(".").build();
    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=autograph");
}
