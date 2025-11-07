{
  pkgs ? import <nixpkgs> { },
}:

pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc
    cargo
    cargo-audit
    clippy
    rustfmt
    rust-analyzer
    git
    openssl
    pkg-config
  ];

  shellHook = ''
    rustfmt --edition 2024 dns/src/record/*.rs dns/src/*.rs dns-transport/src/*.rs src/*.rs
    cargo audit
  '';

  RUST_BACKTRACE = 1;
}
