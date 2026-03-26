let
  pkgs = import <nixpkgs> {};
in
  pkgs.mkShell {
    buildInputs = with pkgs; [
        openssl
        clang
        libclang
    ];
    nativeBuildInputs = with pkgs; [
        pkg-config
        rustPlatform.bindgenHook
    ];
  }
