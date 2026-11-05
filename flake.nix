{
  description = "G2 bootloader patch build and host tools";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  outputs = { nixpkgs, ... }:
    let systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ];
    in {
      devShells = nixpkgs.lib.genAttrs systems (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in { default = pkgs.mkShell {
          packages = [
            pkgs.llvmPackages_21.clang-unwrapped
            pkgs.llvmPackages_21.lld
            pkgs.llvmPackages_21.llvm
            pkgs.llvmPackages_21.clang-tools
            pkgs.gnumake
            pkgs.ruff
            pkgs.curl
            (pkgs.python3.withPackages (p: [ p.pyserial p.bleak p.crc p.unicorn ])) ];
          hardeningDisable = [ "all" ];
        }; });
    };
}
