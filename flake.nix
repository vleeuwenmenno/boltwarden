{
  description = "Linux quick-access GUI for Bitwarden and Vaultwarden vaults";

  inputs = {
    bundlers.url = "github:NixOS/bundlers";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      bundlers,
      nixpkgs,
      ...
    }:
    let
      supportedSystems = [ "x86_64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      packageVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          runtimeLibs = with pkgs; [
            fontconfig
            libGL
            libx11
            libxcursor
            libxi
            libxkbcommon
            libxrandr
            libxcb
            wayland
          ];
        in
        {
          default = pkgs.rustPlatform.buildRustPackage {
            pname = "bw-quick-access";
            version = packageVersion;

            src = pkgs.lib.cleanSource ./.;

            cargoLock = {
              lockFile = ./Cargo.lock;
            };

            nativeBuildInputs = with pkgs; [
              copyDesktopItems
              makeWrapper
              pkg-config
            ];

            buildInputs = runtimeLibs;
            nativeCheckInputs = [ pkgs.dbus ];
            RUST_TEST_THREADS = "1";

            postInstall = ''
              wrapProgram "$out/bin/bw-quick-access" \
                --prefix LD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath runtimeLibs}"
            '';

            desktopItems = [
              (pkgs.makeDesktopItem {
                name = "bw-quick-access-daemon";
                desktopName = "Bitwarden Quick Access Daemon";
                genericName = "Password Manager Daemon";
                comment = "Start the Bitwarden Quick Access background daemon";
                exec = "bw-quick-access --daemon";
                icon = "dialog-password";
                terminal = false;
                categories = [ "Utility" ];
              })
            ];

            meta = {
              description = "Linux quick-access GUI for Bitwarden and Vaultwarden vaults";
              homepage = "https://git.mvl.sh/vleeuwenmenno/bw-quick-access";
              mainProgram = "bw-quick-access";
              platforms = supportedSystems;
            };
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/bw-quick-access";
          meta = {
            description = "Run the Bitwarden Quick Access GUI";
          };
        };
      });

      devShells = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              clippy
              dbus
              pkg-config
              rustc
              rustfmt
            ];

            inputsFrom = [ self.packages.${system}.default ];
          };
        }
      );

      checks = forAllSystems (system: {
        package = self.packages.${system}.default;
      });

      bundlers = forAllSystems (system: {
        default = bundlers.bundlers.${system}.default;
      });
    };
}
