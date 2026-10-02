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
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      packageVersion = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package.version;
      browserIdentity = builtins.fromJSON (builtins.readFile ./extension/lib/browser-identities.json);
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
            pname = "boltwarden";
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
              wrapProgram "$out/bin/boltwarden" \
                --prefix LD_LIBRARY_PATH : "${pkgs.lib.makeLibraryPath runtimeLibs}"

              makeWrapper "$out/bin/boltwarden" "$out/bin/boltwarden-native-host" \
                --add-flags native-host
              mkdir -p "$out/lib/mozilla/native-messaging-hosts" \
                "$out/etc/chromium/native-messaging-hosts"
              cat > "$out/lib/mozilla/native-messaging-hosts/${browserIdentity.host_name}.json" <<EOF
              {
                "name": "${browserIdentity.host_name}",
                "description": "Boltwarden browser integration",
                "path": "$out/bin/boltwarden-native-host",
                "type": "stdio",
                "allowed_extensions": ["${browserIdentity.firefox_id}"]
              }
              EOF
              cat > "$out/etc/chromium/native-messaging-hosts/${browserIdentity.host_name}.json" <<EOF
              {
                "name": "${browserIdentity.host_name}",
                "description": "Boltwarden browser integration",
                "path": "$out/bin/boltwarden-native-host",
                "type": "stdio",
                "allowed_origins": ["chrome-extension://${browserIdentity.chrome_id}/"]
              }
              EOF
            '';

            desktopItems = [
              (pkgs.makeDesktopItem {
                name = "boltwarden-daemon";
                desktopName = "Boltwarden Daemon";
                genericName = "Password Manager Daemon";
                comment = "Start the Boltwarden background daemon";
                exec = "boltwarden --daemon";
                icon = "dialog-password";
                terminal = false;
                categories = [ "Utility" ];
              })
            ];

            meta = {
              description = "Linux quick-access GUI for Bitwarden and Vaultwarden vaults";
              homepage = "https://github.com/vleeuwenmenno/boltwarden";
              mainProgram = "boltwarden";
              platforms = supportedSystems;
            };
          };
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/boltwarden";
          meta = {
            description = "Run the Boltwarden GUI";
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

          extension = pkgs.mkShell {
            packages = with pkgs; [
              nodejs_22
              gnumake
              git
            ];
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
