{
  description = "Reference OMEMO implementation (python-omemo/twomemo/oldmemo) for cross-language interop tests";

  inputs.nixpkgs.url = "nixpkgs";

  outputs = { self, nixpkgs }:
    let
      forAllSystems = f: nixpkgs.lib.genAttrs
        [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ]
        (system: f nixpkgs.legacyPackages.${system});
    in {
      # `nix build .#default --print-out-paths` yields a store path whose
      # bin/python3 already has twomemo/oldmemo/omemo (and their transitive
      # deps) on sys.path - no manual PYTHONPATH assembly needed.
      packages = forAllSystems (pkgs: {
        default = pkgs.python3.withPackages (ps: [ ps.omemo ps.twomemo ps.oldmemo ]);
      });
    };
}
