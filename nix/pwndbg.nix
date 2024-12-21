{
  pkgs ? import <nixpkgs> { },
  python3 ? pkgs.python3,
  gdb ? pkgs.gdb,
  inputs ? null,
  isDev ? false,
  isLLDB ? false,
  lldb ? pkgs.lldb_19,
}:
let
  binPath = pkgs.lib.makeBinPath (
    [
      python3.pkgs.pwntools # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/wrappers/checksec.py#L8
    ]
    ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
      python3.pkgs.ropper # ref: https://github.com/pwndbg/pwndbg/blob/2023.07.17/pwndbg/commands/ropper.py#L30
    ]
  );

  pyEnv = import ./pyenv.nix {
    inherit
      pkgs
      python3
      inputs
      isDev
      isLLDB
      ;
    lib = pkgs.lib;
  };

  pwndbgVersion =
    let
      versionFile = builtins.readFile "${inputs.pwndbg}/pwndbg/lib/version.py";
      versionMatch = builtins.match ".*\n__version__ = \"([0-9]+.[0-9]+.[0-9]+)\".*" versionFile;
      version = if versionMatch == null then "unknown" else (builtins.elemAt versionMatch 0);
    in
    version;

  pwndbg =
    let
      pwndbgName = if isLLDB then "pwndbg-lldb" else "pwndbg";
    in
    pkgs.stdenv.mkDerivation {
      name = pwndbgName;
      version = pwndbgVersion;

      src = pkgs.lib.sourceByRegex inputs.pwndbg (
        [
          "pwndbg"
          "pwndbg/.*"
        ]
        ++ (
          if isLLDB then
            [
              "lldbinit.py"
              "pwndbg-lldb.py"
            ]
          else
            [
              "gdbinit.py"
            ]
        )
      );

      nativeBuildInputs = [ pkgs.makeWrapper ];
      buildInputs = [ pyEnv ];

      installPhase =
        let
          fix_init_script =
            { target, line }:
            ''
              # Build self-contained init script for lazy loading from vanilla gdb
              # I purposely use insert() so I can re-import during development without having to restart gdb
              sed "${line} i import sys, os\n\
              sys.path.insert(0, '${pyEnv}/${pyEnv.sitePackages}')\n\
              sys.path.insert(0, '$out/share/pwndbg/')\n\
              os.environ['PATH'] += ':${binPath}'\n" -i ${target}
            '';
        in
        (
          if isLLDB then
            ''
              mkdir -p $out/share/pwndbg
              mkdir -p $out/bin

              cp -r lldbinit.py pwndbg $out/share/pwndbg
              cp pwndbg-lldb.py $out/bin/${pwndbgName}

              ${fix_init_script {
                target = "$out/bin/${pwndbgName}";
                line = "4";
              }}

              touch $out/share/pwndbg/.skip-venv
              wrapProgram $out/bin/${pwndbgName} \
                --prefix PATH : ${pkgs.lib.makeBinPath [ lldb ]} \
            ''
            + (pkgs.lib.optionalString (!pkgs.stdenv.isDarwin) ''
              --set LLDB_DEBUGSERVER_PATH ${pkgs.lib.makeBinPath [ lldb ]}/lldb-server \
            '')
            + ''
              --set PWNDBG_LLDBINIT_DIR $out/share/pwndbg
            ''
          else
            ''
              mkdir -p $out/share/pwndbg

              cp -r gdbinit.py pwndbg $out/share/pwndbg
              ${fix_init_script {
                target = "$out/share/pwndbg/gdbinit.py";
                line = "2";
              }}

              touch $out/share/pwndbg/.skip-venv
              makeWrapper ${gdb}/bin/gdb $out/bin/${pwndbgName} \
                --add-flags "--quiet --early-init-eval-command=\"set auto-load safe-path /\" --command=$out/share/pwndbg/gdbinit.py"
            ''
        );

      meta = {
        pwndbgVenv = pyEnv;
        python3 = python3;
        gdb = gdb;
        lldb = lldb;
        isLLDB = isLLDB;
      };
    };
in
pwndbg
